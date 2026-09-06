package session

import (
	"context"
	"fmt"
	"net"
	"path"
	"sync"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// serveOnce runs everything for the life of one SSH connection and returns the
// reason it ended.
//
// The shape is: work out where we are, make the remote match, publish the
// socket, attach every service that can run here, then race them all into one
// channel. Whichever fails first wins and the rest are torn down — because a
// session whose 1Password broker has died is not a session you want quietly
// forwarding ports as though nothing happened, and reconnecting is cheap.
func (s *Session) serveOnce(ctx context.Context, conn Conn) (err error) {
	defer func() { _ = conn.Close() }()

	label := s.opts.Connector.Label()

	facts, err := probeFacts(ctx, conn)
	if err != nil {
		return err
	}
	paths := shim.PathsFor(facts.Home, facts.RuntimeDir)

	if s.opts.AutoInstall {
		syncer := &shimSyncer{Binary: s.opts.ShimBinary, Version: s.opts.Version, Fetch: s.opts.FetchShim, Events: s.events}
		uploaded, err := syncer.sync(ctx, conn, facts, paths, s.opts.Version)
		switch {
		case err != nil:
			// A shim that will not install is not fatal on its own: port
			// forwarding needs nothing on the remote box and is very often the
			// reason someone ran devtun at all. Say so loudly and carry on
			// with whatever still works.
			s.events.Emit(event.Event{
				Kind: "shim-failed", Class: event.Lifecycle, Level: event.Warn,
				Text: "could not install the remote helper: " + err.Error(),
			})
		case uploaded:
			s.events.Emit(event.Event{
				Kind: "shim-installed", Class: event.Lifecycle, Level: event.Info,
				Text:   fmt.Sprintf("installed the devtun helper on %s", label),
				Fields: []any{"version", s.opts.Version, "path", paths.Binary},
			})
		default:
			s.events.Emit(event.Event{
				Kind: "shim-current", Class: event.Diagnostic, Level: event.Debug,
				Text: "the remote helper is already current",
			})
		}
	}

	listener, err := conn.ListenSocket(ctx, paths.Socket)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		// Cleanup has to outlive the cancelled context that brought us here,
		// or Ctrl-C leaves a dead socket behind for the next run to trip over.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupGrace)
		defer cancel()
		conn.RemoveSocket(cleanupCtx, paths.Socket)
	}()

	socket := newSocketServer(s.events)
	instances, advisors, adviceHost := s.attachAll(ctx, conn, facts, paths, label, socket)

	// Services that speak a foreign protocol publish their own socket beside
	// the control one. See service.SocketService for why this cannot go
	// through Hello.
	own, closeOwn, err := s.publishOwnSockets(ctx, conn, paths, instances)
	if err != nil {
		return err
	}
	defer closeOwn()

	// running is closed by each service's goroutine as it returns, so teardown
	// can wait for them. The contract says Close is called after Run has
	// returned, and until this existed it simply was not: the supervisor
	// cancelled and closed immediately, so a Run still unwinding could put a
	// dead dialer back on the tunnel manager after Close had cleared it — and
	// the next connection, seeing forwarders already in place, would leave them
	// pointed at an SSH connection that no longer exists.
	var running sync.WaitGroup
	running.Add(len(instances))
	defer func() {
		running.Wait()
		closeAll(instances, s.opts.Bus)
	}()

	s.reportSetup(ctx, conn, facts, paths, label, advisors, adviceHost)

	// One channel, one buffer slot per goroutine, so nothing leaks blocked on
	// a send once the first failure has been taken.
	failures := make(chan error, len(instances)+len(own)+2)
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() { failures <- socket.serve(serveCtx, listener) }()
	go func() { failures <- conn.KeepAlive(serveCtx, keepAliveInterval, keepAliveTimeout) }()
	for _, o := range own {
		go func(o ownSocket) {
			failures <- annotate(o.id, o.serve(serveCtx, o.listener))
		}(o)
	}
	for _, inst := range instances {
		go func(inst attached) {
			defer running.Done()
			failures <- annotate(inst.meta.ID, inst.instance.Run(serveCtx))
		}(inst)
	}

	// cancel() runs before the deferred wait, so the services are already being
	// told to stop by the time anything waits on them.
	select {
	case err := <-failures:
		if ctx.Err() != nil {
			return nil
		}
		return err
	case <-ctx.Done():
		return nil
	}
}

// ownSocket is a service's private listener on the remote box.
type ownSocket struct {
	id       string
	path     string
	listener net.Listener
	serve    func(context.Context, net.Listener) error
}

// publishOwnSockets creates a socket for each service that needs one of its
// own, and returns a function that tears them all down.
//
// A service that cannot publish its socket is reported and skipped rather than
// failing the connection: an sshd with forwarding restrictions should not cost
// you port forwarding, which needs nothing on the remote at all.
func (s *Session) publishOwnSockets(
	ctx context.Context, conn Conn, paths shim.RemotePaths, instances []attached,
) ([]ownSocket, func(), error) {
	var out []ownSocket

	closeAll := func() {
		for _, o := range out {
			_ = o.listener.Close()
			// Cleanup outlives the cancelled context that brought us here, or
			// a stale socket is left for the next run to trip over.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupGrace)
			conn.RemoveSocket(cleanupCtx, o.path)
			cancel()
		}
	}

	for _, inst := range instances {
		provider, ok := inst.service.(service.SocketService)
		if !ok {
			continue
		}
		path := path.Join(path.Dir(paths.Socket), provider.SocketName())
		listener, err := conn.ListenSocket(ctx, path)
		if err != nil {
			s.opts.Bus.For(inst.meta.ID).Emit(event.Event{
				Kind: "socket-failed", Class: event.Lifecycle, Level: event.Warn,
				Text: inst.meta.Title + " could not publish its socket: " + err.Error(),
			})
			continue
		}
		out = append(out, ownSocket{
			id: inst.meta.ID, path: path, listener: listener, serve: provider.ServeSocket,
		})
		s.opts.Bus.For(inst.meta.ID).Emit(event.Event{
			Kind: "listening", Class: event.Diagnostic, Level: event.Debug,
			Text:   inst.meta.Title + " is listening on " + path,
			Fields: []any{"socket", path},
		})
	}
	return out, closeAll, nil
}

// attached pairs a running instance with the service it came from.
type attached struct {
	meta     service.Meta
	instance service.Instance
	// service is kept so the session can ask about the optional interfaces
	// after attaching, without a second pass over the registry.
	service service.Service
}

// attachAll probes and attaches every enabled service, and registers the ones
// that want a slice of the control socket.
//
// A service that cannot run here is not an error. A dev box without the
// 1Password CLI is an ordinary dev box, and refusing to forward ports because
// of it would be absurd — so it is reported once and skipped.
func (s *Session) attachAll(
	ctx context.Context, conn Conn, facts service.Facts, paths shim.RemotePaths,
	label string, socket *socketServer,
) ([]attached, []service.Advisor, service.Host) {
	var instances []attached
	var advisors []service.Advisor
	// One host value is enough for the advisors: they differ only in the
	// service-scoped config and event sink, and setup advice uses neither.
	var adviceHost service.Host

	for _, svc := range s.opts.Services {
		meta := svc.Meta()
		// News *about* a service is emitted through that service's own sink,
		// not the session's: it is what a reader filtering on "1password"
		// expects to see, and "1password is unavailable" attributed to
		// "session" would be invisible to them.
		sink := s.opts.Bus.For(meta.ID)

		if !s.opts.Config.Enabled(label, meta.ID, true) {
			sink.Emit(event.Event{
				Kind: "disabled", Class: event.Diagnostic, Level: event.Debug,
				Text: meta.Title + " is switched off for " + label,
			})
			continue
		}

		h := &host{
			label:  label,
			facts:  facts,
			paths:  paths,
			events: sink,
			config: s.opts.Config.Section(label, meta.ID),
			client: conn,
		}

		if support := svc.Probe(ctx, h); !support.OK {
			sink.Emit(event.Event{
				Kind: "unavailable", Class: event.Lifecycle, Level: event.Info,
				Text: meta.Title + " is unavailable: " + support.Reason,
			})
			continue
		}

		instance, err := svc.Attach(ctx, h)
		if err != nil {
			sink.Emit(event.Event{
				Kind: "attach-failed", Class: event.Lifecycle, Level: event.Warn,
				Text: "could not start " + meta.Title + ": " + err.Error(),
			})
			continue
		}

		if handler, ok := svc.(service.SocketHandler); ok {
			socket.register(meta.ID, handler)
		}
		if advisor, ok := svc.(service.Advisor); ok {
			if lines := advisor.SetupLines(h); len(lines) > 0 {
				advisors = append(advisors, advisor)
			}
		}

		adviceHost = h
		instances = append(instances, attached{meta: meta, instance: instance, service: svc})
		// Diagnostic, not Info: three services starting normally is three lines
		// of filler at the top of every session, and the one line that matters
		// there — that we connected — was getting buried under them. A service
		// that cannot run still speaks up, because that is news.
		sink.Emit(event.Event{
			Kind: "started", Class: event.Diagnostic, Level: event.Debug,
			Text: meta.Title + " ready",
		})
	}
	return instances, advisors, adviceHost
}

// closeAll tears instances down in reverse order, so a service that was
// started after another is stopped before it.
func closeAll(instances []attached, bus *event.Bus) {
	for i := len(instances) - 1; i >= 0; i-- {
		if err := instances[i].instance.Close(); err != nil {
			bus.For(instances[i].meta.ID).Emit(event.Event{
				Kind:  "close-failed",
				Class: event.Diagnostic, Level: event.Debug,
				Text: "stopping " + instances[i].meta.Title + ": " + err.Error(),
			})
		}
	}
}

// annotate names the service a failure came from, so "connection lost" in the
// log says which half noticed.
func annotate(id string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", id, err)
}

// Prepare connects once, brings the remote helper up to date, reports what the
// shell still needs, and returns — without starting any service.
//
// It is `devtun install`: the same code path as a real session up to the point
// where services would attach, so what it verifies is what a session will
// actually do, rather than a second implementation that can drift from it.
func (s *Session) Prepare(ctx context.Context) error {
	conn, err := s.opts.Connector.Connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	label := s.opts.Connector.Label()
	facts, err := probeFacts(ctx, conn)
	if err != nil {
		return err
	}
	paths := shim.PathsFor(facts.Home, facts.RuntimeDir)

	syncer := &shimSyncer{Binary: s.opts.ShimBinary, Version: s.opts.Version, Fetch: s.opts.FetchShim, Events: s.events}
	uploaded, err := syncer.sync(ctx, conn, facts, paths, s.opts.Version)
	if err != nil {
		return err
	}
	kind, text := "shim-current", "the devtun helper on "+label+" was already current"
	if uploaded {
		kind, text = "shim-installed", "installed the devtun helper on "+label
	}
	s.events.Emit(event.Event{
		Kind: kind, Class: event.Lifecycle, Level: event.Info, Text: text,
		Fields: []any{"version", s.opts.Version, "path", paths.Binary},
	})

	s.reportSetup(ctx, conn, facts, paths, label, nil, nil)
	return nil
}
