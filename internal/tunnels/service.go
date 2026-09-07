// Package tunnels forwards every port the remote box opens onto localhost.
//
// A remote dev server announces "http://localhost:5173" and means a machine
// you are not sitting at. This service watches what the remote is listening on
// and keeps a local listener open for each one, on the same port number
// wherever it can, so the URL the tool printed is the URL that works.
//
// It differs from its predecessor, autotun, in one deliberate way: nothing is
// exempted for having been up before devtun connected. autotun snapshotted the
// listening set at connect time and treated it as furniture, which is a fair
// rule for a one-shot session but a bad one for a tool you reattach to the
// same box with every day — a service becomes invisible for no better reason
// than that it started first, and each reconnect shows a different board.
// Everything at or above --min-port is forwarded, and the user hides what they
// do not want; see Mode.
//
// The Manager, and with it every local port assignment, lives on the Service
// rather than on an Instance. A reconnect is Close followed by Attach, and the
// whole point of remembering the assignments is that the browser tab you left
// open still works afterwards.
package tunnels

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/tunnels/probe"
)

var (
	_ service.Service      = (*Service)(nil)
	_ service.Configurable = (*Service)(nil)
	_ service.Instance     = (*instance)(nil)
	// A Host already runs scripts and collects their output, which is the
	// whole of what the prober needs — no adapter, and one fewer thing to keep
	// in step.
	_ probe.Runner = (service.Host)(nil)
)

// tools are the discovery commands worth asking Facts about, most preferred
// first. The remote prober picks between them again on its own; this is only
// about answering "can this work here" without a round trip.
var tools = []string{"ss", "lsof", "netstat"}

// Options configures the service. Start from DefaultOptions: a zero Policy
// forwards port 22, which is nobody's intent.
type Options struct {
	Policy Policy
	// Bind is the local address listeners bind to.
	Bind string
	// SamePort turns a busy local port into an error rather than a remap.
	SamePort bool
	// Interval is how often the remote is scanned.
	Interval time.Duration
	// Grace is how many consecutive missed scans a tunnel survives.
	Grace int
	// GlobalHide is devtun's top-level hide list, applied to every host. It
	// reads as a per-port hide but is never written back to a host's file.
	GlobalHide PortSet
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// DefaultOptions is the configuration with no flags given.
func DefaultOptions() Options {
	return Options{
		Policy:   DefaultPolicy(),
		Bind:     "127.0.0.1",
		Interval: 2 * time.Second,
	}
}

// Service is the tunnels capability.
type Service struct {
	opts  Options
	alloc *Allocator
	// sink forwards to whichever host is attached now. The Manager outlives
	// any one connection, so it cannot hold a Host's sink directly.
	sink *sinkRef

	mu    sync.Mutex
	mgr   *Manager
	store *Store
}

// New returns a tunnels service. Nothing touches the network until Attach.
func New(opts Options) *Service {
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.Policy.MaxPort == 0 {
		opts.Policy.MaxPort = 65535
	}
	if opts.Policy.RemoteBind == "" {
		opts.Policy.RemoteBind = BindAny
	}
	return &Service{
		opts:  opts,
		alloc: NewAllocator(opts.Bind, opts.SamePort),
		sink:  &sinkRef{},
	}
}

// Meta implements service.Service.
func (s *Service) Meta() service.Meta {
	return service.Meta{
		ID:    "tunnels",
		Title: "Tunnels",
		Glyph: "⇄",
		Class: event.Network,
		Short: "forward every port the remote box opens onto localhost",
	}
}

// Probe reports whether the host has anything that can list listening sockets.
//
// The first three answers come out of Facts, which the session gathered once
// for every service. Only a box with none of them costs a round trip, and only
// to ask about the last resort: /proc/net/tcp is a file, so it cannot show up
// in a tool lookup, and it is what makes a stripped Alpine container work.
func (s *Service) Probe(ctx context.Context, h service.Host) service.Support {
	facts := h.Facts()
	for _, tool := range tools {
		if facts.Has(tool) {
			return service.Supported()
		}
	}
	out, err := h.Output(ctx, "test -r /proc/net/tcp && echo yes")
	if err == nil && strings.TrimSpace(out) == "yes" {
		return service.Supported()
	}
	return service.Unsupported(fmt.Sprintf(
		"no usable port discovery tool on %s (needs ss, lsof, netstat or /proc/net/tcp)", h.Label()))
}

// Attach binds the service to a connection. The first call builds the Manager
// and reads the host's remembered decisions; later calls — every reconnect —
// reuse both, and swap nothing but the dialer and the event sink.
func (s *Service) Attach(ctx context.Context, h service.Host) (service.Instance, error) {
	s.sink.set(h.Events())

	s.mu.Lock()
	first := s.mgr == nil
	if first {
		s.store = NewStore(h.Config())
		s.mgr = NewManager(s.alloc, nil, ManagerOptions{
			Policy:     s.opts.Policy,
			Settings:   s.store,
			GlobalHide: s.opts.GlobalHide,
			HostHide:   s.store.Hide(),
			Grace:      s.opts.Grace,
			Events:     s.sink,
			Now:        s.opts.Now,
		})
	}
	mgr := s.mgr
	store := s.store
	s.mu.Unlock()

	// A hide list that would not parse fails open, so it has to be said out
	// loud: the alternative is a port you thought was hidden quietly appearing
	// on the board. Once, on the first attach — a reconnect re-reads nothing.
	if first {
		if err := store.HideErr(); err != nil {
			h.Events().Emit(event.Event{
				// Network, not Diagnostic: a diagnostic is dropped without
				// --verbose, and a hide list that silently did nothing is the
				// whole thing this line exists to prevent.
				Service: "tunnels", Class: event.Network, Level: event.Warn,
				Kind: "config", Text: err.Error(),
			})
		}
	}

	// The dialer's lifetime is the instance's, not Attach's: Attach may be
	// called with a context that covers only the attach, and a forwarder still
	// needs to open channels long after that returns.
	dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &instance{
		host:    h,
		mgr:     mgr,
		mon:     probe.NewMonitor(h, s.opts.Interval),
		dialCtx: dialCtx,
		cancel:  cancel,
	}, nil
}

// Manager exposes the forwarding state for the TUI and the control socket. It
// is nil until the first Attach, because it is bound to a host's config.
func (s *Service) Manager() *Manager {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mgr
}

// ViewPrefs returns how this host's table is presented.
func (s *Service) ViewPrefs() ViewPrefs {
	s.mu.Lock()
	store := s.store
	s.mu.Unlock()
	if store == nil {
		return DefaultViewPrefs()
	}
	return store.View()
}

// SetViewPrefs records how this host's table is presented, and applies the
// part of it the Manager owns.
func (s *Service) SetViewPrefs(p ViewPrefs) {
	s.mu.Lock()
	store, mgr := s.store, s.mgr
	s.mu.Unlock()

	if store != nil {
		store.SetView(p)
	}
	if mgr != nil {
		mgr.SetShowHidden(p.ShowHidden)
	}
}

// Settings implements service.Configurable. Everything here changes what you
// look at; forwarding is decided per port, with Mode.
func (s *Service) Settings() []service.Setting {
	boolAt := func(get func(ViewPrefs) bool, set func(*ViewPrefs, bool)) (func() string, func(string)) {
		return func() string {
				return fmt.Sprint(get(s.ViewPrefs()))
			}, func(v string) {
				p := s.ViewPrefs()
				set(&p, v == "true")
				s.SetViewPrefs(p)
			}
	}
	showGet, showSet := boolAt(
		func(p ViewPrefs) bool { return p.ShowHidden },
		func(p *ViewPrefs, v bool) { p.ShowHidden = v })
	idleGet, idleSet := boolAt(
		func(p ViewPrefs) bool { return p.InactiveLast },
		func(p *ViewPrefs, v bool) { p.InactiveLast = v })

	return []service.Setting{
		{
			Key:   "show_hidden",
			Title: "Show hidden ports",
			Help:  "List the ports you hid, so you can unhide one",
			Get:   showGet,
			Set:   showSet,
		},
		{
			Key:   "inactive_last",
			Title: "Idle rows last",
			Help:  "Sink rows with no tunnel below the ones that have them",
			Get:   idleGet,
			Set:   idleSet,
		},
	}
}

// instance is the service bound to one SSH connection.
type instance struct {
	host    service.Host
	mgr     *Manager
	mon     *probe.Monitor
	dialCtx context.Context
	cancel  context.CancelFunc
}

// Run drives the remote prober, syncing the manager with every scan, until the
// context is cancelled or the stream stops.
func (i *instance) Run(ctx context.Context) error {
	i.mgr.SetDialer(hostDialer{ctx: i.dialCtx, host: i.host})

	err := i.mon.Run(ctx,
		func(info probe.Info) {
			i.host.Events().Emit(event.Event{
				Kind:   "watching",
				Class:  event.Network,
				Level:  event.Info,
				Text:   fmt.Sprintf("watching for listening ports on %s (%s)", i.host.Label(), info.Mode),
				Fields: []any{"mode", string(info.Mode)},
			})
		},
		func(res probe.Result) { i.mgr.Sync(res.Snapshot) },
	)

	if ctx.Err() != nil {
		return nil // an orderly stop; the session is going away anyway
	}
	// The prober loops forever by design, so any return — including the io.EOF
	// of a cleanly closed session — means the link went away. Reporting it as
	// an error is what asks the supervisor to reconnect.
	return err
}

// Close drops the transport. The Manager, and every local port it has been
// assigned, stays on the Service ready for the next Attach.
func (i *instance) Close() error {
	i.cancel()
	i.mgr.SetDialer(nil)
	return nil
}

// hostDialer adapts a Host's channel opener to the narrow Dialer the
// forwarding path is written against, so that path stays testable against a
// plain in-process TCP server.
type hostDialer struct {
	ctx  context.Context
	host service.Host
}

// Dial opens a direct-tcpip channel. The network is ignored: an SSH channel is
// TCP or it is nothing.
func (d hostDialer) Dial(network, addr string) (net.Conn, error) {
	return d.host.DialTCP(d.ctx, addr)
}

// sinkRef is an event.Sink whose target is swapped on each Attach.
type sinkRef struct {
	mu sync.Mutex
	to event.Sink
}

func (s *sinkRef) set(to event.Sink) {
	s.mu.Lock()
	s.to = to
	s.mu.Unlock()
}

func (s *sinkRef) Emit(e event.Event) {
	s.mu.Lock()
	to := s.to
	s.mu.Unlock()
	if to != nil {
		to.Emit(e)
	}
}

// States, ForwardNow and TryLocalPort delegate to the Manager.
//
// They exist because the Manager is built lazily, on the first Attach — that is
// when a Host, and so a config store, first exists. Anything wired up before
// then (the browser bridge, the TUI) would otherwise capture a nil Manager and
// keep it forever. Delegating through the Service means callers hold the stable
// thing and ask late, and a call before the first connection answers emptily
// rather than panicking.

// States returns the current tunnel table, or nothing before the first
// connection.
func (s *Service) States() []State {
	if m := s.Manager(); m != nil {
		return m.States()
	}
	return nil
}

// ForwardNow overrides a skip for one port. Before the first connection there
// is nothing to override, which is not an error worth reporting upwards.
func (s *Service) ForwardNow(remotePort int) error {
	if m := s.Manager(); m != nil {
		return m.ForwardNow(remotePort)
	}
	return nil
}

// TryLocalPort asks for a specific local port for this session only.
func (s *Service) TryLocalPort(remotePort, local int) error {
	if m := s.Manager(); m != nil {
		return m.TryLocalPort(remotePort, local)
	}
	return nil
}
