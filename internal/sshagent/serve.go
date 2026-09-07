package sshagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// socketName is what the agent socket is called on the remote box, beside the
// control socket. See service.SocketService for why it cannot be the control
// socket: an `ssh` client speaks the agent protocol the instant it connects and
// will never send devtun's greeting frame first.
const socketName = "devtun-agent.sock"

// SocketName is the file name for this service's own socket.
func (s *Service) SocketName() string { return socketName }

// SetupLines is the one line the remote shell needs.
//
// It is returned unconditionally. Whether the variable is already set is not
// something this service can tell — it sees the host's PATH, not its
// environment — and the session is what compares the line against what the
// user's login shell actually reports, printing setup advice only for what is
// genuinely missing.
func (s *Service) SetupLines(h service.Host) []string {
	return []string{fmt.Sprintf("export SSH_AUTH_SOCK=%q", path.Join(path.Dir(h.SocketPath()), socketName))}
}

// ServeSocket accepts agent connections until the context is cancelled.
//
// Unlike the 1Password broker's one-request-per-connection, these connections
// are long-lived and carry many requests: an `ssh` client opens one, binds it
// to its destination, lists, signs, and holds it for the whole handshake. So
// each gets a goroutine and its own connection to the local agent, and the
// destination a bind established stays with it.
func (s *Service) ServeSocket(ctx context.Context, listener net.Listener) error {
	var connections sync.WaitGroup
	defer connections.Wait()

	// Closing the listener is what unblocks Accept; nothing else will, and the
	// session closes it only after this has returned. Double-closing it there
	// is harmless.
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accepting an agent connection: %w", err)
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			s.serveConn(ctx, conn)
		}()
	}
}

// serveConn serves one forwarded agent connection.
func (s *Service) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	host := s.current()
	if host == nil {
		// The session publishes the socket only for an attached service, so
		// this is a wiring mistake rather than anything a remote box can
		// provoke.
		return
	}
	l := &link{host: host.Label(), events: host.Events()}

	local, err := s.dial(ctx)
	if err != nil {
		l.failed("connect", err.Error())
		return
	}
	defer func() { _ = local.Close() }()

	// ServeAgent is parked in a read and knows nothing about contexts, so
	// cancellation has to arrive as a closed connection. Both ends are closed:
	// the remote one to end the loop, the local one so a signature waiting on
	// the agent cannot outlive the session either.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		_ = local.Close()
	})
	defer stop()

	// One caveat about ServeAgent worth knowing before reading the event log:
	// it writes every request that returns an error — every refused signature,
	// every refused Add — to the standard logger, and there is no hook to stop
	// it (x/crypto's own comment there is a TODO asking for one). devtun uses
	// `log` for nothing else, so the remedy is one line where the process
	// starts, not a fork of the agent server here.
	g := &gate{ctx: ctx, svc: s, upstream: agent.NewClient(local), link: l}

	// ServeAgent returns only when the connection fails, so there is always an
	// error; the question is whether it is anything more than the client having
	// hung up, which is how every one of these ends.
	if err := agent.ServeAgent(g, conn); !disconnected(ctx, err) {
		l.failed("serve", err.Error())
	}
}

// disconnected reports the errors that mean "the client went away", which every
// agent connection ends with and none of which is news.
func disconnected(ctx context.Context, err error) bool {
	return ctx.Err() != nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}

// authorize consults policy and, if policy has no answer, the human.
//
// Note what is passed to Decide: the host devtun connected to, and the subject
// built from the key and the destination. Nothing the connection said about
// itself takes part — an agent connection carries no provenance at all, and
// what little the protocol offers would be the remote box describing itself.
func (s *Service) authorize(ctx context.Context, l *link, subject string, dest destination) (allowed bool, reason string) {
	asked := s.gate.Authorize(ctx, prompt.Request{
		Host:    l.host,
		Subject: subject,
		Noun:    "key",
		// The scope is what a subject-wide grant will actually cover, and for a
		// key that is the destination. "Allow this key for github.com this
		// session" is a promise someone can weigh; "allow this key" is not.
		Scope: dest.String(),
		// A `git push` signs several times in a row. Landing the cursor on
		// "allow once" would cost a keystroke per signature and get the whole
		// service switched off by lunchtime; the options stay in
		// narrowest-first order, only the starting point moves.
		Prefer: prompt.ChoiceAllowSecretSession,
		Rows:   dest.rows(),
		// Nothing about the caller: an agent connection carries no provenance
		// at all, and what little the protocol offers would be the remote box
		// describing itself.
	})

	if asked.Err != nil {
		l.failed(subject, "could not save the rule: "+asked.Err.Error())
	} else if asked.Note != "" {
		l.event("saved", event.Info, asked.Note)
	}
	return asked.Allowed, asked.Reason
}

// link is one connection's surroundings: the authenticated host it arrived
// from, and where its events go. The host label is what every decision is
// recorded against, which is why it is taken from the SSH destination and
// nowhere else.
type link struct {
	host   string
	events event.Sink
}

// The events below are this service's security record: which key signed for
// where, and what was decided. Every semantic event gets a method so the
// wording stays consistent and the set of things worth reporting is visible in
// one place.

func (l *link) event(kind string, level event.Level, text string, fields ...any) {
	l.events.Emit(event.Event{
		Kind:   kind,
		Class:  event.Security,
		Level:  level,
		Text:   text,
		Fields: fields,
	})
}

// requested records an incoming signature request, before any decision is made,
// so a request sitting waiting for a human is visible while it waits.
func (l *link) requested(subject string, dest destination) {
	l.event("requested", event.Info,
		fmt.Sprintf("%s wants to sign with %s", l.host, subject),
		"dest", dest.String())
}

// signed records a signature that was made, and how long the agent took.
func (l *link) signed(subject, reason string, elapsed time.Duration) {
	l.event("signed", event.Info,
		fmt.Sprintf("signed for %s: %s (%s)", l.host, subject, reason),
		"why", reason, "took", elapsed.Round(time.Millisecond))
}

// denied records a refused signature. Refusals are Info rather than Warn:
// denying is the system working, not failing.
func (l *link) denied(subject, reason string) {
	l.event("denied", event.Info,
		fmt.Sprintf("refused %s a signature with %s — %s", l.host, subject, reason),
		"why", reason)
}

// listed records the remote box learning which keys are loaded. It is not an
// authentication and it is not refused, but it is the one thing an unattended
// box can get out of the agent unasked, so it belongs in the record.
func (l *link) listed(keys int, dest destination) {
	l.event("listed", event.Info,
		fmt.Sprintf("%s listed the %d keys in your agent", l.host, keys),
		"keys", keys, "dest", dest.String())
}

// refused records an operation this service never performs. Warn, not Info,
// because nothing a dev box legitimately does asks to mutate the agent on your
// desk — so one of these is worth looking at even though it was blocked.
func (l *link) refused(what string, dest destination) {
	l.event("refused", event.Warn,
		fmt.Sprintf("refused to let %s %s your agent", l.host, what),
		"dest", dest.String())
}

// bound records the destination a connection has proved it is signing for.
//
// Onward forwarding gets a Warn: it means the box you are authenticating *to*
// will have your agent as well, which is the exact blind-trust chain this
// service exists to make visible.
func (l *link) bound(dest destination) {
	level, onward := event.Info, ""
	if dest.forwarding {
		level, onward = event.Warn, " — and will be offered your agent in turn"
	}
	l.event("bound", level,
		fmt.Sprintf("%s is signing for %s%s", l.host, dest, onward),
		"dest", dest.String(), "forwarding", dest.forwarding)
}

// unbound records a session-bind that was unreadable or unverifiable. It is a
// Warn and it names the connection as unbound, because from here on its
// signatures are attributed to an unknown destination — and a bind that fails
// to verify is either a broken client or an attempt to borrow somebody else's
// grant.
func (l *link) unbound(err error) {
	l.event("unbound", event.Warn,
		fmt.Sprintf("ignored a destination %s claimed: %s", l.host, err),
		"err", err.Error())
}

// failed records this service, or the agent behind it, going wrong — which is
// neither an allow nor a deny and should not be counted as either.
func (l *link) failed(what, detail string) {
	l.event("failed", event.Error, "the SSH agent could not "+what, "err", detail)
}
