// Package session owns a devtun connection to one host: the SSH link, the
// facts about the box, the control socket, and the services layered on top.
//
// It is the only place reconnect logic lives. A laptop sleeps, a network comes
// and goes, a dev box reboots; none of that should mean going back to a
// terminal to restart something, and none of it should be a special case inside
// a service. So a reconnect is Close on every Instance followed by a fresh
// Attach, and anything that must survive it — a live grant, a tunnel's local
// port assignment — belongs to the Service, which outlives the connection.
package session

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

const (
	// A black-holed link — a closed lid, vanished wifi — leaves the TCP
	// session open as far as both ends are concerned, so a keepalive is the
	// only thing that notices. The timeout is the load-bearing half: without
	// it the session sits there looking healthy and dead.
	keepAliveInterval = 15 * time.Second
	// socketCheckInterval is how often the published sockets are confirmed to
	// still be there. Slower than the keepalive on purpose: losing a socket is
	// rare and costs a shell round trip to notice, while losing the connection
	// is common and costs nothing.
	socketCheckInterval = 30 * time.Second
	keepAliveTimeout    = 20 * time.Second

	minReconnectDelay = 1 * time.Second
	maxReconnectDelay = 30 * time.Second
	// A connection that lasted this long is evidence the trouble is over, so
	// the next outage starts backing off from the bottom again.
	stableConnection = 60 * time.Second

	// cleanupGrace bounds the tidy-up that runs after the context that brought
	// us here has already been cancelled.
	cleanupGrace = 5 * time.Second
)

// State is what the connection is doing, for the status bar and the log.
type State string

const (
	Connecting   State = "connecting"
	Connected    State = "connected"
	Reconnecting State = "reconnecting"
	Disconnected State = "disconnected"
	Stopped      State = "stopped"
)

// Status is a snapshot of the session for a renderer.
type Status struct {
	State     State
	Detail    string
	Attempt   int
	NextRetry time.Time
	Since     time.Time
}

// Connector establishes SSH connections. It is an interface so the supervisor
// can be tested against an in-process server, or none at all.
type Connector interface {
	// Connect dials the host. It must honour ctx.
	Connect(ctx context.Context) (Conn, error)
	// Label is the name config and policy are recorded against.
	Label() string
	// Describe is how the destination is shown to a human.
	Describe() string
}

// unattendable is implemented by a Connector that can stop asking the user
// questions. The supervisor calls it once the first connection has been made,
// because everything after that happens behind the interface.
type unattendable interface {
	GoUnattended()
}

// Conn is one live SSH connection.
type Conn interface {
	remoteClient
	// ListenSocket publishes a socket on the remote. takeOver displaces one
	// another devtun is answering on, which is refused by default: the session
	// that had it would keep running, still calling itself connected, while
	// sshd routed nothing to it ever again.
	ListenSocket(ctx context.Context, path string, takeOver bool) (net.Listener, error)
	RemoveSocket(ctx context.Context, path string)
	KeepAlive(ctx context.Context, interval, timeout time.Duration) error
	Close() error
}

// Options configure a session.
type Options struct {
	Connector Connector
	Bus       *event.Bus
	// Services are tried in order. Each is asked whether it can work here
	// before it is attached.
	Services []service.Service
	// Config supplies each service its namespaced slice, and answers whether a
	// service is enabled on this host.
	Config ConfigProvider
	// Reconnect keeps the session alive across a dropped link. False makes a
	// drop fatal, which is what a supervisor that should restart the process
	// wants.
	Reconnect bool
	// AutoInstall keeps the remote shim in step with this build.
	AutoInstall bool
	// TakeOver displaces another devtun already attached to this host, rather
	// than refusing to start.
	TakeOver bool
	// ShimBinary overrides the shim uploaded to the remote.
	ShimBinary string
	// FetchShim downloads a helper built for another platform. Nil means one
	// cannot be downloaded, which is right for a development build that has no
	// release to take it from.
	FetchShim func(ctx context.Context, goos, goarch string) (string, error)
	// Version is this build, used for the shim handshake.
	Version string
	// Setup decides how forward devtun is about the remote shell rc.
	Setup SetupMode
	// AskSetup puts the question to the user and reports their answer. Nil
	// means there is nobody to ask, which is the same as declining.
	AskSetup func(ctx context.Context, plan RCPlan) (bool, error)
	// OnStatus is called whenever the connection state changes. It must not
	// block.
	OnStatus func(Status)
}

// ConfigProvider is the session's view of the config store, narrowed to the
// two questions it actually asks.
type ConfigProvider interface {
	// Enabled reports whether a service should run on this host.
	Enabled(label, serviceID string, fallback bool) bool
	// Section returns a namespaced slice of a host's configuration. The
	// session uses it for its own state too, under the reserved id below, so
	// there is one persistence mechanism rather than two.
	Section(label, serviceID string) service.Config
}

// sessionSection is the reserved config id the session keeps its own state
// under — currently just whether the shell-rc question has been put.
const sessionSection = "session"

// Session supervises one host.
type Session struct {
	opts   Options
	events event.Sink

	// retry lets the UI cut short a backoff. Buffered, so asking twice while
	// already retrying is harmless.
	retry chan struct{}

	mu     sync.Mutex
	status Status
}

// New builds a session. It does not connect.
func New(opts Options) *Session {
	return &Session{
		opts:   opts,
		events: opts.Bus.For("session"),
		retry:  make(chan struct{}, 1),
		status: Status{State: Connecting},
	}
}

// SetAskSetup replaces the shell-rc asker.
//
// It exists because the two interfaces ask the same question differently — a
// terminal confirmation in log mode, a modal in the TUI — and the TUI is
// constructed after the session it drives. Call it before Run; it is not safe
// afterwards, and there is no reason to.
func (s *Session) SetAskSetup(ask func(context.Context, RCPlan) (bool, error)) {
	s.opts.AskSetup = ask
}

// SetPrompter is the same arrangement for approvals: under the TUI the
// question has to be a modal inside it, and that modal cannot exist until the
// program does. Call before Run.
func (s *Session) SetPrompter(install func()) {
	if install != nil {
		install()
	}
}

// Status returns the current connection state.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// RetryNow cuts short the wait before the next connection attempt, which is
// what you press after opening a laptop lid: the backoff was measured against
// an outage that has already ended.
func (s *Session) RetryNow() {
	select {
	case s.retry <- struct{}{}:
	default:
	}
}

// Run owns the connection until ctx is cancelled.
func (s *Session) Run(ctx context.Context) error {
	delay := minReconnectDelay
	attempt := 0
	// reconnected distinguishes the first connection from every one after it,
	// so the log can say "connected" once and "reconnected after 42s" later —
	// which are different pieces of news to someone who just opened a lid.
	reconnected := false
	lastDrop := time.Now()

	for ctx.Err() == nil {
		attempt++
		// The first attempt is "connecting"; every one after it is a
		// reconnection, which is a different thing to see in a status bar.
		state := Reconnecting
		if attempt == 1 {
			state = Connecting
		}
		s.report(Status{State: state, Attempt: attempt})

		conn, err := s.opts.Connector.Connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.report(Status{State: Disconnected, Attempt: attempt, Detail: err.Error(), NextRetry: time.Now().Add(delay)})
			s.events.Emit(event.Event{
				Kind: "connect-failed", Class: event.Lifecycle, Level: event.Warn,
				Text: fmt.Sprintf("could not reach %s: %v — retrying in %s",
					s.opts.Connector.Label(), err, delay),
			})
			if !s.opts.Reconnect || isFatal(err) {
				return err
			}
			if !s.wait(ctx, delay) {
				break
			}
			delay = nextDelay(delay)
			continue
		}

		// From here on nobody can answer a question: the first connection is
		// the last one made while a terminal is still ours.
		if u, ok := s.opts.Connector.(unattendable); ok {
			u.GoUnattended()
		}

		attempt = 0
		started := time.Now()
		s.report(Status{State: Connected, Since: started})
		s.announce(reconnected, time.Since(lastDrop))

		err = s.serveOnce(ctx, conn)
		lastDrop = time.Now()
		reconnected = true

		if ctx.Err() != nil {
			break
		}
		if !s.opts.Reconnect {
			return err
		}
		// A box that will never accept the connection is not something to keep
		// trying: thirty-second retries against a permanent refusal look like a
		// hang, and the one message that explained it has long scrolled away.
		if isFatal(err) {
			s.events.Emit(event.Event{
				Kind: "refused", Class: event.Lifecycle, Level: event.Error,
				Text: "giving up on " + s.opts.Connector.Label() + ": " + err.Error(),
			})
			s.report(Status{State: Stopped, Detail: err.Error()})
			return err
		}
		if err != nil {
			s.events.Emit(event.Event{
				Kind: "disconnected", Class: event.Lifecycle, Level: event.Warn,
				Text: "connection lost: " + err.Error(),
			})
		}
		if time.Since(started) > stableConnection {
			delay = minReconnectDelay
		}
		s.report(Status{State: Disconnected, Detail: detailOr(err, "connection closed"), NextRetry: time.Now().Add(delay)})
		if !s.wait(ctx, delay) {
			break
		}
		delay = nextDelay(delay)
	}

	s.report(Status{State: Stopped})
	return nil
}

func detailOr(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}

// wait pauses before the next attempt, returning false if the session is
// shutting down.
func (s *Session) wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-s.retry:
		return true
	case <-t.C:
		return true
	}
}

func nextDelay(d time.Duration) time.Duration {
	if d *= 2; d > maxReconnectDelay {
		return maxReconnectDelay
	}
	return d
}

// announce puts the connection itself into the activity log. Everything else
// devtun does is reported; the one event a reader most wants to see first was
// the one thing that only reached the status bar.
func (s *Session) announce(again bool, down time.Duration) {
	if !again {
		s.events.Emit(event.Event{
			Kind: "connected", Class: event.Lifecycle, Level: event.Info,
			Text: "connected to " + s.opts.Connector.Label(),
		})
		return
	}
	s.events.Emit(event.Event{
		Kind: "reconnected", Class: event.Lifecycle, Level: event.Info,
		Text: fmt.Sprintf("reconnected to %s after %s", s.opts.Connector.Label(), down.Round(time.Second)),
	})
}

func (s *Session) report(st Status) {
	s.mu.Lock()
	if st.Since.IsZero() {
		st.Since = s.status.Since
	}
	s.status = st
	s.mu.Unlock()

	if s.opts.OnStatus != nil {
		s.opts.OnStatus(st)
	}
}
