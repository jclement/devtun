package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// helloTimeout drops a connection that opens and then says nothing. A client
// that has arrived but will not identify itself is either broken or probing,
// and either way it should not hold a goroutine.
const helloTimeout = 30 * time.Second

// socketServer accepts shim connections on the reverse-forwarded socket and
// routes each to the service it named.
//
// Routing on a first frame rather than on a socket per service is what lets
// devtun add a capability without adding a socket, a path convention and a line
// in the user's shell rc. It also means a service is free to keep its
// connection open for a stream — the envelope says nothing about what follows
// it — which one-socket-per-service would have made another negotiation.
type socketServer struct {
	handlers map[string]service.SocketHandler
	events   event.Sink
}

func newSocketServer(events event.Sink) *socketServer {
	return &socketServer{handlers: make(map[string]service.SocketHandler), events: events}
}

// register wires a service id to its handler.
func (s *socketServer) register(id string, h service.SocketHandler) {
	s.handlers[id] = h
}

// serve accepts until the listener fails or ctx is cancelled.
func (s *socketServer) serve(ctx context.Context, listener net.Listener) error {
	var live sync.WaitGroup
	defer live.Wait()

	// Closing the listener is what unblocks Accept; there is no other way to
	// interrupt it.
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accepting a shim connection: %w", err)
		}
		live.Add(1)
		go func() {
			defer live.Done()
			s.handle(ctx, conn)
		}()
	}
}

// handle reads the Hello and hands the connection to the named service. The
// handler owns the connection from that point, including closing it — a
// service that wants to stream cannot have this function close underneath it.
func (s *socketServer) handle(ctx context.Context, conn net.Conn) {
	hello, err := readHello(ctx, conn)
	if err != nil {
		_ = conn.Close()
		if !errors.Is(err, io.EOF) {
			s.events.Emit(event.Event{
				Kind: "rejected", Class: event.Diagnostic, Level: event.Debug,
				Text: "a shim connection was dropped: " + err.Error(),
			})
		}
		return
	}

	handler, ok := s.handlers[hello.Service]
	if !ok {
		// Say why, rather than hanging up. The person on the far side ran `op`
		// and got an EOF, which tells them nothing and looks like devtun is
		// broken — when in fact the answer is a toggle they or someone else
		// turned off, on a machine they may not be sitting at.
		_ = shim.WriteFrame(conn, refusal{
			Error: fmt.Sprintf("the %s service is switched off for this host on the workstation", hello.Service),
		})
		_ = conn.Close()
		// Naming a service that is not running is worth saying out loud: it is
		// what you see when a service is disabled and something on the remote
		// box still expects it, and the fix is a toggle rather than a mystery.
		s.events.Emit(event.Event{
			Kind: "unhandled", Class: event.Lifecycle, Level: event.Warn,
			Text:   fmt.Sprintf("%s on the remote asked for the %q service, which is not running here", callerName(hello.Caller), hello.Service),
			Fields: []any{"service", hello.Service},
		})
		return
	}

	if err := handler.HandleConn(ctx, conn, hello.Caller); err != nil && ctx.Err() == nil {
		s.events.Emit(event.Event{
			Service: hello.Service,
			Kind:    "failed", Class: event.Diagnostic, Level: event.Warn,
			Text: "serving a shim request failed: " + err.Error(),
		})
	}
}

// refusal is the one frame the session itself sends. Its shape is the common
// prefix of every service's response — an error string — so a shim decoding its
// own reply type still finds the message.
type refusal struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// readHello reads and validates the greeting frame.
func readHello(ctx context.Context, conn net.Conn) (shim.Hello, error) {
	// A connection forwarded over SSH ignores SetDeadline, so the deadline is
	// enforced by closing the connection from a watchdog instead.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			_ = conn.Close()
		case <-time.After(helloTimeout):
			_ = conn.Close()
		}
	}()

	var hello shim.Hello
	if err := shim.ReadFrame(conn, &hello); err != nil {
		return hello, err
	}
	// Equality, not compatibility: the session re-uploads the shim on connect,
	// so a mismatch means something is wrong rather than merely old, and
	// saying so plainly beats guessing at which fields still mean what.
	if hello.V != shim.Version {
		return hello, fmt.Errorf("the remote shim speaks protocol v%d but this devtun speaks v%d", hello.V, shim.Version)
	}
	if hello.Service == "" {
		return hello, errors.New("the remote shim named no service")
	}
	// Everything in Caller is chosen by a process on a semi-trusted box and is
	// shown to a human — in a log line, and in the approval prompt where it is
	// the evidence somebody decides on. A cursor-movement escape in a program
	// name could repaint what that prompt appears to be asking.
	hello.Caller.User = event.SanitizeTo(hello.Caller.User, 32)
	hello.Caller.Host = event.SanitizeTo(hello.Caller.Host, 64)
	hello.Caller.CWD = event.SanitizeTo(hello.Caller.CWD, 128)
	hello.Caller.Program = event.SanitizeTo(hello.Caller.Program, 64)
	hello.Caller.Version = event.SanitizeTo(hello.Caller.Version, 32)
	return hello, nil
}

// callerName renders a caller for a message, never for a decision.
func callerName(c service.Caller) string {
	switch {
	case c.Program != "" && c.User != "":
		return c.Program + " (" + c.User + ")"
	case c.Program != "":
		return c.Program
	case c.User != "":
		return c.User
	default:
		return "something"
	}
}
