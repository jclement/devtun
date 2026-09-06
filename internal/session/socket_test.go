package session

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// recordingHandler captures what a service was handed.
type recordingHandler struct {
	mu      sync.Mutex
	callers []service.Caller
	done    chan struct{}
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{done: make(chan struct{}, 4)}
}

func (h *recordingHandler) HandleConn(_ context.Context, conn net.Conn, caller service.Caller) error {
	defer conn.Close()
	h.mu.Lock()
	h.callers = append(h.callers, caller)
	h.mu.Unlock()
	h.done <- struct{}{}
	return nil
}

// serveOnSocketPair runs the server against an in-process pipe and returns the
// client end. No unix socket, no SSH, no flakes.
func serveOnSocketPair(t *testing.T, srv *socketServer) (net.Conn, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.serve(ctx, listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return conn, func() { cancel(); conn.Close() }
}

// collect subscribes to the bus and returns a snapshot function. The
// snapshot is taken under the same lock as the append, because the bus
// delivers from whichever goroutine emitted.
func collect(bus *event.Bus) func() []event.Event {
	var mu sync.Mutex
	var got []event.Event
	bus.Subscribe(func(e event.Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	return func() []event.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]event.Event(nil), got...)
	}
}

func TestHelloRoutesToTheNamedService(t *testing.T) {
	bus := event.NewBus(8)
	srv := newSocketServer(bus)
	opHandler, openHandler := newRecordingHandler(), newRecordingHandler()
	srv.register(shim.ServiceOp, opHandler)
	srv.register(shim.ServiceOpen, openHandler)

	conn, cleanup := serveOnSocketPair(t, srv)
	defer cleanup()

	hello := shim.Hello{V: shim.Version, Service: shim.ServiceOp}
	hello.Caller.Program = "deploy.sh"
	if err := shim.WriteFrame(conn, hello); err != nil {
		t.Fatal(err)
	}

	select {
	case <-opHandler.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the op handler was never reached")
	}
	if len(openHandler.done) != 0 {
		t.Error("the wrong handler was called")
	}
	opHandler.mu.Lock()
	defer opHandler.mu.Unlock()
	if opHandler.callers[0].Program != "deploy.sh" {
		t.Errorf("the caller did not reach the handler: %+v", opHandler.callers[0])
	}
}

// Naming a service that is not running is what you see when a service is
// disabled and something on the box still expects it. The fix is a toggle, so
// it must not look like a mystery.
func TestUnknownServiceIsReportedNotSilent(t *testing.T) {
	bus := event.NewBus(8)
	snapshot := collect(bus)
	srv := newSocketServer(bus)

	conn, cleanup := serveOnSocketPair(t, srv)
	defer cleanup()

	hello := shim.Hello{V: shim.Version, Service: "1password"}
	hello.Caller.Program = "deploy.sh"
	_ = shim.WriteFrame(conn, hello)

	waitFor(t, func() bool {
		for _, e := range snapshot() {
			if e.Kind == "unhandled" && e.Level == event.Warn {
				return true
			}
		}
		return false
	})
}

func TestVersionMismatchIsRefused(t *testing.T) {
	bus := event.NewBus(8)
	srv := newSocketServer(bus)
	handler := newRecordingHandler()
	srv.register(shim.ServiceOp, handler)

	conn, cleanup := serveOnSocketPair(t, srv)
	defer cleanup()

	_ = shim.WriteFrame(conn, shim.Hello{V: shim.Version + 1, Service: shim.ServiceOp})

	select {
	case <-handler.done:
		t.Fatal("a mismatched protocol version must not reach a handler")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestNamelessServiceIsRefused(t *testing.T) {
	bus := event.NewBus(8)
	srv := newSocketServer(bus)
	handler := newRecordingHandler()
	srv.register(shim.ServiceOp, handler)

	conn, cleanup := serveOnSocketPair(t, srv)
	defer cleanup()

	_ = shim.WriteFrame(conn, shim.Hello{V: shim.Version})

	select {
	case <-handler.done:
		t.Fatal("a Hello naming no service must not reach a handler")
	case <-time.After(300 * time.Millisecond):
	}
}

// A client that opens and then says nothing must not hold a goroutine for ever.
func TestSilentConnectionIsDropped(t *testing.T) {
	bus := event.NewBus(8)
	srv := newSocketServer(bus)
	handler := newRecordingHandler()
	srv.register(shim.ServiceOp, handler)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.serve(ctx, listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Cancelling is what a shutdown looks like; the silent connection must not
	// keep serve from returning.
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("a cancelled serve should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after cancellation")
	}
}

// Several services on one socket at the same time is the whole point.
func TestConcurrentConnectionsToDifferentServices(t *testing.T) {
	bus := event.NewBus(16)
	srv := newSocketServer(bus)
	opHandler, openHandler := newRecordingHandler(), newRecordingHandler()
	srv.register(shim.ServiceOp, opHandler)
	srv.register(shim.ServiceOpen, openHandler)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.serve(ctx, listener) }()

	for _, svc := range []string{shim.ServiceOp, shim.ServiceOpen, shim.ServiceOp} {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = shim.WriteFrame(conn, shim.Hello{V: shim.Version, Service: svc})
	}

	waitFor(t, func() bool {
		opHandler.mu.Lock()
		openHandler.mu.Lock()
		defer opHandler.mu.Unlock()
		defer openHandler.mu.Unlock()
		return len(opHandler.callers) == 2 && len(openHandler.callers) == 1
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// A shim that gets an EOF learns nothing. The answer is usually a toggle
// somebody turned off on a machine they are not sitting at, so it has to be
// said out loud rather than inferred from a closed connection.
func TestDisabledServiceIsToldWhy(t *testing.T) {
	bus := event.NewBus(8)
	srv := newSocketServer(bus)

	conn, cleanup := serveOnSocketPair(t, srv)
	defer cleanup()

	_ = shim.WriteFrame(conn, shim.Hello{V: shim.Version, Service: "1password"})

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var got refusal
	if err := shim.ReadFrame(conn, &got); err != nil {
		t.Fatalf("want a refusal frame, got %v", err)
	}
	if got.OK {
		t.Error("a refusal must not report success")
	}
	if !strings.Contains(got.Error, "1password") || !strings.Contains(got.Error, "switched off") {
		t.Errorf("the refusal should say which service and why, got %q", got.Error)
	}
}
