package browser

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
	"github.com/jclement/devtun/internal/tunnels"
)

// exchange runs one open request through HandleConn over an in-process pipe.
func exchange(t *testing.T, svc *Service, request openRequest) openResponse {
	t.Helper()
	client, server := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = svc.HandleConn(context.Background(), server, service.Caller{Program: "vite"})
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := shim.WriteFrame(client, request); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	var response openResponse
	if err := shim.ReadFrame(client, &response); err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	client.Close()
	wg.Wait()
	return response
}

func TestHandleConnOpensARewrittenURL(t *testing.T) {
	var opened string
	svc := New(Options{
		Tunnels: &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174, Remapped: false}}},
		Open:    func(_ context.Context, u string) error { opened = u; return nil },
		Poll:    time.Millisecond,
		Wait:    50 * time.Millisecond,
	})

	got := exchange(t, svc, openRequest{URL: "http://localhost:5173/app"})

	if !got.OK {
		t.Fatalf("want success, got error %q", got.Error)
	}
	if opened != "http://localhost:5174/app" {
		t.Errorf("opened the wrong URL: %q", opened)
	}
}

// A refusal must come back as a reply, not a dropped connection: the shim on
// the far side prints it so the human can open the URL themselves.
func TestHandleConnReportsARefusalRatherThanHangingUp(t *testing.T) {
	svc := New(Options{
		Tunnels: &fakeTunnels{},
		Open:    func(context.Context, string) error { return nil },
		Poll:    time.Millisecond,
		Wait:    50 * time.Millisecond,
	})

	got := exchange(t, svc, openRequest{URL: "http://localhost:9999/"})

	if got.OK {
		t.Fatal("an unforwarded port must not report success")
	}
	if !strings.Contains(got.Error, "9999") {
		t.Errorf("the reply should say what was wrong, got %q", got.Error)
	}
}

// A failure to launch the browser is the user's problem to hear about, not
// something to swallow into a success.
func TestHandleConnReportsALaunchFailure(t *testing.T) {
	svc := New(Options{
		Tunnels: &fakeTunnels{states: []tunnels.State{{RemotePort: 3000, LocalPort: 3000}}},
		Open:    func(context.Context, string) error { return errNoBrowser },
		Poll:    time.Millisecond,
		Wait:    50 * time.Millisecond,
	})

	got := exchange(t, svc, openRequest{URL: "http://localhost:3000/"})

	if got.OK {
		t.Fatal("a failed launch must not report success")
	}
	if !strings.Contains(got.Error, "no browser") {
		t.Errorf("the reply should carry the reason, got %q", got.Error)
	}
}

func TestAttachAndCloseAreQuiet(t *testing.T) {
	svc := New(Options{Open: func(context.Context, string) error { return nil }})
	inst, err := svc.Attach(context.Background(), stubHost{})
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- inst.Run(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a cancelled Run should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if err := inst.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// stubHost is the smallest thing satisfying service.Host: this service uses
// only the label and the event sink.
type stubHost struct{ service.Host }

func (stubHost) Label() string      { return "bedev" }
func (stubHost) Events() event.Sink { return event.Discard }

var errNoBrowser = errNoBrowserType{}

type errNoBrowserType struct{}

func (errNoBrowserType) Error() string { return "no browser on this machine" }

// A browser window appearing because a process on another machine asked for it
// must never be a surprise: it has to be accountable afterwards.
func TestOpeningIsReported(t *testing.T) {
	bus := event.NewBus(8)
	svc := New(Options{
		Tunnels: &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:    func(context.Context, string) error { return nil },
		Poll:    time.Millisecond,
		Wait:    50 * time.Millisecond,
	})
	if _, err := svc.Attach(context.Background(), busHost{bus: bus}); err != nil {
		t.Fatal(err)
	}

	if got := exchange(t, svc, openRequest{URL: "http://localhost:5173/app"}); !got.OK {
		t.Fatalf("want success, got %q", got.Error)
	}

	var found bool
	for _, e := range bus.History() {
		if e.Kind == "opened" && e.Class == event.Network {
			found = true
			if !strings.Contains(e.Text, "5174") {
				t.Errorf("the event should name the URL actually opened, got %q", e.Text)
			}
			if !strings.Contains(e.Text, "vite") {
				t.Errorf("the event should name who asked, got %q", e.Text)
			}
		}
	}
	if !found {
		t.Errorf("opening a browser emitted nothing:\n%+v", bus.History())
	}
}

func TestRefusalIsReported(t *testing.T) {
	bus := event.NewBus(8)
	svc := New(Options{
		Tunnels: &fakeTunnels{},
		Open:    func(context.Context, string) error { return nil },
		Poll:    time.Millisecond,
		Wait:    20 * time.Millisecond,
	})
	if _, err := svc.Attach(context.Background(), busHost{bus: bus}); err != nil {
		t.Fatal(err)
	}

	_ = exchange(t, svc, openRequest{URL: "http://localhost:9999/"})

	for _, e := range bus.History() {
		if e.Kind == "refused" && e.Level == event.Warn {
			return
		}
	}
	t.Errorf("a refusal should be reported too:\n%+v", bus.History())
}

type busHost struct {
	service.Host
	bus *event.Bus
}

func (h busHost) Label() string      { return "bedev" }
func (h busHost) Events() event.Sink { return h.bus.For("browser") }
