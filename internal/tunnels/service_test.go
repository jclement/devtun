package tunnels

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

// fakeHost is a service.Host backed by an in-process TCP server. There is no
// SSH anywhere in these tests: the prober stream is a string and a channel is
// a loopback connection, which is what makes the whole path testable.
type fakeHost struct {
	label  string
	facts  service.Facts
	events event.Sink
	cfg    service.Config
	// stream is the framed prober transcript Run replays before parking.
	stream string
	// dialTo is where DialTCP actually connects, standing in for the remote.
	dialTo string
	// procReadable is what `test -r /proc/net/tcp` reports.
	procReadable bool

	mu     sync.Mutex
	dialed []string
}

func (h *fakeHost) Label() string        { return h.label }
func (h *fakeHost) Facts() service.Facts { return h.facts }
func (h *fakeHost) Events() event.Sink   { return h.events }
func (h *fakeHost) Config() service.Config {
	return h.cfg
}
func (h *fakeHost) ShimPath() string   { return "" }
func (h *fakeHost) SocketPath() string { return "" }

func (h *fakeHost) Run(ctx context.Context, script string, w io.Writer) error {
	if _, err := io.WriteString(w, h.stream); err != nil {
		return err
	}
	// The real prober loops until the session ends; so does this one, or the
	// instance would treat the end of the transcript as a dropped link.
	<-ctx.Done()
	return ctx.Err()
}

func (h *fakeHost) Output(ctx context.Context, script string) (string, error) {
	if strings.Contains(script, "/proc/net/tcp") && h.procReadable {
		return "yes\n", nil
	}
	return "", nil
}

func (h *fakeHost) Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	return nil
}

func (h *fakeHost) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	h.mu.Lock()
	h.dialed = append(h.dialed, address)
	h.mu.Unlock()
	return net.Dial("tcp", h.dialTo)
}

// lastDialed reports the address the tunnel last asked the remote to reach.
func (h *fakeHost) lastDialed() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.dialed) == 0 {
		return ""
	}
	return h.dialed[len(h.dialed)-1]
}

// proberStream builds the framed transcript for a host listening on ports.
func proberStream(ports ...int) string {
	var b strings.Builder
	b.WriteString("@@DEVTUN-READY 1 ss Linux\n")
	b.WriteString("@@DEVTUN-SCAN\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "LISTEN 0 511 127.0.0.1:%d 0.0.0.0:* users:((\"node\",pid=42,fd=7))\n", p)
	}
	b.WriteString("@@DEVTUN-END\n")
	return b.String()
}

func TestServiceMeta(t *testing.T) {
	meta := New(DefaultOptions()).Meta()
	if meta.ID != "tunnels" || meta.Title != "Tunnels" || meta.Glyph != "⇄" {
		t.Errorf("Meta() = %+v", meta)
	}
	if meta.Class != event.Network {
		t.Errorf("class = %q, want network", meta.Class)
	}
}

func TestServiceProbe(t *testing.T) {
	tests := []struct {
		name  string
		tools map[string]string
		proc  bool
		want  bool
	}{
		{"ss", map[string]string{"ss": "/usr/bin/ss"}, false, true},
		{"lsof only, the macOS path", map[string]string{"lsof": "/usr/sbin/lsof"}, false, true},
		{"netstat only, an old box", map[string]string{"netstat": "/bin/netstat"}, false, true},
		{"nothing but /proc, a stripped container", nil, true, true},
		{"nothing at all", map[string]string{"bash": "/bin/bash"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &fakeHost{
				label:        "devbox",
				facts:        service.Facts{Tools: tt.tools},
				events:       event.Discard,
				procReadable: tt.proc,
			}
			got := New(DefaultOptions()).Probe(context.Background(), h)
			if got.OK != tt.want {
				t.Fatalf("Probe().OK = %v, want %v (%s)", got.OK, tt.want, got.Reason)
			}
			// A reason has to name the host, so the user knows which box to
			// go and look at.
			if !got.OK && !strings.Contains(got.Reason, "devbox") {
				t.Errorf("reason = %q, want it to name the host", got.Reason)
			}
		})
	}
}

// The point of the Service/Instance split: a reconnect is Close then Attach,
// and the local port a service landed on comes back with it, so the browser
// tab left open on it keeps working.
func TestServiceReattachReclaimsTheLocalPort(t *testing.T) {
	echo := newEchoServer(t)
	events := &collector{}

	// A remote port that is busy locally, so the first allocation has to remap
	// and the reclaimed number is a number worth reclaiming.
	remote := occupy(t)
	host := &fakeHost{
		label:  "devbox",
		facts:  service.Facts{Tools: map[string]string{"ss": "/usr/bin/ss"}},
		events: events,
		cfg:    newFakeConfig(),
		stream: proberStream(remote),
		dialTo: echo.addr(),
	}

	svc := New(DefaultOptions())
	local, stop := attachUntilActive(t, svc, host, remote)
	if local == remote {
		t.Fatalf("local port %d should have been remapped away from the busy %d", local, remote)
	}
	if got := roundTrip(t, local, "one"); got != "ONE" {
		t.Errorf("round trip = %q, want ONE", got)
	}
	// The far end of the channel is the remote's own port, not the local one.
	if want := fmt.Sprintf("127.0.0.1:%d", remote); host.lastDialed() != want {
		t.Errorf("dialed %q, want %q", host.lastDialed(), want)
	}
	mgr := svc.Manager()
	firstSeen := stateFor(t, mgr, remote).FirstSeen
	stop()

	// The link drops and comes back. Everything about the connection is new;
	// nothing about the port table should be.
	again, stop := attachUntilActive(t, svc, host, remote)
	defer stop()
	if again != local {
		t.Errorf("local port = %d after reattach, want the original %d", again, local)
	}
	if svc.Manager() != mgr {
		t.Error("the manager was rebuilt on reattach; the port table lives on the service")
	}
	if got := stateFor(t, svc.Manager(), remote).FirstSeen; !got.Equal(firstSeen) {
		t.Errorf("first seen = %v after reattach, want the original %v — a reconnect is not a new service", got, firstSeen)
	}
	if got := roundTrip(t, local, "two"); got != "TWO" {
		t.Errorf("round trip after reattach = %q, want TWO", got)
	}

	kinds := events.kinds()
	if len(kinds) == 0 || kinds[0] != "watching" {
		t.Errorf("events = %v, want the first to report what discovery mode was chosen", kinds)
	}
	if !contains(kinds, KindOpened) || !contains(kinds, KindClosed) {
		t.Errorf("events = %v, want an opened and a closed", kinds)
	}
}

// A decision made through the service reaches the host's config document, and
// is honoured by the next process to open it.
func TestServicePersistsThroughTheConfigSeam(t *testing.T) {
	echo := newEchoServer(t)
	cfg := newFakeConfig()
	remote := freePort(t)

	newHost := func() *fakeHost {
		return &fakeHost{
			label:  "devbox",
			facts:  service.Facts{Tools: map[string]string{"ss": "/usr/bin/ss"}},
			events: event.Discard,
			cfg:    cfg,
			stream: proberStream(remote),
			dialTo: echo.addr(),
		}
	}

	first := New(DefaultOptions())
	_, stop := attachUntilActive(t, first, newHost(), remote)
	first.Manager().SetMode(remote, ModeHidden)
	stop()

	prefs := first.ViewPrefs()
	prefs.ShowHidden = true
	first.SetViewPrefs(prefs)

	// A different Service over the same config is the next run of devtun.
	second := New(DefaultOptions())
	host := newHost()
	inst, err := second.Attach(context.Background(), host)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); inst.Close() })
	go func() { _ = inst.Run(ctx) }()

	waitUntil(t, func() bool { return len(second.Manager().States()) > 0 }, "the port to be discovered")
	if st := stateFor(t, second.Manager(), remote); st.Mode != ModeHidden || st.Status == StatusActive {
		t.Errorf("port = %q/%q on the next run, want the remembered hide", st.Mode, st.Status)
	}
	if !second.ViewPrefs().ShowHidden {
		t.Error("the view preference was not remembered")
	}
}

// attachUntilActive attaches svc to host and runs it until the port is
// forwarded, returning the local port and a function that tears the connection
// down. Calling stop and then attaching again is precisely a reconnect.
func attachUntilActive(t *testing.T, svc *Service, host service.Host, remote int) (int, func()) {
	t.Helper()
	inst, err := svc.Attach(context.Background(), host)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- inst.Run(ctx) }()

	waitUntil(t, func() bool {
		for _, st := range svc.Manager().States() {
			if st.RemotePort == remote && st.Status == StatusActive {
				return true
			}
		}
		return false
	}, fmt.Sprintf("remote %d to be forwarded", remote))

	local := stateFor(t, svc.Manager(), remote).LocalPort

	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				// A cancelled run is an orderly stop, not something to
				// reconnect over.
				if err != nil {
					t.Errorf("Run() = %v, want nil after cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("Run did not return after cancellation")
			}
			if err := inst.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	return local, stop
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
