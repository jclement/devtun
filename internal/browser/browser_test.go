package browser

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/tunnels"
)

type fakeTunnels struct {
	mu       sync.Mutex
	states   []tunnels.State
	forwards []int
	tries    []int
	// appearOnForward makes ForwardNow publish the tunnel, as the real
	// manager does a moment later.
	appearOnForward *tunnels.State
	tryErr          error
}

func (f *fakeTunnels) States() []tunnels.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tunnels.State(nil), f.states...)
}

func (f *fakeTunnels) ForwardNow(remotePort int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forwards = append(f.forwards, remotePort)
	if f.appearOnForward != nil {
		f.states = append(f.states, *f.appearOnForward)
	}
	return nil
}

func (f *fakeTunnels) TryLocalPort(remotePort, local int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries = append(f.tries, local)
	return f.tryErr
}

func newService(tn Tunnels) *Service {
	return New(Options{
		Prompter: allowOnce{},
		Tunnels:  tn,
		Open:     func(context.Context, string) error { return nil },
		Poll:     time.Millisecond,
		Wait:     50 * time.Millisecond,
	})
}

func TestLoopbackURLIsRewrittenToTheLocalPort(t *testing.T) {
	tn := &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174, Remapped: true}}}
	tn.tryErr = context.Canceled // the original port is busy, so keep the remap

	got, err := newService(tn).localize(context.Background(), "http://localhost:5173/")
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if got != "http://localhost:5174/" {
		t.Errorf("want the remapped port, got %q", got)
	}
}

// A login callback on a moved port is a broken redirect, so the matching
// number is reclaimed when nothing else holds it.
func TestRemappedPortIsReclaimedWhenFree(t *testing.T) {
	tn := &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174, Remapped: true}}}

	got, err := newService(tn).localize(context.Background(), "http://127.0.0.1:5173/callback")
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if got != "http://localhost:5173/callback" {
		t.Errorf("want the original port reclaimed, got %q", got)
	}
	if len(tn.tries) != 1 || tn.tries[0] != 5173 {
		t.Errorf("want one attempt to reclaim 5173, got %v", tn.tries)
	}
}

// An OAuth consent screen is not on the dev box and must pass through
// untouched.
func TestPublicURLPassesThroughUnchanged(t *testing.T) {
	tn := &fakeTunnels{}
	const want = "https://github.com/login/oauth/authorize?client_id=x"

	got, err := newService(tn).localize(context.Background(), want)
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if got != want {
		t.Errorf("want %q unchanged, got %q", want, got)
	}
	if len(tn.forwards) != 0 {
		t.Error("a public URL should not ask for a tunnel")
	}
}

// Opening the wrong service is far worse than opening nothing, because it
// looks like it worked.
func TestUnforwardedLoopbackPortIsRefused(t *testing.T) {
	_, err := newService(&fakeTunnels{}).localize(context.Background(), "http://localhost:9999/")
	if err == nil {
		t.Fatal("an unforwarded loopback port must be refused")
	}
	if !strings.Contains(err.Error(), "9999") {
		t.Errorf("the refusal should name the port, got %v", err)
	}
}

// Naming a port is more specific than a filter the user set in general.
func TestSkippedPortIsForwardedOnDemand(t *testing.T) {
	tn := &fakeTunnels{
		states:          []tunnels.State{{RemotePort: 3000, LocalPort: 0}},
		appearOnForward: &tunnels.State{RemotePort: 3000, LocalPort: 3000},
	}

	got, err := newService(tn).localize(context.Background(), "http://localhost:3000/")
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if got != "http://localhost:3000/" {
		t.Errorf("unexpected URL %q", got)
	}
	if len(tn.forwards) != 1 {
		t.Errorf("want exactly one forward request, got %v", tn.forwards)
	}
}

// A refusal must not become a busy loop.
func TestForwardIsRequestedOnlyOnce(t *testing.T) {
	tn := &fakeTunnels{states: []tunnels.State{{RemotePort: 3000, LocalPort: 0}}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _ = newService(tn).localize(ctx, "http://localhost:3000/")

	tn.mu.Lock()
	defer tn.mu.Unlock()
	if len(tn.forwards) != 1 {
		t.Errorf("want one forward request however long we wait, got %d", len(tn.forwards))
	}
}

func TestNonHTTPSchemesAreRefused(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "ssh://box", "javascript:alert(1)"} {
		if _, err := newService(&fakeTunnels{}).localize(context.Background(), raw); err == nil {
			t.Errorf("%q should be refused", raw)
		}
	}
}

func TestSchemeDefaultPorts(t *testing.T) {
	tn := &fakeTunnels{states: []tunnels.State{{RemotePort: 443, LocalPort: 8443}}}
	got, err := newService(tn).localize(context.Background(), "https://localhost/app")
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if got != "https://localhost:8443/app" {
		t.Errorf("https with no port should mean 443, got %q", got)
	}
}

func TestProbeNeedsAWayToOpen(t *testing.T) {
	if New(Options{}).Probe(context.Background(), nil).OK {
		t.Error("with no opener the service cannot work")
	}
	if !newService(&fakeTunnels{}).Probe(context.Background(), nil).OK {
		t.Error("with an opener it can")
	}
}

// allowOnce approves whatever it is asked, so that the tests about rewriting
// URLs are not also tests of the gate. The gate has its own below.
type allowOnce struct{}

func (allowOnce) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	return prompt.ChoiceAllowOnce, nil
}
