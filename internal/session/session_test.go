package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

// --- fakes ---------------------------------------------------------------

type fakeConn struct {
	probe string
	// fail, when closed, makes KeepAlive return and so ends the connection.
	fail     chan error
	listener net.Listener
	closed   atomic.Bool
	uploads  atomic.Int32
}

func newFakeConn(t *testing.T) *fakeConn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &fakeConn{probe: goodProbe, fail: make(chan error, 1), listener: l}
}

func (c *fakeConn) Run(context.Context, string, io.Writer) error { return nil }

func (c *fakeConn) Output(_ context.Context, script string) (string, error) {
	switch {
	case contains(script, markBasics):
		return c.probe, nil
	case contains(script, "--devtun-shim"):
		return "devtun-shim test\n", nil
	default:
		return "ok\n", nil
	}
}

func (c *fakeConn) Upload(context.Context, string, string, os.FileMode) error {
	c.uploads.Add(1)
	return nil
}
func (c *fakeConn) DialTCP(context.Context, string) (net.Conn, error) { return nil, errors.New("no") }
func (c *fakeConn) ListenSocket(context.Context, string) (net.Listener, error) {
	return c.listener, nil
}
func (c *fakeConn) RemoveSocket(context.Context, string) {}
func (c *fakeConn) KeepAlive(ctx context.Context, _, _ time.Duration) error {
	select {
	case err := <-c.fail:
		return err
	case <-ctx.Done():
		return nil
	}
}
func (c *fakeConn) Close() error {
	c.closed.Store(true)
	_ = c.listener.Close()
	return nil
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

type fakeConnector struct {
	mu       sync.Mutex
	conns    []*fakeConn
	attempts int
	t        *testing.T
	err      error
}

func (f *fakeConnector) Connect(context.Context) (Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.err != nil {
		return nil, f.err
	}
	c := newFakeConn(f.t)
	f.conns = append(f.conns, c)
	return c, nil
}
func (f *fakeConnector) Label() string    { return "bedev" }
func (f *fakeConnector) Describe() string { return "jsc@bedev" }

func (f *fakeConnector) last() *fakeConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.conns) == 0 {
		return nil
	}
	return f.conns[len(f.conns)-1]
}

func (f *fakeConnector) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.conns)
}

// tries counts every attempt, successful or not — which is what a test about
// retrying needs, and what count() cannot tell it.
func (f *fakeConnector) tries() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

// countingService records how many times it was attached and closed, and keeps
// state on the Service to prove it survives a reconnect.
type countingService struct {
	id        string
	supported bool
	attaches  atomic.Int32
	closes    atomic.Int32
	// generation is service-level state; it must not reset on a reconnect.
	generation atomic.Int32
}

func (s *countingService) Meta() service.Meta {
	return service.Meta{ID: s.id, Title: s.id, Class: event.Network}
}

func (s *countingService) Probe(context.Context, service.Host) service.Support {
	if !s.supported {
		return service.Unsupported("not on this box")
	}
	return service.Supported()
}

func (s *countingService) Attach(context.Context, service.Host) (service.Instance, error) {
	s.attaches.Add(1)
	s.generation.Add(1)
	return &countingInstance{owner: s}, nil
}

type countingInstance struct{ owner *countingService }

func (i *countingInstance) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (i *countingInstance) Close() error                  { i.owner.closes.Add(1); return nil }

type fakeConfig struct {
	mu       sync.Mutex
	disabled map[string]bool
	docs     map[string]any
}

func newFakeConfig() *fakeConfig {
	return &fakeConfig{disabled: map[string]bool{}, docs: map[string]any{}}
}
func (c *fakeConfig) Enabled(_, id string, fallback bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled[id] {
		return false
	}
	return fallback
}
func (c *fakeConfig) Section(_, id string) service.Config { return &fakeSection{cfg: c, id: id} }

type fakeSection struct {
	cfg *fakeConfig
	id  string
}

func (s *fakeSection) Get(string, any) (bool, error) { return false, nil }

// GetLocal behaves as Get here: this fake holds no shared layer for a local
// read to differ from.
func (s *fakeSection) GetLocal(key string, v any) (bool, error) { return s.Get(key, v) }
func (s *fakeSection) Set(key string, v any) error {
	s.cfg.mu.Lock()
	defer s.cfg.mu.Unlock()
	s.cfg.docs[s.id+"."+key] = v
	return nil
}

func testSession(t *testing.T, services ...service.Service) (*Session, *fakeConnector, *event.Bus) {
	t.Helper()
	connector := &fakeConnector{t: t}
	bus := event.NewBus(64)
	s := New(Options{
		Connector: connector,
		Bus:       bus,
		Services:  services,
		Config:    newFakeConfig(),
		Reconnect: true,
		Version:   "test",
		Setup:     SetupNever,
	})
	return s, connector, bus
}

// --- tests ---------------------------------------------------------------

func TestServicesAttachOnConnect(t *testing.T) {
	svc := &countingService{id: "tunnels", supported: true}
	s, connector, _ := testSession(t, svc)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, func() bool { return svc.attaches.Load() == 1 })
	if s.Status().State != Connected {
		t.Errorf("want connected, got %q", s.Status().State)
	}

	cancel()
	<-done
	if svc.closes.Load() != 1 {
		t.Errorf("want the instance closed exactly once, got %d", svc.closes.Load())
	}
	if c := connector.last(); c == nil || !c.closed.Load() {
		t.Error("the connection should be closed on shutdown")
	}
}

// A dev box without the 1Password CLI is an ordinary dev box. Refusing to
// forward ports because of it would be absurd.
func TestUnsupportedServiceIsSkippedNotFatal(t *testing.T) {
	ok := &countingService{id: "tunnels", supported: true}
	nope := &countingService{id: "1password", supported: false}
	s, _, bus := testSession(t, ok, nope)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	waitFor(t, func() bool { return ok.attaches.Load() == 1 })
	if nope.attaches.Load() != 0 {
		t.Error("an unsupported service must not be attached")
	}
	waitFor(t, func() bool {
		for _, e := range bus.History() {
			if e.Kind == "unavailable" && e.Service == "1password" {
				return true
			}
		}
		return false
	})
}

func TestDisabledServiceIsNotProbed(t *testing.T) {
	svc := &countingService{id: "browser", supported: true}
	connector := &fakeConnector{t: t}
	cfg := newFakeConfig()
	cfg.disabled["browser"] = true

	s := New(Options{
		Connector: connector, Bus: event.NewBus(16), Services: []service.Service{svc},
		Config: cfg, Reconnect: true, Version: "test", Setup: SetupNever,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	waitFor(t, func() bool { return connector.count() == 1 })
	time.Sleep(100 * time.Millisecond)
	if svc.attaches.Load() != 0 {
		t.Error("a disabled service must not be attached")
	}
}

// The core invariant: a reconnect is Close followed by a fresh Attach, and
// state kept on the Service survives it.
func TestReconnectClosesAndReattachesWithoutLosingServiceState(t *testing.T) {
	svc := &countingService{id: "tunnels", supported: true}
	s, connector, _ := testSession(t, svc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	waitFor(t, func() bool { return svc.attaches.Load() == 1 })

	// Drop the link the way a closed lid does.
	connector.last().fail <- errors.New("connection reset")

	waitFor(t, func() bool { return svc.attaches.Load() == 2 })
	if svc.closes.Load() != 1 {
		t.Errorf("the first instance should have been closed once, got %d", svc.closes.Load())
	}
	if connector.count() != 2 {
		t.Errorf("want a second connection, got %d", connector.count())
	}
	// The generation counter lives on the Service, so it accumulates rather
	// than resetting — which is what makes grants and port assignments
	// survive a reconnect.
	if svc.generation.Load() != 2 {
		t.Errorf("service state did not survive the reconnect: generation %d", svc.generation.Load())
	}
}

func TestReconnectDisabledMakesADropFatal(t *testing.T) {
	svc := &countingService{id: "tunnels", supported: true}
	connector := &fakeConnector{t: t}
	s := New(Options{
		Connector: connector, Bus: event.NewBus(16), Services: []service.Service{svc},
		Config: newFakeConfig(), Reconnect: false, Version: "test", Setup: SetupNever,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, func() bool { return svc.attaches.Load() == 1 })
	want := errors.New("connection reset")
	connector.last().fail <- want

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want the drop reported as an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
	if svc.attaches.Load() != 1 {
		t.Error("it must not reconnect when told not to")
	}
}

func TestConnectFailureBacksOffAndKeepsTrying(t *testing.T) {
	connector := &fakeConnector{t: t, err: errors.New("no route to host")}
	bus := event.NewBus(16)
	s := New(Options{
		Connector: connector, Bus: bus, Config: newFakeConfig(),
		Reconnect: true, Version: "test", Setup: SetupNever,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	waitFor(t, func() bool {
		for _, e := range bus.History() {
			if e.Kind == "connect-failed" {
				return true
			}
		}
		return false
	})
	if got := s.Status().State; got != Disconnected {
		t.Errorf("want disconnected, got %q", got)
	}
	// RetryNow must not deadlock when called repeatedly.
	s.RetryNow()
	s.RetryNow()
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	d := minReconnectDelay
	for i := 0; i < 20; i++ {
		d = nextDelay(d)
	}
	if d != maxReconnectDelay {
		t.Errorf("backoff should cap at %s, got %s", maxReconnectDelay, d)
	}
}

func TestOnPath(t *testing.T) {
	if !onPath("/usr/bin:/home/jsc/.devtun/bin:/bin", "/home/jsc/.devtun/bin") {
		t.Error("an exact entry should count")
	}
	if !onPath("/home/jsc/.devtun/bin/", "/home/jsc/.devtun/bin") {
		t.Error("a trailing slash should not matter")
	}
	if onPath("/usr/bin:/home/jsc/.devtun/binaries", "/home/jsc/.devtun/bin") {
		t.Error("a prefix match must not count")
	}
	if onPath("", "/home/jsc/.devtun/bin") {
		t.Error("an empty PATH cannot contain anything")
	}
}

// Retrying a permanent refusal every thirty seconds looks exactly like a hang,
// and the message that explained it scrolled away long ago.
func TestPermanentRefusalStopsInsteadOfRetrying(t *testing.T) {
	connector := &fakeConnector{
		t:   t,
		err: errors.New("publishing the socket: ssh: tcpip-forward request denied by peer; check AllowStreamLocalForwarding"),
	}
	bus := event.NewBus(16)
	s := New(Options{
		Connector: connector, Bus: bus, Config: newFakeConfig(),
		Reconnect: true, Version: "test", Setup: SetupNever,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a permanent refusal should be reported, not swallowed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session kept retrying a refusal it will never get past")
	}
	if got := connector.tries(); got > 1 {
		t.Errorf("want a single attempt against a permanent refusal, got %d", got)
	}
}

// The cost of wrongly calling a transient failure fatal is a session that gives
// up on a box that was about to come back, so ordinary network errors must
// keep retrying.
func TestOrdinaryFailuresKeepRetrying(t *testing.T) {
	connector := &fakeConnector{t: t, err: errors.New("dial tcp 10.0.0.9:22: connect: network is unreachable")}
	s := New(Options{
		Connector: connector, Bus: event.NewBus(16), Config: newFakeConfig(),
		Reconnect: true, Version: "test", Setup: SetupNever,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	waitFor(t, func() bool { return connector.tries() >= 2 })
}

func TestFatalWrapsAndUnwraps(t *testing.T) {
	inner := errors.New("forwarding is off")
	err := Fatal(inner)

	if !isFatal(err) {
		t.Error("an explicitly fatal error should be recognised")
	}
	if !errors.Is(err, inner) {
		t.Error("the cause must stay reachable through errors.Is")
	}
	if Fatal(nil) != nil {
		t.Error("wrapping nil should stay nil")
	}
	if isFatal(errors.New("connection reset by peer")) {
		t.Error("an ordinary network error must not be fatal")
	}
}

// The contract says Close is called after Run has returned. Until the
// supervisor joined the service goroutines it simply was not: a Run still
// unwinding could put a dead dialer back on a manager Close had just cleared,
// and the next connection would leave its forwarders pointed at an SSH
// connection that no longer existed.
func TestCloseHappensAfterRunReturns(t *testing.T) {
	svc := &orderedService{id: "tunnels", started: make(chan struct{})}
	connector := &fakeConnector{t: t}
	s := New(Options{
		Connector: connector, Bus: event.NewBus(16), Services: []service.Service{svc},
		Config: newFakeConfig(), Reconnect: false, Version: "test", Setup: SetupNever,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	<-svc.started
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if !svc.closedAfterRun.Load() {
		t.Error("Close was called while Run was still running")
	}
}

// orderedService records whether Close saw Run already finished.
type orderedService struct {
	id             string
	started        chan struct{}
	running        atomic.Bool
	closedAfterRun atomic.Bool
	once           sync.Once
}

func (s *orderedService) Meta() service.Meta {
	return service.Meta{ID: s.id, Title: s.id, Class: event.Network}
}
func (s *orderedService) Probe(context.Context, service.Host) service.Support {
	return service.Supported()
}
func (s *orderedService) Attach(context.Context, service.Host) (service.Instance, error) {
	return &orderedInstance{owner: s}, nil
}

type orderedInstance struct{ owner *orderedService }

func (i *orderedInstance) Run(ctx context.Context) error {
	i.owner.running.Store(true)
	i.owner.once.Do(func() { close(i.owner.started) })
	<-ctx.Done()
	// Unwind slowly, the way a real service tearing down forwarders does.
	time.Sleep(50 * time.Millisecond)
	i.owner.running.Store(false)
	return nil
}

func (i *orderedInstance) Close() error {
	i.owner.closedAfterRun.Store(!i.owner.running.Load())
	return nil
}
