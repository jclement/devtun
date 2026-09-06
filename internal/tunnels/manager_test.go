package tunnels

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/tunnels/probe"
)

// echoServer is a stand-in for a remote dev server: it upper-cases whatever it
// is sent, so tests can prove bytes went through the tunnel in both directions.
type echoServer struct {
	ln net.Listener
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting echo server: %v", err)
	}
	e := &echoServer{ln: ln}
	go e.serve()
	t.Cleanup(func() { ln.Close() })
	return e
}

func (e *echoServer) serve() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte(strings.ToUpper(string(buf[:n]))))
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

func (e *echoServer) addr() string { return e.ln.Addr().String() }

// fixedDialer routes every dial to one address, standing in for the SSH
// transport, and records what it was asked for.
type fixedDialer struct {
	addr string

	mu     sync.Mutex
	dialed []string
	err    error
}

func (d *fixedDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	err := d.err
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return net.Dial("tcp", d.addr)
}

func (d *fixedDialer) lastDial() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.dialed) == 0 {
		return ""
	}
	return d.dialed[len(d.dialed)-1]
}

func (d *fixedDialer) setErr(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
}

// collector accumulates the events the manager emits.
type collector struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *collector) Emit(e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

// all returns a snapshot of what was emitted, taken under the same lock as the
// append because the manager emits from whichever goroutine synced.
func (c *collector) all() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.events...)
}

func (c *collector) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.events))
	for i, e := range c.events {
		out[i] = e.Kind
	}
	return out
}

func (c *collector) last() event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return event.Event{}
	}
	return c.events[len(c.events)-1]
}

func (c *collector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = nil
}

// snapshotOf builds a probe snapshot for the given ports.
func snapshotOf(ports ...int) probe.Snapshot {
	s := probe.Snapshot{}
	for i, p := range ports {
		s[p] = probe.Service{
			Port:  p,
			Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}},
			PID:   1000 + i,
			Proc:  "node",
		}
	}
	return s
}

// newTestManager wires a manager to an echo server through a fixed dialer.
func newTestManager(t *testing.T, policy Policy) (*Manager, *fixedDialer, *collector) {
	t.Helper()
	echo := newEchoServer(t)
	d := &fixedDialer{addr: echo.addr()}
	c := &collector{}
	m := NewManager(NewAllocator("127.0.0.1", false), d, ManagerOptions{
		Policy: policy,
		Events: c,
	})
	t.Cleanup(m.Close)
	return m, d, c
}

// stateFor returns the manager's row for a remote port.
func stateFor(t *testing.T, m *Manager, port int) State {
	t.Helper()
	for _, s := range m.States() {
		if s.RemotePort == port {
			return s
		}
	}
	t.Fatalf("no state for remote port %d", port)
	return State{}
}

// roundTrip sends a line through a local tunnel port and returns the reply.
func roundTrip(t *testing.T, port int, msg string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("dialing local tunnel port %d: %v", port, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("writing: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading: %v", err)
	}
	return string(buf)
}

func TestManagerForwardsANewService(t *testing.T) {
	m, dialer, events := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))

	st := stateFor(t, m, port)
	if st.Status != StatusActive {
		t.Fatalf("status = %q, want active (skip: %q, err: %q)", st.Status, st.Skip, st.Err)
	}
	if st.LocalPort != port {
		t.Errorf("local port = %d, want the matching %d", st.LocalPort, port)
	}
	if st.Remapped {
		t.Error("a free port should not be marked remapped")
	}

	if got := roundTrip(t, st.LocalPort, "hello"); got != "HELLO" {
		t.Errorf("round trip = %q, want %q", got, "HELLO")
	}
	if want := fmt.Sprintf("127.0.0.1:%d", port); dialer.lastDial() != want {
		t.Errorf("dialed %q, want %q", dialer.lastDial(), want)
	}

	// Counters only settle once the connection has been torn down.
	waitUntil(t, func() bool {
		s := stateFor(t, m, port)
		return s.BytesIn == 5 && s.BytesOut == 5
	}, "byte counters to reach 5 each")

	st = stateFor(t, m, port)
	if st.TotalConns != 1 {
		t.Errorf("total connections = %d, want 1", st.TotalConns)
	}
	if kinds := events.kinds(); len(kinds) != 1 || kinds[0] != KindOpened {
		t.Errorf("events = %v, want one opened", kinds)
	}
	if got := events.last().Class; got != event.Network {
		t.Errorf("event class = %q, want network", got)
	}
}

func TestManagerClosesTunnelsAfterTheGracePeriod(t *testing.T) {
	m, _, events := newTestManager(t, DefaultPolicy())

	a, b := freePort(t), freePort(t)
	m.Sync(snapshotOf(a, b))
	m.Sync(snapshotOf(a, b, freePort(t)))
	events.reset()

	// One missed scan is tolerated, since a single dropped scan should not
	// tear down working tunnels.
	m.Sync(snapshotOf(a, b))
	if len(m.States()) != 3 {
		t.Errorf("after one miss there are %d rows, want 3", len(m.States()))
	}

	// The second consecutive miss removes it.
	m.Sync(snapshotOf(a, b))
	if len(m.States()) != 2 {
		t.Errorf("after two misses there are %d rows, want 2", len(m.States()))
	}
	if kinds := events.kinds(); len(kinds) != 1 || kinds[0] != KindClosed {
		t.Errorf("events = %v, want one closed", kinds)
	}
}

func TestManagerReleasesTheLocalPortOnTeardown(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	local := stateFor(t, m, port).LocalPort

	m.Sync(probe.Snapshot{})
	m.Sync(probe.Snapshot{})

	waitUntil(t, func() bool {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", local))
		if err != nil {
			return false
		}
		ln.Close()
		return true
	}, "the local port to be released")
}

func TestManagerCycleModeAttachesAndDetaches(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Fatalf("status = %q, want active before any decision", st.Status)
	}

	// auto → on: already forwarding, now unconditionally.
	if got := m.CycleMode(port); got != ModeOn {
		t.Fatalf("first cycle = %q, want on", got)
	}
	st := stateFor(t, m, port)
	if st.Status != StatusActive || st.Mode != ModeOn {
		t.Fatalf("after on: status %q mode %q, want active/on", st.Status, st.Mode)
	}
	if got := roundTrip(t, st.LocalPort, "up"); got != "UP" {
		t.Errorf("round trip = %q, want UP", got)
	}

	// on → hidden: the tunnel closes and the row leaves the table.
	if got := m.CycleMode(port); got != ModeHidden {
		t.Fatalf("second cycle = %q, want hidden", got)
	}
	for _, st := range m.States() {
		if st.RemotePort == port {
			t.Fatalf("a hidden port is still listed: %+v", st)
		}
	}
	m.SetShowHidden(true)
	if st := stateFor(t, m, port); st.Status == StatusActive || st.Skip != SkipHidden {
		t.Errorf("hidden port = %q/%q, want skipped/hidden", st.Status, st.Skip)
	}

	// A standing decision must survive later scans.
	m.Sync(snapshotOf(port))
	if st := stateFor(t, m, port); st.Status == StatusActive {
		t.Error("a hidden port should stay hidden across scans")
	}

	// And a third cycle returns to following the policy.
	if got := m.CycleMode(port); got != ModeAuto {
		t.Fatalf("third cycle = %q, want auto", got)
	}
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Errorf("back on auto the policy forwards again, got %q", st.Status)
	}
}

func TestManagerCycleModeUnknownPortIsANoop(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())
	if got := m.CycleMode(9999); got != ModeAuto {
		t.Errorf("cycling an unknown port = %q, want auto", got)
	}
}

func TestManagerSetLocalPort(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	remote, pinned := freePort(t), freePort(t)
	m.Sync(snapshotOf(remote))

	if err := m.SetLocalPort(remote, pinned); err != nil {
		t.Fatalf("SetLocalPort: %v", err)
	}
	st := stateFor(t, m, remote)
	if st.LocalPort != pinned {
		t.Errorf("local port = %d, want the pinned %d", st.LocalPort, pinned)
	}
	if st.PinnedLocal != pinned {
		t.Errorf("PinnedLocal = %d, want %d", st.PinnedLocal, pinned)
	}
	if got := roundTrip(t, pinned, "hi"); got != "HI" {
		t.Errorf("round trip on the pinned port = %q, want HI", got)
	}

	// Zero restores the default of mirroring the remote port.
	if err := m.SetLocalPort(remote, 0); err != nil {
		t.Fatalf("SetLocalPort(0): %v", err)
	}
	if st := stateFor(t, m, remote); st.LocalPort != remote {
		t.Errorf("local port = %d, want back to %d", st.LocalPort, remote)
	}
}

func TestManagerSetLocalPortRejectsBadInput(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())
	port := freePort(t)
	m.Sync(snapshotOf(port))

	if err := m.SetLocalPort(port, 70000); err == nil {
		t.Error("an out-of-range port should be rejected")
	}
	if err := m.SetLocalPort(9999, 3000); err == nil {
		t.Error("pinning an unlisted port should be rejected")
	}
}

func TestManagerSetLabelIsRemembered(t *testing.T) {
	echo := newEchoServer(t)
	store := NewStore(newFakeConfig())
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy: DefaultPolicy(), Settings: store,
	})
	defer m.Close()
	port := freePort(t)
	m.Sync(snapshotOf(port))

	if err := m.SetLabel(port, "  front   end  "); err != nil {
		t.Fatal(err)
	}
	if got := stateFor(t, m, port).Label; got != "front end" {
		t.Errorf("label = %q, want normalized label", got)
	}
	if got := store.Port(port).Label; got != "front end" {
		t.Errorf("remembered label = %q", got)
	}
	if err := m.SetLabel(port, ""); err != nil {
		t.Fatal(err)
	}
	if got := store.Port(port).Label; got != "" {
		t.Errorf("cleared label remained %q", got)
	}
}

func TestManagerSetPolicyReevaluatesEverything(t *testing.T) {
	p := DefaultPolicy()
	p.MinPort = 65000 // nothing an ephemeral port can clear
	m, dialer, _ := newTestManager(t, p)

	port := freePort(t)
	m.Sync(snapshotOf(port))
	if st := len(m.States()); st != 0 {
		t.Fatalf("expected the out-of-window service to be filtered out, got %d rows", st)
	}

	p.MinPort = 1024
	m.SetPolicy(p)

	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Errorf("status = %q, want active once the window admits it", st.Status)
	}

	// Pausing leaves current automatic tunnels alone.
	p.Paused = true
	m.SetPolicy(p)
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Errorf("pausing closed an existing tunnel: %q", st.Status)
	}
	m.SetDialer(nil)
	if st := stateFor(t, m, port); st.Status != StatusOffline {
		t.Errorf("paused tunnel during outage = %q, want offline", st.Status)
	}
	m.SetDialer(dialer)
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Errorf("paused tunnel after reconnect = %q, want active", st.Status)
	}

	// But an automatic service that appears while paused waits.
	newPort := freePort(t)
	m.Sync(snapshotOf(port, newPort))
	if st := stateFor(t, m, newPort); st.Status != StatusSkipped || st.Skip != SkipPaused {
		t.Errorf("new service while paused = %q/%q, want skipped/paused", st.Status, st.Skip)
	}

	// Resuming opens what arrived during the pause.
	p.Paused = false
	m.SetPolicy(p)
	if st := stateFor(t, m, newPort); st.Status != StatusActive {
		t.Errorf("waiting service after resume = %q, want active", st.Status)
	}
}

func TestManagerExcludeClosesAnOpenTunnel(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Fatalf("status = %q, want active", st.Status)
	}

	p := m.Policy()
	p.Exclude, _ = ParsePortSet(fmt.Sprint(port))
	m.SetPolicy(p)

	// Excluding a port closes its tunnel and takes the row away entirely:
	// having explicitly excluded it, the user is not deciding about it.
	for _, st := range m.States() {
		if st.RemotePort == port {
			t.Fatalf("an excluded port is still listed: %+v", st)
		}
	}
	waitUntil(t, func() bool {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		ln.Close()
		return true
	}, "the excluded port's listener to be released")
}

// Services ruled out by configuration are noise, not decisions: they never
// reach the table.
func TestManagerHidesConfigurationFilteredServices(t *testing.T) {
	p := DefaultPolicy()
	p.MinPort = 1024
	m, _, _ := newTestManager(t, p)

	fresh := freePort(t)
	snap := snapshotOf(fresh)
	// sshd on 22 is below the port window.
	snap[22] = probe.Service{Port: 22, Binds: []probe.Bind{{Proto: "tcp", Addr: "0.0.0.0"}}, Proc: "sshd"}
	m.Sync(snap)

	for _, st := range m.States() {
		if st.RemotePort == 22 {
			t.Errorf("a port below --min-port was listed: %+v", st)
		}
	}
	if st := stateFor(t, m, fresh); st.Status != StatusActive {
		t.Errorf("new service = %q, want active", st.Status)
	}
}

func TestSkipFiltered(t *testing.T) {
	filtered := []Skip{SkipBelowMin, SkipAboveMax, SkipExcluded, SkipNotInclude, SkipNotLoop}
	shown := []Skip{SkipNone, SkipPaused, Skip("detached")}

	for _, s := range filtered {
		if !s.Filtered() {
			t.Errorf("%q should be filtered out of the table", s)
		}
	}
	for _, s := range shown {
		if s.Filtered() {
			t.Errorf("%q should stay visible", s)
		}
	}
	// Hiding takes the row away too, but through the view preference, so that
	// unhiding is possible at all.
	if SkipHidden.Filtered() {
		t.Error("SkipHidden must not be unconditionally filtered")
	}
}

func TestManagerReportsAllocationFailure(t *testing.T) {
	echo := newEchoServer(t)
	c := &collector{}
	alloc := NewAllocator("127.0.0.1", true) // --same-port
	m := NewManager(alloc, &fixedDialer{addr: echo.addr()}, ManagerOptions{Policy: DefaultPolicy(), Events: c})
	defer m.Close()

	busy := occupy(t)
	m.Sync(snapshotOf(busy))

	st := stateFor(t, m, busy)
	if st.Status != StatusError {
		t.Fatalf("status = %q, want error", st.Status)
	}
	if !strings.Contains(st.Err, "already in use") {
		t.Errorf("error = %q, want a port conflict message", st.Err)
	}
	if kinds := c.kinds(); len(kinds) != 1 || kinds[0] != KindFailed {
		t.Errorf("events = %v, want one failed", kinds)
	}
	if got := c.last().Level; got != event.Error {
		t.Errorf("failure level = %v, want error", got)
	}

	// A repeated failure must not re-emit the same event on every scan.
	c.reset()
	m.Sync(snapshotOf(busy))
	if kinds := c.kinds(); len(kinds) != 0 {
		t.Errorf("events = %v, want the repeated failure to be suppressed", kinds)
	}
}

func TestManagerReconnectReusesTheSameLocalPort(t *testing.T) {
	m, dialer, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	original := stateFor(t, m, port).LocalPort

	// The link drops.
	m.SetDialer(nil)
	if st := stateFor(t, m, port); st.Status == StatusActive {
		t.Error("tunnels should close when the transport goes away")
	}

	// And comes back.
	m.SetDialer(dialer)
	st := stateFor(t, m, port)
	if st.Status != StatusActive {
		t.Fatalf("status = %q, want active after reconnect", st.Status)
	}
	if st.LocalPort != original {
		t.Errorf("local port = %d after reconnect, want the original %d", st.LocalPort, original)
	}
	if got := roundTrip(t, st.LocalPort, "back"); got != "BACK" {
		t.Errorf("round trip = %q, want BACK", got)
	}
}

func TestManagerSurvivesADialFailure(t *testing.T) {
	m, dialer, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	local := stateFor(t, m, port).LocalPort

	dialer.setErr(errors.New("channel refused"))

	// The local listener still accepts; the connection just fails fast.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", local), 3*time.Second)
	if err != nil {
		t.Fatalf("local listener should stay up: %v", err)
	}
	_, _ = io.WriteString(conn, "x")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Logf("read after failed dial: %v", err)
	}
	conn.Close()

	waitUntil(t, func() bool {
		return strings.Contains(stateFor(t, m, port).Err, "channel refused")
	}, "the dial error to surface on the row")

	// Recovery: once dialing works again, the same tunnel serves traffic.
	dialer.setErr(nil)
	if got := roundTrip(t, local, "ok"); got != "OK" {
		t.Errorf("round trip after recovery = %q, want OK", got)
	}
}

func TestManagerCounts(t *testing.T) {
	p := DefaultPolicy()
	p.Paused = true
	m, _, _ := newTestManager(t, p)

	paused := freePort(t)
	m.Sync(snapshotOf(paused))

	p.Paused = false
	m.SetPolicy(p)
	fresh := freePort(t)
	m.Sync(snapshotOf(paused, fresh))
	m.SetMode(paused, ModeHidden)
	m.SetShowHidden(true)

	active, skipped, failed := m.Counts()
	if active != 1 || skipped != 1 || failed != 0 {
		t.Errorf("Counts() = %d/%d/%d, want 1 active, 1 skipped, 0 failed", active, skipped, failed)
	}
}

func TestManagerStatesAreSortedByRemotePort(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())
	m.Sync(probe.Snapshot{
		9000: {Port: 9000},
		3000: {Port: 3000},
		5000: {Port: 5000},
	})
	got := m.States()
	if len(got) != 3 || got[0].RemotePort != 3000 || got[1].RemotePort != 5000 || got[2].RemotePort != 9000 {
		t.Errorf("States() out of order: %+v", got)
	}
}

func TestManagerKeepsResolvedCommandLines(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	withCmd := probe.Snapshot{port: {Port: port, PID: 42, Proc: "node", Cmd: "node /app/server.js"}}
	m.Sync(withCmd)

	// A later scan that has not resolved the command line yet must not blank
	// out what we already know.
	m.Sync(probe.Snapshot{port: {Port: port, PID: 42, Proc: "node"}})
	if got := stateFor(t, m, port).Cmd; got != "node /app/server.js" {
		t.Errorf("command = %q, want the previously resolved one", got)
	}
}

func TestStateURL(t *testing.T) {
	tests := []struct {
		name string
		st   State
		want string
	}{
		{"active unknown has no URL", State{Status: StatusActive, LocalAddr: "127.0.0.1", LocalPort: 3000}, ""},
		{"active HTTP", State{Status: StatusActive, LocalAddr: "127.0.0.1", LocalPort: 3000, Scheme: SchemeHTTP}, "http://127.0.0.1:3000"},
		{"wildcard becomes localhost", State{Status: StatusActive, LocalAddr: "0.0.0.0", LocalPort: 3000, Scheme: SchemeHTTP}, "http://localhost:3000"},
		{"skipped has no URL", State{Status: StatusSkipped, LocalPort: 3000}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.st.URL(); got != tt.want {
				t.Errorf("URL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The Kind strings are what `--json` consumers match on, and the remap marker
// is the one detail a reader must not miss.
func TestEventText(t *testing.T) {
	at := time.Unix(0, 0)
	st := State{RemotePort: 3000, LocalPort: 3000, LocalAddr: "127.0.0.1", Cmd: "node"}
	remapped := State{RemotePort: 3000, LocalPort: 3001, LocalAddr: "127.0.0.1", Remapped: true, Cmd: "node"}

	tests := []struct {
		e    event.Event
		kind string
		want string
	}{
		{openedEvent(at, st), "opened", "remote 3000 → 127.0.0.1:3000 (node)"},
		{openedEvent(at, remapped), "opened", "remote 3000 ≠ 127.0.0.1:3001 (node)"},
		{closedEvent(at, st, "gone"), "closed", "remote 3000 closed on 127.0.0.1:3000 (gone)"},
		{failedEvent(at, st, "busy"), "failed", "remote 3000 not forwarded: busy"},
	}
	for _, tt := range tests {
		if tt.e.Kind != tt.kind {
			t.Errorf("Kind = %q, want %q", tt.e.Kind, tt.kind)
		}
		if tt.e.Class != event.Network {
			t.Errorf("%s: class = %q, want network", tt.kind, tt.e.Class)
		}
		if tt.e.Text != tt.want {
			t.Errorf("Text = %q, want %q", tt.e.Text, tt.want)
		}
	}
}

// waitUntil polls cond, failing the test if it never becomes true.
func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A browser request relocates a tunnel for the session only: a login flow's
// throwaway callback port should not become a permanent pin for that host.
func TestManagerTryLocalPortIsNotRemembered(t *testing.T) {
	echo := newEchoServer(t)
	store := NewStore(newFakeConfig())
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy: DefaultPolicy(), Settings: store,
	})
	defer m.Close()

	remote, moved := freePort(t), freePort(t)
	m.Sync(snapshotOf(remote))

	if err := m.TryLocalPort(remote, moved); err != nil {
		t.Fatalf("TryLocalPort: %v", err)
	}
	if got := stateFor(t, m, remote).LocalPort; got != moved {
		t.Errorf("local port = %d, want the tunnel moved to %d", got, moved)
	}
	if got := roundTrip(t, moved, "hi"); got != "HI" {
		t.Errorf("round trip on the relocated port = %q, want HI", got)
	}
	if saved := store.Port(remote).Local; saved != 0 {
		t.Errorf("settings recorded local port %d; a temporary move should not persist", saved)
	}

	// The choice a user makes deliberately, by contrast, is remembered.
	if err := m.SetLocalPort(remote, moved); err != nil {
		t.Fatalf("SetLocalPort: %v", err)
	}
	if saved := store.Port(remote).Local; saved != moved {
		t.Errorf("settings recorded %d, want the pinned %d", saved, moved)
	}
}

// An explicit request beats a blanket rule: pausing suspends new automatic
// tunnels, but asking for one by port is not a blanket anything.
func TestManagerForwardNowOverridesASkip(t *testing.T) {
	p := DefaultPolicy()
	p.Paused = true
	m, _, _ := newTestManager(t, p)
	port := freePort(t)

	m.Sync(snapshotOf(port))
	if st := stateFor(t, m, port); st.Status != StatusSkipped || st.Skip != SkipPaused {
		t.Fatalf("status = %q / %q, want a paused skip", st.Status, st.Skip)
	}

	if err := m.ForwardNow(port); err != nil {
		t.Fatalf("ForwardNow: %v", err)
	}
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Fatalf("status = %q, want the tunnel opened", st.Status)
	}
	if got := roundTrip(t, port, "hi"); got != "HI" {
		t.Errorf("round trip = %q, want HI", got)
	}
}

func TestManagerForwardNowLeavesADeliberateHideAlone(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())
	port := freePort(t)
	m.Sync(snapshotOf(port))
	m.SetMode(port, ModeHidden)

	if err := m.ForwardNow(port); err == nil {
		t.Error("a port the user hid was forwarded anyway")
	}
	m.SetShowHidden(true)
	if st := stateFor(t, m, port); st.Status == StatusActive {
		t.Error("the tunnel was opened despite being hidden")
	}
}

func TestManagerForwardNowRejectsAnUnlistedPort(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())
	if err := m.ForwardNow(9999); err == nil {
		t.Error("an unlisted port should be rejected")
	}
}

// A dozen lines arriving in the same instant reads as something going wrong
// rather than something working — and on a busy box that is the very first
// impression devtun makes.
func TestFirstBurstIsSummarisedOnce(t *testing.T) {
	mgr, _, c := newTestManager(t, DefaultPolicy())

	snap := probe.Snapshot{}
	for _, port := range []int{3000, 5173, 8080, 9229, 5432} {
		snap[port] = probe.Service{Port: port, Proc: "node", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}}
	}
	mgr.Sync(snap)

	var summaries, singles int
	for _, e := range c.all() {
		switch e.Kind {
		case "opened-many":
			summaries++
			if !strings.Contains(e.Text, "5 ports") {
				t.Errorf("the summary should count the ports, got %q", e.Text)
			}
			if !strings.Contains(e.Text, "x hides") {
				t.Errorf("the summary should say how to hide one, got %q", e.Text)
			}
		case "opened":
			singles++
		}
	}
	if summaries != 1 {
		t.Errorf("want one summary line, got %d", summaries)
	}
	if singles != 0 {
		t.Errorf("the burst should not also emit %d individual lines", singles)
	}

	// A port appearing later is news about that port, and must not be folded
	// into anything.
	snap[4000] = probe.Service{Port: 4000, Proc: "vite", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}}
	mgr.Sync(snap)

	for _, e := range c.all() {
		if e.Kind == "opened" && strings.Contains(e.Text, "4000") {
			return
		}
	}
	t.Error("a port appearing after the first scan should get its own line")
}

// Three ports is a normal dev box waking up, not a flood.
func TestSmallBurstIsNotSummarised(t *testing.T) {
	mgr, _, c := newTestManager(t, DefaultPolicy())

	snap := probe.Snapshot{}
	for _, port := range []int{3000, 5173} {
		snap[port] = probe.Service{Port: port, Proc: "node", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}}
	}
	mgr.Sync(snap)

	for _, e := range c.all() {
		if e.Kind == "opened-many" {
			t.Fatalf("two ports should not be summarised: %q", e.Text)
		}
	}
}

// A count of what you cannot currently see is the point: it is the reminder
// that the board is shorter than the box. States() omits hidden rows by design,
// so the count has to come from somewhere else.
func TestHiddenCountIsVisibleWhileHiddenRowsAreNot(t *testing.T) {
	mgr, _, _ := newTestManager(t, DefaultPolicy())

	snap := probe.Snapshot{}
	for _, port := range []int{3000, 5432, 6379} {
		snap[port] = probe.Service{Port: port, Proc: "x", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}}
	}
	mgr.Sync(snap)

	if got := mgr.Hidden(); got != 0 {
		t.Fatalf("nothing is hidden yet, got %d", got)
	}

	mgr.SetMode(5432, ModeHidden)
	mgr.SetMode(6379, ModeHidden)
	mgr.Sync(snap)

	if got := mgr.Hidden(); got != 2 {
		t.Errorf("want 2 hidden, got %d", got)
	}
	// And they must still be absent from the table, which is the reason the
	// count could not simply be derived from it.
	for _, st := range mgr.States() {
		if st.RemotePort == 5432 || st.RemotePort == 6379 {
			t.Errorf("a hidden port is still in States(): %d", st.RemotePort)
		}
	}
}

// The global hide list hides without being written to the host file, so it has
// to be counted the same way.
func TestGloballyHiddenPortsAreCounted(t *testing.T) {
	echo := newEchoServer(t)
	mgr := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy:     DefaultPolicy(),
		GlobalHide: []int{5432},
		Events:     &collector{},
	})
	t.Cleanup(mgr.Close)

	mgr.Sync(probe.Snapshot{
		3000: {Port: 3000, Proc: "x", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}},
		5432: {Port: 5432, Proc: "postgres", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}},
	})

	if got := mgr.Hidden(); got != 1 {
		t.Errorf("want the globally hidden port counted, got %d", got)
	}
}

// Sync iterates a map, so without sorting the same box prints a different
// summary every run — and a list you cannot scan for the port you care about
// is a list you read twice.
func TestTheSummaryListsPortsInOrder(t *testing.T) {
	mgr, _, c := newTestManager(t, DefaultPolicy())

	snap := probe.Snapshot{}
	for _, port := range []int{37973, 5432, 3000, 5173, 8080} {
		snap[port] = probe.Service{Port: port, Proc: "x", Binds: []probe.Bind{{Proto: "tcp", Addr: "127.0.0.1"}}}
	}
	mgr.Sync(snap)

	var summary string
	for _, e := range c.all() {
		if e.Kind == "opened-many" {
			summary = e.Text
		}
	}
	if summary == "" {
		t.Fatal("no summary was emitted")
	}
	want := "3000 5173 5432 8080 37973"
	if !strings.Contains(summary, want) {
		t.Errorf("want the ports in order (%s), got %q", want, summary)
	}
}
