package tunnels

import (
	"fmt"
	"testing"

	"github.com/jclement/devtun/internal/tunnels/probe"
)

func svc(port int, addrs ...string) probe.Service {
	s := probe.Service{Port: port, Proc: "node"}
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1"}
	}
	for _, a := range addrs {
		s.Binds = append(s.Binds, probe.Bind{Proto: "tcp", Addr: a})
	}
	return s
}

func mustSet(t *testing.T, spec string) PortSet {
	t.Helper()
	ps, err := ParsePortSet(spec)
	if err != nil {
		t.Fatalf("ParsePortSet(%q): %v", spec, err)
	}
	return ps
}

// Everything at or above the floor is forwarded — including services that were
// already up. Nothing is exempted for having started before devtun connected,
// because a box you reattach to daily would otherwise show a different table
// every time.
func TestPolicyDefaults(t *testing.T) {
	p := DefaultPolicy()
	tests := []struct {
		name string
		svc  probe.Service
		want Skip
	}{
		{"high port is forwarded", svc(3000), SkipNone},
		{"privileged port is skipped", svc(80), SkipBelowMin},
		{"boundary 1024 is forwarded", svc(1024), SkipNone},
		{"boundary 1023 is skipped", svc(1023), SkipBelowMin},
		{"wildcard bind is forwarded by default", svc(3000, "0.0.0.0"), SkipNone},
		{"a database nobody restarted is still forwarded", svc(5432), SkipNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Eval(tt.svc); got != tt.want {
				t.Errorf("Eval() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPolicyExclude(t *testing.T) {
	p := DefaultPolicy()
	p.Exclude = mustSet(t, "3000,9000-9100")

	for _, port := range []int{3000, 9000, 9050, 9100} {
		if got := p.Eval(svc(port)); got != SkipExcluded {
			t.Errorf("port %d = %q, want excluded", port, got)
		}
	}
	if got := p.Eval(svc(3001)); got != SkipNone {
		t.Errorf("port 3001 = %q, want forwarded", got)
	}
}

// --exclude has to beat --include, otherwise there is no way to punch a hole
// in a range.
func TestPolicyExcludeBeatsInclude(t *testing.T) {
	p := DefaultPolicy()
	p.Include = mustSet(t, "8000-9000")
	p.Exclude = mustSet(t, "8080")

	if got := p.Eval(svc(8080)); got != SkipExcluded {
		t.Errorf("port 8080 = %q, want excluded", got)
	}
	if got := p.Eval(svc(8081)); got != SkipNone {
		t.Errorf("port 8081 = %q, want forwarded", got)
	}
}

func TestPolicyIncludeIsExclusive(t *testing.T) {
	p := DefaultPolicy()
	p.Include = mustSet(t, "3000")

	if got := p.Eval(svc(3000)); got != SkipNone {
		t.Errorf("port 3000 = %q, want forwarded", got)
	}
	if got := p.Eval(svc(4000)); got != SkipNotInclude {
		t.Errorf("port 4000 = %q, want not-in-include", got)
	}
}

// Naming a port explicitly is an unambiguous request for it, so --include
// overrides the port window and the bind filter.
func TestPolicyIncludeOverridesOtherRules(t *testing.T) {
	p := DefaultPolicy()
	p.Include = mustSet(t, "80,5432")
	p.RemoteBind = BindLoopback

	if got := p.Eval(svc(80)); got != SkipNone {
		t.Errorf("explicitly included port 80 = %q, want forwarded despite --min-port", got)
	}
	if got := p.Eval(svc(5432, "0.0.0.0")); got != SkipNone {
		t.Errorf("explicitly included wildcard bind = %q, want forwarded", got)
	}
}

func TestPolicyPortWindow(t *testing.T) {
	p := DefaultPolicy()
	p.MinPort, p.MaxPort = 3000, 4000

	if got := p.Eval(svc(2999)); got != SkipBelowMin {
		t.Errorf("port 2999 = %q, want below-min", got)
	}
	if got := p.Eval(svc(4001)); got != SkipAboveMax {
		t.Errorf("port 4001 = %q, want above-max", got)
	}
	if got := p.Eval(svc(3500)); got != SkipNone {
		t.Errorf("port 3500 = %q, want forwarded", got)
	}
}

func TestPolicyRemoteBindLoopback(t *testing.T) {
	p := DefaultPolicy()
	p.RemoteBind = BindLoopback

	tests := []struct {
		name string
		svc  probe.Service
		want Skip
	}{
		{"loopback only", svc(3000, "127.0.0.1"), SkipNone},
		{"both loopbacks", svc(3000, "127.0.0.1", "::1"), SkipNone},
		{"wildcard", svc(3000, "0.0.0.0"), SkipNotLoop},
		{"mixed", svc(3000, "127.0.0.1", "0.0.0.0"), SkipNotLoop},
		{"specific address", svc(3000, "10.0.0.5"), SkipNotLoop},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Eval(tt.svc); got != tt.want {
				t.Errorf("Eval() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPolicyPaused(t *testing.T) {
	p := DefaultPolicy()
	p.Paused = true
	if got := p.Eval(svc(3000)); got != SkipPaused {
		t.Errorf("Eval() = %q, want paused", got)
	}
	// Pausing must not mask a more specific reason being wrong; excluded
	// still reports excluded.
	p.Exclude = mustSet(t, "3000")
	if got := p.Eval(svc(3000)); got != SkipExcluded {
		t.Errorf("Eval() = %q, want excluded", got)
	}
}

func TestParseRemoteBind(t *testing.T) {
	if got, err := ParseRemoteBind("any"); err != nil || got != BindAny {
		t.Errorf(`ParseRemoteBind("any") = %q, %v`, got, err)
	}
	if got, err := ParseRemoteBind("loopback"); err != nil || got != BindLoopback {
		t.Errorf(`ParseRemoteBind("loopback") = %q, %v`, got, err)
	}
	if _, err := ParseRemoteBind("sideways"); err == nil {
		t.Error("want an error for an unknown bind mode")
	}
}

func TestModeCycleAndParse(t *testing.T) {
	if got := ParseMode(""); got != ModeAuto {
		t.Errorf("the zero mode = %q, want auto", got)
	}
	if got := ParseMode("nonsense"); got != ModeAuto {
		t.Errorf("an unreadable stored mode = %q, want auto", got)
	}
	want := []Mode{ModeOn, ModeHidden, ModeAuto}
	m := ModeAuto
	for i, w := range want {
		if m = m.Next(); m != w {
			t.Fatalf("cycle step %d = %q, want %q", i+1, m, w)
		}
	}
}

// --- The decision, end to end -------------------------------------------
//
// Policy.Eval is only half the story: Mode, the global hide list and the
// reconnect path all meet in the Manager, and that is where the rewrite
// actually differs from autotun.

// The first thing devtun ever sees on a host gets forwarded. Everything above
// the floor, nothing held back for being older than the session.
func TestFirstAttachForwardsEverythingAboveMinPort(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	a, b := freePort(t), freePort(t)
	snap := snapshotOf(a, b)
	snap[22] = probe.Service{Port: 22, Binds: []probe.Bind{{Proto: "tcp", Addr: "0.0.0.0"}}, Proc: "sshd"}
	m.Sync(snap)

	for _, port := range []int{a, b} {
		if st := stateFor(t, m, port); st.Status != StatusActive {
			t.Errorf("port %d = %q/%q on the very first scan, want active", port, st.Status, st.Skip)
		}
	}
	if got := len(m.States()); got != 2 {
		t.Errorf("%d rows, want 2 — sshd on 22 is below the floor and not a decision", got)
	}
}

// Hiding is the user's only per-port veto, so it has to hold through a dropped
// link. Losing it would re-open a tunnel the user closed on purpose.
func TestHidePersistsAcrossAReconnect(t *testing.T) {
	m, dialer, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	m.SetMode(port, ModeHidden)

	m.SetDialer(nil)
	m.SetDialer(dialer)
	m.Sync(snapshotOf(port))

	if len(m.States()) != 0 {
		t.Fatalf("a hidden row came back after a reconnect: %+v", m.States())
	}
	m.SetShowHidden(true)
	st := stateFor(t, m, port)
	if st.Mode != ModeHidden || st.Status == StatusActive {
		t.Errorf("after reconnect = %q/%q, want it still hidden and unforwarded", st.Mode, st.Status)
	}
}

// And through a restart of devtun itself, which is the case autotun could not
// serve: the decision lives in the host's config, not in the session.
func TestHidePersistsAcrossARestart(t *testing.T) {
	cfg := newFakeConfig()
	port := freePort(t)

	first, _, _ := newTestManagerWithStore(t, DefaultPolicy(), NewStore(cfg))
	first.Sync(snapshotOf(port))
	if st := stateFor(t, first, port); st.Status != StatusActive {
		t.Fatalf("status = %q, want active before hiding", st.Status)
	}
	first.SetMode(port, ModeHidden)

	// A new process: a new Store over the same config document.
	second, _, _ := newTestManagerWithStore(t, DefaultPolicy(), NewStore(cfg))
	second.Sync(snapshotOf(port))

	if len(second.States()) != 0 {
		t.Fatalf("a hidden row came back on the next run: %+v", second.States())
	}
	second.SetShowHidden(true)
	if st := stateFor(t, second, port); st.Mode != ModeHidden {
		t.Errorf("mode = %q on the next run, want the remembered hidden", st.Mode)
	}
}

// The global list hides a port on every host — a company-wide agent, say — but
// is not a decision about any one host, so it is never written to a host file.
func TestGlobalHideListAppliesWithoutBeingWrittenBack(t *testing.T) {
	echo := newEchoServer(t)
	store := NewStore(newFakeConfig())
	port := freePort(t)

	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy:     DefaultPolicy(),
		Settings:   store,
		GlobalHide: []int{port},
	})
	t.Cleanup(m.Close)
	m.Sync(snapshotOf(port))

	if len(m.States()) != 0 {
		t.Fatalf("a globally hidden port was listed: %+v", m.States())
	}
	m.SetShowHidden(true)
	if st := stateFor(t, m, port); st.Skip != SkipHidden || st.Status == StatusActive {
		t.Errorf("globally hidden port = %q/%q, want skipped/hidden", st.Status, st.Skip)
	}
	// Its mode is untouched, so dropping it from the global list restores it
	// everywhere rather than leaving a hide behind on every host it touched.
	if st := stateFor(t, m, port); st.Mode != ModeAuto {
		t.Errorf("mode = %q, want auto", st.Mode)
	}
	if got := store.Port(port); got != (PortPrefs{}) {
		t.Errorf("the global hide was written to the host file: %+v", got)
	}
}

// "On" is how you say "I know it is below the floor, forward it anyway".
func TestModeOnBeatsAFilter(t *testing.T) {
	p := DefaultPolicy()
	p.MinPort = 65000
	m, _, _ := newTestManager(t, p)

	port := freePort(t)
	m.Sync(snapshotOf(port))
	if len(m.States()) != 0 {
		t.Fatalf("expected the out-of-window port to be filtered out: %+v", m.States())
	}

	if got := m.SetMode(port, ModeOn); got != ModeOn {
		t.Fatalf("SetMode = %q, want on", got)
	}
	st := stateFor(t, m, port)
	if st.Status != StatusActive {
		t.Fatalf("status = %q, want an explicit on to beat --min-port", st.Status)
	}
	if got := roundTrip(t, st.LocalPort, "on"); got != "ON" {
		t.Errorf("round trip = %q, want ON", got)
	}
}

// --exclude is the one filter "on" does not beat. It is a statement about this
// run, and a stored preference that overrode it would leave no way to suppress
// a port for a single session.
func TestExcludeBeatsModeOn(t *testing.T) {
	m, _, _ := newTestManager(t, DefaultPolicy())

	port := freePort(t)
	m.Sync(snapshotOf(port))
	m.SetMode(port, ModeOn)
	if st := stateFor(t, m, port); st.Status != StatusActive {
		t.Fatalf("status = %q, want active before excluding", st.Status)
	}

	p := m.Policy()
	p.Exclude = mustSet(t, fmt.Sprint(port))
	m.SetPolicy(p)

	st := stateFor(t, m, port)
	if st.Status == StatusActive {
		t.Error("--exclude did not close a tunnel the user had switched on")
	}
	if st.Skip != SkipExcluded {
		t.Errorf("skip = %q, want excluded", st.Skip)
	}
	// The row stays, because a standing "on" that is not being honoured is
	// something the user needs to see in order to change their mind.
	if len(m.States()) != 1 {
		t.Errorf("%d rows, want the excluded-but-on port still listed", len(m.States()))
	}
}

// newTestManagerWithStore is newTestManager with persistence attached.
func newTestManagerWithStore(t *testing.T, policy Policy, store *Store) (*Manager, *fixedDialer, *collector) {
	t.Helper()
	echo := newEchoServer(t)
	d := &fixedDialer{addr: echo.addr()}
	c := &collector{}
	m := NewManager(NewAllocator("127.0.0.1", false), d, ManagerOptions{
		Policy:   policy,
		Settings: store,
		Events:   c,
	})
	t.Cleanup(m.Close)
	return m, d, c
}
