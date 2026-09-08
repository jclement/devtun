package tui

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
)

// testNow is the fixed clock every test renders against, so ages and uptimes
// are the same on every machine and in every year.
var testNow = time.Date(2026, 9, 6, 14, 22, 1, 0, time.UTC)

// stubTunnels is a tunnelCtrl backed by a fixed slice of rows.
//
// It reproduces the one manager behaviour the interface actually depends on:
// a hidden port is not in States at all unless hidden rows are being shown.
// Without that, "x makes the row disappear" would be a test of nothing.
type stubTunnels struct {
	mu       sync.Mutex
	rows     []tunnels.State
	prefs    tunnels.ViewPrefs
	policy   tunnels.Policy
	localErr error
	labels   map[int]string
	locals   map[int]int
}

func newStub(rows ...tunnels.State) *stubTunnels {
	return &stubTunnels{
		rows:   rows,
		policy: tunnels.DefaultPolicy(),
		// Tests about layout and keys should see the rows they construct in
		// the order they constructed them; grouping is covered on its own.
		prefs:  tunnels.ViewPrefs{InactiveLast: false, Sort: "port"},
		labels: map[int]string{},
		locals: map[int]int{},
	}
}

func (s *stubTunnels) Hidden() int {
	n := 0
	for _, r := range s.rows {
		if r.Mode == tunnels.ModeHidden {
			n++
		}
	}
	return n
}

func (s *stubTunnels) States() []tunnels.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]tunnels.State, 0, len(s.rows))
	for _, r := range s.rows {
		if r.Mode == tunnels.ModeHidden && !s.prefs.ShowHidden {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *stubTunnels) each(port int, fn func(*tunnels.State)) {
	for i := range s.rows {
		if s.rows[i].RemotePort == port {
			fn(&s.rows[i])
		}
	}
}

func (s *stubTunnels) SetMode(port int, mode tunnels.Mode) tunnels.Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.each(port, func(r *tunnels.State) {
		r.Mode = mode
		switch mode {
		case tunnels.ModeHidden:
			r.Status, r.Skip = tunnels.StatusSkipped, tunnels.SkipHidden
		default:
			r.Skip = tunnels.SkipNone
		}
	})
	return mode
}

func (s *stubTunnels) CycleMode(port int) tunnels.Mode {
	s.mu.Lock()
	next := tunnels.ModeAuto
	s.each(port, func(r *tunnels.State) { next = r.Mode.Next() })
	s.mu.Unlock()
	return s.SetMode(port, next)
}

func (s *stubTunnels) CycleScheme(port int) tunnels.Scheme {
	s.mu.Lock()
	next := tunnels.SchemeUnknown
	s.each(port, func(r *tunnels.State) { next = r.Scheme.Next() })
	s.mu.Unlock()
	return s.SetScheme(port, next)
}

func (s *stubTunnels) SetScheme(port int, scheme tunnels.Scheme) tunnels.Scheme {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.each(port, func(r *tunnels.State) {
		r.Scheme = scheme
		r.SchemePinned = scheme != tunnels.SchemeUnknown
	})
	return scheme
}

func (s *stubTunnels) SetLocalPort(port, local int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localErr != nil {
		return s.localErr
	}
	s.locals[port] = local
	s.each(port, func(r *tunnels.State) {
		r.PinnedLocal = local
		if local > 0 {
			r.LocalPort = local
		}
	})
	return nil
}

func (s *stubTunnels) SetLabel(port int, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels[port] = label
	s.each(port, func(r *tunnels.State) { r.Label = label })
	return nil
}

func (s *stubTunnels) Policy() tunnels.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy
}

func (s *stubTunnels) SetPolicy(p tunnels.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = p
}

func (s *stubTunnels) ViewPrefs() tunnels.ViewPrefs {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prefs
}

func (s *stubTunnels) SetViewPrefs(p tunnels.ViewPrefs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefs = p
}

// stubSecrets is a secretsCtrl over a fixed rule list.
// oneSource wraps a single stub broker as the tab's source list, which is what
// the model takes now that there is more than one broker.
func oneSource(s *stubSecrets) []accessSource {
	if s == nil {
		return nil
	}
	return []accessSource{{id: "1password", title: "1Password", ctrl: s}}
}

type stubSecrets struct {
	rules     []authz.Rule
	global    []authz.Rule
	live      []authz.Grant
	grants    int
	cached    int
	forgot    bool
	revoked   []int
	revokedBy []string
	denied    []int
}

func (s *stubSecrets) Rules() []authz.Rule { return s.rules }

func (s *stubSecrets) Revoke(i int) error {
	s.revoked = append(s.revoked, i)
	s.rules = append(s.rules[:i], s.rules[i+1:]...)
	return nil
}

func (s *stubSecrets) Deny(i int) error {
	s.denied = append(s.denied, i)
	s.rules[i].Action = authz.ActionDeny
	return nil
}

func (s *stubSecrets) GlobalRules() []authz.Rule { return s.global }

func (s *stubSecrets) Grants() []authz.Grant { return s.live }

func (s *stubSecrets) RevokeGrant(host, subject string) bool {
	for i, g := range s.live {
		if g.Host == host && g.Subject == subject {
			s.live = append(s.live[:i], s.live[i+1:]...)
			s.revokedBy = append(s.revokedBy, host+" "+subject)
			return true
		}
	}
	return false
}

func (s *stubSecrets) Forget() (int, int) {
	s.forgot = true
	return s.grants, s.cached
}

// newTestStore is the real configuration store over a temporary directory.
//
// There is no stub for this one. What the Config tab has to get right is which
// of two files a value lands in and which of them a value came from, and a stub
// could only ever agree with itself about that. Nothing reaches the disk until
// Save, so the ones that never call it pay for a directory and no I/O.
func newTestStore(t *testing.T) *hostcfg.Store {
	t.Helper()
	return hostcfg.Open(t.TempDir())
}

// stubService is the smallest thing satisfying service.Service, for the
// Services tab and the settings popup.
type stubService struct {
	meta service.Meta
}

func (s stubService) Meta() service.Meta { return s.meta }

func (s stubService) Probe(context.Context, service.Host) service.Support {
	return service.Supported()
}

func (s stubService) Attach(context.Context, service.Host) (service.Instance, error) {
	return nil, nil
}

// --- building and driving a model -----------------------------------------

// newTestModel builds a model at a known size with a fixed clock.
func newTestModel(t *testing.T, d deps) *Model {
	t.Helper()
	if d.tunnels == nil {
		d.tunnels = newStub()
	}
	if d.host == "" {
		d.host = "bedev"
	}
	if d.now == nil {
		d.now = func() time.Time { return testNow }
	}
	d.rng = rand.New(rand.NewSource(1))
	if d.openURL == nil {
		d.openURL = func(context.Context, string) error { return nil }
	}
	m := newModel(d)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	m.status = session.Status{State: session.Connected, Since: testNow.Add(-14 * time.Minute)}
	m.everConnected = true
	m.reload()
	return m
}

// plainView renders the model with styling stripped, for content assertions.
func plainView(m *Model) string { return ansi.Strip(m.frame()) }

// send delivers a keystroke by name, the way a terminal would.
func send(m *Model, name string) { m.Update(key(name)) }

// key turns a keystroke name into the message Bubble Tea would deliver for it.
// v2 reports printable input as Key.Text and everything else as a key code, so
// the two cases are built differently.
func key(name string) tea.KeyPressMsg {
	special := map[string]rune{
		"enter": tea.KeyEnter, "esc": tea.KeyEscape, "tab": tea.KeyTab,
		"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
		"home": tea.KeyHome, "end": tea.KeyEnd, "pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown,
		"backspace": tea.KeyBackspace, "space": tea.KeySpace,
	}
	if code, ok := special[name]; ok {
		return tea.KeyPressMsg{Code: code}
	}
	if name == "shift+tab" {
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	}
	if rest, ok := strings.CutPrefix(name, "ctrl+"); ok {
		return tea.KeyPressMsg{Code: []rune(rest)[0], Mod: tea.ModCtrl}
	}
	r := []rune(name)[0]
	return tea.KeyPressMsg{Code: r, Text: name}
}

// click delivers a left button press at a cell.
func click(m *Model, x, y int) {
	m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
}

// row builds an active tunnel for the table.
func row(remote, local int, cmd string) tunnels.State {
	return tunnels.State{
		RemotePort: remote,
		LocalPort:  local,
		LocalAddr:  "127.0.0.1",
		Remapped:   remote != local,
		Cmd:        cmd,
		Proc:       strings.Fields(cmd + " ")[0],
		Status:     tunnels.StatusActive,
		Scheme:     tunnels.SchemeHTTP,
		FirstSeen:  testNow.Add(-14 * time.Minute),
		Created:    testNow.Add(-14 * time.Minute),
	}
}

// skippedRow builds a row that is listed but not forwarded.
func skippedRow(remote int, cmd string, skip tunnels.Skip) tunnels.State {
	s := row(remote, 0, cmd)
	s.Status, s.Skip, s.LocalPort = tunnels.StatusSkipped, skip, 0
	if skip == tunnels.SkipHidden {
		s.Mode = tunnels.ModeHidden
	}
	return s
}

// bodyLines returns just the active tab's own lines, with styling stripped.
// Assertions about a tab have to look here rather than at the whole frame: the
// ticker and the toast both quote events and actions, so a naive Contains over
// the frame passes on the strength of a line the tab did not draw.
func bodyLines(m *Model) string {
	lines := strings.Split(plainView(m), "\n")
	if len(lines) < m.chrome()+1 {
		return ""
	}
	return strings.Join(lines[rowBody:rowBody+m.bodyHeight()], "\n")
}
