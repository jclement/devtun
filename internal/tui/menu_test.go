package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/prompt"
)

// locate finds text on the rendered screen and returns the cell of its first
// character, so a test clicks where something was actually drawn.
func locate(t *testing.T, m *Model, text string) (int, int) {
	t.Helper()
	for y, line := range strings.Split(plainView(m), "\n") {
		if i := strings.Index(line, text); i >= 0 {
			return ansi.StringWidth(line[:i]), y
		}
	}
	t.Fatalf("%q is not on screen:\n%s", text, plainView(m))
	return 0, 0
}

func rightClick(m *Model, x, y int) {
	m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseRight})
}

// accessFixture is an Access tab with one of each kind of row.
func accessFixture(t *testing.T) (*Model, *stubSecrets) {
	t.Helper()
	s := &stubSecrets{
		live: []authz.Grant{
			{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow},
			{Host: "bedev", Subject: "op://Personal/AWS/root", Action: authz.ActionDeny},
		},
		rules: []authz.Rule{
			{Host: "bedev", Subject: "op://Work/CI/token", Action: authz.ActionAllow},
			{Host: "bedev", Subject: "op://Work/Stripe/key", Action: authz.ActionDeny},
		},
		global: []authz.Rule{{Host: "**", Subject: "op://Private/**", Action: authz.ActionDeny}},
	}
	m := newTestModel(t, deps{secrets: oneSource(s)})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	send(m, "3")
	return m, s
}

func TestClickingARowSelectsItAndClickingAgainOpensIt(t *testing.T) {
	m, _ := accessFixture(t)
	x, y := locate(t, m, "op://Work/CI/token")

	click(m, x, y)
	if r, ok := m.selectedAccess(); !ok || r.subject() != "op://Work/CI/token" {
		t.Fatalf("the click selected %+v", r)
	}
	if m.showDetail {
		t.Fatal("the first click opened the detail; it should only select")
	}
	click(m, x, y)
	if !m.showDetail {
		t.Fatal("a click on the selected row did not open it")
	}
	if !strings.Contains(plainView(m), "exactly this secret") {
		t.Errorf("the detail does not explain the rule:\n%s", plainView(m))
	}
}

// Headings are labels: a click on one must not arm r against nothing.
func TestClickingASectionHeadingSelectsNothing(t *testing.T) {
	m, _ := accessFixture(t)
	x, y := locate(t, m, "WRITTEN BY DEVTUN")
	click(m, x, y)
	if m.hasSelection() {
		t.Errorf("a heading took the cursor (row %d)", m.cursor())
	}
}

func TestRightClickOpensTheRowsMenuWithReasons(t *testing.T) {
	m, s := accessFixture(t)
	x, y := locate(t, m, "op://Private/**")
	rightClick(m, x, y)

	if m.menu == nil {
		t.Fatal("a right click did not open the action menu")
	}
	view := plainView(m)
	// The reason is on screen before anyone presses r.
	if !strings.Contains(view, "global rule — edit it in config.yaml") {
		t.Errorf("the menu does not say why revoke is unavailable:\n%s", view)
	}
	// And pressing it anyway changes nothing.
	send(m, "r")
	if len(s.revoked) != 0 {
		t.Errorf("the menu revoked a global rule: %v", s.revoked)
	}
	if m.menu == nil {
		t.Error("an unavailable item closed the menu")
	}
}

func TestClickingAMenuItemRunsIt(t *testing.T) {
	m, s := accessFixture(t)
	x, y := locate(t, m, "op://Work/CI/token")
	rightClick(m, x, y)

	bx, by := locate(t, m, "Make this rule a deny")
	click(m, bx, by)
	if len(s.denied) != 1 || s.denied[0] != 0 {
		t.Errorf("clicking the menu's deny item denied %v", s.denied)
	}
	if m.menu != nil {
		t.Error("the menu stayed open after running")
	}
}

func TestTheDotKeyOpensTheMenuAndAClickOutsideClosesIt(t *testing.T) {
	m, _ := accessFixture(t)
	send(m, "down")
	send(m, ".")
	if m.menu == nil {
		t.Fatal(". did not open the menu")
	}
	click(m, 0, m.height-2)
	if m.menu != nil {
		t.Error("a click outside the menu did not close it")
	}
}

// One keystroke never loosens. r on an allow only tightens and stays one
// key; r on a deny asks, says what will happen, and needs the y — enter, the
// key that dismisses everything else, does not accept.
func TestRevokingADenyAsksFirst(t *testing.T) {
	m, s := accessFixture(t)
	selectSubject(m, "op://Work/Stripe/key")
	send(m, "r")
	if m.confirm == nil {
		t.Fatal("r on a deny rule did not ask")
	}
	// No allow underneath and no prompt surface in this fixture, so the
	// honest consequence is that it stays refused.
	if !strings.Contains(plainView(m), "stays refused") {
		t.Errorf("the confirm does not say what happens next:\n%s", plainView(m))
	}
	send(m, "enter")
	if len(s.revoked) != 0 || m.confirm == nil {
		t.Fatal("enter accepted a loosening confirm")
	}
	send(m, "n")
	if len(s.revoked) != 0 {
		t.Fatal("n removed the refusal")
	}

	// An allow goes in one key.
	selectSubject(m, "op://Work/CI/token")
	send(m, "r")
	if m.confirm != nil || len(s.revoked) != 1 {
		t.Errorf("r on an allow should not ask: confirm=%v revoked=%v", m.confirm != nil, s.revoked)
	}
}

func TestStopAskRefusalAsksBeforeItGoes(t *testing.T) {
	m, s := accessFixture(t)
	selectSubject(m, "op://Personal/AWS/root")
	send(m, "r")
	if m.confirm == nil {
		t.Fatal("revoking a stop-ask refusal did not ask")
	}
	send(m, "y")
	if len(s.revokedBy) != 1 {
		t.Errorf("y did not revoke the refusal: %v", s.revokedBy)
	}
}

func TestTheConfirmsButtonsAreClickable(t *testing.T) {
	m, s := accessFixture(t)
	selectSubject(m, "op://Work/Stripe/key")
	send(m, "r")

	// A click on the box but off the buttons is not an answer.
	tx, ty := locate(t, m, "Remove a refusal?")
	click(m, tx, ty)
	if m.confirm == nil || len(s.revoked) != 0 {
		t.Fatal("a click on the confirm's title answered it")
	}
	// Nor is a click outside: the confirm is modal.
	click(m, 0, m.height-2)
	if m.confirm == nil {
		t.Fatal("a click outside dismissed the confirm")
	}
	bx, by := locate(t, m, "remove it")
	click(m, bx, by)
	if len(s.revoked) != 1 || s.revoked[0] != 1 {
		t.Errorf("clicking 'remove it' revoked %v", s.revoked)
	}
}

// F is the panic button and only tightens: approvals and cached values go,
// "stop asking" refusals stay, so it needs no confirm. Clearing the refusals
// is X, which loosens and asks first.
func TestForgetKeepsRefusalsAndClearingThemAsks(t *testing.T) {
	m, s := accessFixture(t)
	send(m, "F")
	if m.confirm != nil || !s.forgot {
		t.Fatal("F should forget in one key")
	}
	if !strings.Contains(m.toast.text, "kept 1 refusal") {
		t.Errorf("F does not say the refusal survived: %q", m.toast.text)
	}

	send(m, "X")
	if m.confirm == nil || s.refusalsForgot != 0 {
		t.Fatal("X cleared refusals without asking")
	}
	if !strings.Contains(m.confirm.title, "1 refusal") {
		t.Errorf("the confirm does not count them: %q", m.confirm.title)
	}
	send(m, "y")
	if s.refusalsForgot != 1 {
		t.Error("y did not clear the refusals")
	}
	send(m, "X")
	if m.confirm != nil {
		t.Error("X asked with no refusals left")
	}
}

// `: deny` ran Revoke, because "deny" was one of Revoke's aliases and Revoke
// was declared first — on a deny row, deleting the refusal you asked for.
func TestThePaletteRanksDenyAboveRevoke(t *testing.T) {
	m, _ := accessFixture(t)
	send(m, ":")
	typeIn(m, "deny")
	if len(m.cmd.matches) == 0 || m.cmd.matches[0].key != "D" {
		t.Fatalf("`: deny` offers %+v first", m.cmd.matches)
	}
	for _, a := range m.cmd.matches {
		if a.key == "r" && a.tab == tabAccess {
			t.Error("`: deny` still offers Revoke")
		}
	}
}

func TestTheCommandsChipOpensThePaletteAndAClickRunsAnEntry(t *testing.T) {
	m, _ := accessFixture(t)
	x, y := locate(t, m, "☰ commands")
	click(m, x+1, y)
	if !m.cmd.open {
		t.Fatal("clicking ☰ commands did not open the palette")
	}
	// With nothing typed, this tab's actions come first.
	if m.cmd.matches[0].tab != tabAccess {
		t.Errorf("the palette leads with %v, not this tab", m.cmd.matches[0].tab)
	}
	bx, by := locate(t, m, "Show every key")
	click(m, bx, by)
	if m.cmd.open || !m.showHelp {
		t.Error("clicking a palette entry did not run it")
	}
}

func TestTheWheelMovesThePaletteAndScrollsATallDetail(t *testing.T) {
	m, _ := accessFixture(t)
	send(m, ":")
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if m.cmd.cursor != 1 {
		t.Errorf("the wheel left the palette cursor at %d", m.cmd.cursor)
	}
	send(m, "esc")

	// A short window makes the detail taller than the screen.
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 14})
	selectSubject(m, "op://Work/Stripe/key")
	send(m, "enter")
	if !strings.Contains(plainView(m), "more line") {
		t.Fatalf("a tall detail does not say there is more:\n%s", plainView(m))
	}
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if m.detailScroll == 0 {
		t.Error("the wheel did not scroll the detail")
	}
	if m.cursor() < 0 || m.accessRows[m.cursor()].subject() != "op://Work/Stripe/key" {
		t.Error("the wheel over the detail moved the list behind it")
	}
}

func TestClickingADetailActionRunsIt(t *testing.T) {
	m, s := accessFixture(t)
	selectSubject(m, "op://Work/CI/token")
	send(m, "enter")
	bx, by := locate(t, m, "Revoke this rule or grant")
	click(m, bx, by)
	if len(s.revoked) != 1 || s.revoked[0] != 0 {
		t.Errorf("clicking revoke in the detail revoked %v", s.revoked)
	}
	if m.showDetail {
		t.Error("the detail stayed open over a rule that is gone")
	}
}

// The key bar lists what works now, not a cheat-sheet: on a global rule there
// is no r and no D, because both would only be refused.
func TestTheKeyBarOnlyOffersWhatWorks(t *testing.T) {
	m, _ := accessFixture(t)
	selectSubject(m, "op://Private/**")
	bar := ansi.Strip(m.keyBar())
	for _, absent := range []string{"revoke", "deny"} {
		if strings.Contains(bar, absent) {
			t.Errorf("the key bar offers %q on a global rule: %q", absent, bar)
		}
	}
	for _, present := range []string{"enter detail", ". more", ": commands"} {
		if !strings.Contains(bar, present) {
			t.Errorf("the key bar is missing %q: %q", present, bar)
		}
	}

	selectSubject(m, "op://Work/CI/token")
	if bar := ansi.Strip(m.keyBar()); !strings.Contains(bar, "r revoke") || !strings.Contains(bar, "D deny") {
		t.Errorf("the key bar on an allow rule: %q", bar)
	}
}

// The commands entry outlives every contextual hint when the bar is narrow.
func TestTheKeyBarKeepsCommandsWhenNarrow(t *testing.T) {
	m, _ := accessFixture(t)
	selectSubject(m, "op://Work/CI/token")
	for _, width := range []int{60, 80, 100} {
		m.Update(tea.WindowSizeMsg{Width: width, Height: 30})
		if bar := ansi.Strip(m.keyBar()); !strings.Contains(bar, ":") {
			t.Errorf("at %d columns the bar lost `:`: %q", width, bar)
		}
	}
}

// A grant lapsing above the cursor must not slide the selection onto its
// neighbour, where the next r would revoke the wrong thing.
func TestTheAccessCursorFollowsTheRowNotThePosition(t *testing.T) {
	m, s := accessFixture(t)
	selectSubject(m, "op://Work/CI/token")
	s.live = s.live[1:] // the first grant lapses
	m.reload()
	if r, ok := m.selectedAccess(); !ok || r.subject() != "op://Work/CI/token" {
		t.Errorf("after a grant lapsed the cursor is on %q", r.subject())
	}
}

func TestTheHeaderSaysWhatEachTabShowsAndWhatIsBrokered(t *testing.T) {
	m, _ := accessFixture(t)
	view := plainView(m)
	for _, want := range []string{"bedev", "connected", "brokering op", "what bedev may use in your name"} {
		if !strings.Contains(view, want) {
			t.Errorf("the frame is missing %q:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "NOTHING MATCHES") {
		t.Errorf("the fallback is not shown:\n%s", view)
	}
}

func TestReleasingTheMouseIsVisible(t *testing.T) {
	m, _ := accessFixture(t)
	send(m, "m")
	if !strings.Contains(ansi.Strip(m.viewChip()), "mouse off") {
		t.Errorf("with the mouse released nothing says so: %q", ansi.Strip(m.viewChip()))
	}
}

// The answers are clickable, but not in the first instant: the box appears
// unannounced, under a pointer that was on its way to something else.
func TestApprovalAnswersAreClickableOnceSeen(t *testing.T) {
	now := testNow
	m := newTestModel(t, deps{now: func() time.Time { return now }})
	reply := make(chan prompt.Choice, 1)
	m.Update(approvalMsg{
		request: prompt.Request{Host: "bedev", Subject: "op://A/B/c"},
		options: []prompt.MenuItem{{Label: "Yes, this secret — once", Choice: prompt.ChoiceAllowOnce}, {Label: "No", Choice: prompt.ChoiceDeny}},
		reply:   reply,
	})
	x, y := locate(t, m, "Yes, this secret — once")
	click(m, x, y)
	if m.approval == nil {
		t.Fatal("a click answered the approval the instant it appeared")
	}
	now = now.Add(time.Second)
	click(m, x, y)
	if m.approval != nil {
		t.Fatal("a click on an answer did not answer")
	}
	if got := <-reply; got != prompt.ChoiceAllowOnce {
		t.Errorf("the click answered %v", got)
	}
}

// A double click on a port opens its detail, the same as everywhere else, and
// the detail's first action is the browser.
func TestDoubleClickingAPortOpensItsDetail(t *testing.T) {
	var opened string
	m := newTestModel(t, deps{
		tunnels: newStub(row(3000, 3000, "node vite")),
		openURL: func(_ context.Context, url string) error { opened = url; return nil },
	})
	click(m, 5, m.listTop())
	click(m, 5, m.listTop())
	if !m.showDetail {
		t.Fatal("a double click did not open the detail")
	}
	bx, by := locate(t, m, "Open this port in a browser")
	click(m, bx, by)
	if opened != "http://127.0.0.1:3000" {
		t.Errorf("the detail's browser action opened %q", opened)
	}
}
