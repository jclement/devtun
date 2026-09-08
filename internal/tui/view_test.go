package tui

import (
	"fmt"
	"github.com/jclement/devtun/internal/ui"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/tunnels"
)

func TestKeyHelperNamesTheKeysTheModelMatchesOn(t *testing.T) {
	// The whole keyboard suite is worthless if the messages it sends are not
	// the ones a terminal would produce, so check the translation itself.
	for _, name := range []string{"x", "enter", "esc", "tab", "shift+tab", "ctrl+h", "/", "?", "G", "1"} {
		if got := key(name).String(); got != name {
			t.Errorf("key(%q) reports itself as %q", name, got)
		}
	}
}

func TestViewRendersTheTable(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(
		row(3000, 3000, "node vite"),
		row(8080, 9090, "python3 -m http.server"),
	)})
	view := plainView(m)

	for _, want := range []string{
		"devtun", "bedev", "Tunnels", "Activity", "Access", "Services", "Config",
		"LOCAL", "REMOTE", "PROCESS", "3000", "9090", "node vite", "connected", "2 fwd",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the view is missing %q:\n%s", want, view)
		}
	}
}

// Nothing may exceed the terminal width, on any tab, or the frame wraps and
// every column after the wrap is describing the wrong row.
func TestViewNeverExceedsTheTerminalWidth(t *testing.T) {
	rows := []tunnels.State{
		row(3000, 3000, "node /a/very/long/path/to/some/server.js --with --many --flags --indeed"),
		row(8080, 8080, strings.Repeat("x", 400)),
		skippedRow(5432, strings.Repeat("y", 200), tunnels.SkipHidden),
		// A bind error wraps onto a second line rather than being cut, which
		// is a second way for a row to be wider than the frame.
		errorRow(4000, "python3 -m http.server"),
	}
	secrets := &stubSecrets{rules: []authz.Rule{
		{Host: strings.Repeat("h", 90), Subject: "op://" + strings.Repeat("v", 200), Action: authz.ActionAllow, Note: strings.Repeat("n", 80)},
	}}
	services := []service.Service{stubService{meta: service.Meta{
		ID: "1password", Title: "1Password", Glyph: "🔒", Short: strings.Repeat("s", 200),
	}}}

	for _, width := range []int{40, 41, 60, 80, 100, 200} {
		for _, tb := range []tab{tabTunnels, tabActivity, tabAccess, tabServices, tabConfig} {
			stub := newStub(rows...)
			stub.prefs.ShowHidden = true
			m := newTestModel(t, deps{tunnels: stub, secrets: oneSource(secrets), services: services, store: newTestStore(t)})
			m.Update(tea.WindowSizeMsg{Width: width, Height: 20})
			m.tab = tb
			m.Update(eventMsg(event.Event{
				Time: testNow, Service: "1password", Class: event.Security, Kind: "allowed",
				Text: strings.Repeat("z", 300),
			}))
			m.move(1)

			// The overlays that can be over any tab, plus the Config tab's own
			// editor, which draws into the bottom border where an overlong
			// value would push the frame wider rather than wrap it.
			for _, overlay := range []string{"", "?", "enter"} {
				if overlay != "" {
					send(m, overlay)
				}
				if tb == tabConfig {
					m.editor, m.editorSetting = editorConfigValue, "hide.host"
					m.input.SetValue(strings.Repeat("9", 400))
				}
				for _, line := range strings.Split(m.frame(), "\n") {
					if w := ansi.StringWidth(line); w > width {
						t.Fatalf("tab %s at width %d (overlay %q): a line is %d cells wide:\n%q",
							tb, width, overlay, w, ansi.Strip(line))
					}
				}
				m.closeEditor()
				if overlay != "" {
					send(m, "esc")
				}
			}
		}
	}
}

func TestViewFillsExactlyTheTerminalHeight(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	for _, height := range []int{10, 20, 24, 50} {
		m.Update(tea.WindowSizeMsg{Width: 100, Height: height})
		if lines := strings.Count(m.frame(), "\n") + 1; lines != height {
			t.Errorf("the frame is %d lines in a %d-line terminal", lines, height)
		}
	}
}

// A window too small for the frame gets a sentence, not a sheared table: a
// broken table still looks like data.
func TestTooSmallTerminalSaysSoRatherThanShearing(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	for _, size := range [][2]int{{30, 24}, {100, 8}, {20, 5}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		view := plainView(m)
		if !strings.Contains(view, "devtun needs") {
			t.Errorf("at %dx%d there is no explanation:\n%s", size[0], size[1], view)
		}
		if strings.Contains(view, "LOCAL") {
			t.Errorf("at %dx%d the table was drawn anyway:\n%s", size[0], size[1], view)
		}
		for _, line := range strings.Split(m.frame(), "\n") {
			if w := ansi.StringWidth(line); w > size[0] {
				t.Errorf("at %dx%d a line is %d cells wide", size[0], size[1], w)
			}
		}
	}
}

func TestLANWarningOnlyForANonLoopbackBind(t *testing.T) {
	loopback := row(3000, 3000, "node")
	m := newTestModel(t, deps{tunnels: newStub(loopback)})
	if strings.Contains(plainView(m), "LAN EXPOSED") {
		t.Errorf("a loopback bind was reported as exposed:\n%s", plainView(m))
	}

	exposed := row(3000, 3000, "node")
	exposed.LocalAddr = "0.0.0.0"
	m = newTestModel(t, deps{tunnels: newStub(exposed)})
	if !strings.Contains(plainView(m), "LAN EXPOSED 0.0.0.0") {
		t.Errorf("a 0.0.0.0 bind was not called out:\n%s", plainView(m))
	}
}

// The warning has to survive a narrow terminal: it is the one part of the
// header that is not decoration.
func TestLANWarningSurvivesANarrowHeader(t *testing.T) {
	exposed := row(3000, 3000, "node")
	exposed.LocalAddr = "0.0.0.0"
	m := newTestModel(t, deps{tunnels: newStub(exposed)})
	m.Update(tea.WindowSizeMsg{Width: 44, Height: 20})
	if !strings.Contains(plainView(m), "LAN EXPOSED") {
		t.Errorf("the warning was dropped to fit:\n%s", plainView(m))
	}
}

// The ticker is the reason an approval cannot be missed while you are looking
// at another tab, so it shows the newest events and follows you across tabs.
// How many it shows scales with the window, so the test asks the model rather
// than hard-coding a number.
func TestTickerShowsTheMostRecentUnderEveryTab(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	// One event first: the pane has no height until it has something to show,
	// so asking for its height on an empty log correctly answers zero.
	m.Update(eventMsg(event.Event{
		Time: testNow, Service: "tunnels", Class: event.Network, Kind: "opened", Text: "seed",
	}))
	lines := m.tickerHeight()
	if lines < tickerMin {
		t.Fatalf("the test window is too short to have a ticker at all")
	}

	// One more than fits, so there is always an event that has scrolled out.
	var texts []string
	for i := 0; i <= lines; i++ {
		texts = append(texts, fmt.Sprintf("event-%d", i))
	}
	for i, text := range texts {
		m.Update(eventMsg(event.Event{
			Time: testNow.Add(time.Duration(i) * time.Second), Service: "tunnels",
			Class: event.Network, Kind: "opened", Text: text,
		}))
	}

	for _, tb := range []tab{tabTunnels, tabActivity, tabAccess, tabServices, tabConfig} {
		m.tab = tb
		view := plainView(m)
		for _, want := range texts[1:] {
			if !strings.Contains(view, want) {
				t.Errorf("tab %s: the ticker is missing %q:\n%s", tb, want, view)
			}
		}
		// The oldest has scrolled out. The activity tab lists everything, so
		// only the other three can assert its absence.
		if tb != tabActivity && strings.Contains(view, texts[0]) {
			t.Errorf("tab %s: the ticker kept one line too many:\n%s", tb, view)
		}
	}
}

// The ticker grows with the window and gives way entirely on a short one,
// where every line it takes is a port row you cannot see.
func TestTickerScalesWithTheWindowAndVanishesOnShortOnes(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	// The pane is not drawn over an empty log, so it needs something in it
	// before its height means anything.
	m.Update(eventMsg(event.Event{
		Time: testNow, Service: "tunnels", Class: event.Network, Kind: "opened", Text: "remote 3000",
	}))
	for _, tc := range []struct {
		height int
		want   int
	}{
		{height: 12, want: 0}, // the table needs every row it can get
		{height: 24, want: 5}, // a quarter of the frame
		{height: 60, want: tickerWant},
	} {
		m.Update(tea.WindowSizeMsg{Width: 100, Height: tc.height})
		if got := m.tickerHeight(); got != tc.want {
			t.Errorf("at %d lines the ticker wanted %d lines, got %d", tc.height, tc.want, got)
		}
	}
}

// Diagnostic events are dropped from the ticker for the same reason the log
// drops them without --verbose, but the activity tab still has them.
func TestTickerSkipsDiagnosticsAndTheActivityTabKeepsThem(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	m.Update(eventMsg(event.Event{Time: testNow, Service: "session", Class: event.Lifecycle, Text: "connected"}))
	m.Update(eventMsg(event.Event{Time: testNow, Service: "session", Class: event.Diagnostic, Text: "shim is current"}))

	if strings.Contains(plainView(m), "shim is current") {
		t.Errorf("a diagnostic reached the ticker:\n%s", plainView(m))
	}
	m.tab = tabActivity
	if !strings.Contains(plainView(m), "shim is current") {
		t.Errorf("the activity tab dropped a diagnostic:\n%s", plainView(m))
	}
}

// The ticker must render the way the log does, because the class colouring is
// what separates a secret leaving the vault from a port opening at a glance.
func TestTickerUsesTheSharedClassTreatment(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	m.Update(eventMsg(event.Event{
		Time: testNow, Service: "1password", Class: event.Security, Kind: "allowed",
		Text: "op://Personal/Docker/PAT allowed 5m",
	}))
	view := m.frame()
	if !strings.Contains(ansi.Strip(view), "🔒 op") {
		t.Errorf("the security glyph and short service name are missing:\n%s", ansi.Strip(view))
	}
	// The class style is applied to the service column, not just the glyph.
	styled := ansiStyleOf("op  ", view)
	if styled == "" {
		t.Errorf("the service column carries no styling:\n%q", view)
	}
}

// ansiStyleOf returns the escape sequence immediately preceding needle.
func ansiStyleOf(needle, s string) string {
	i := strings.Index(s, needle)
	if i <= 0 {
		return ""
	}
	j := strings.LastIndex(s[:i], "\x1b[")
	if j < 0 {
		return ""
	}
	return s[j:i]
}

// The layout at 80×24, which is the terminal most people actually have. The
// M column is the one that must survive the squeeze: it carries the ✕ that
// says which of these rows you hid, and it is a control rather than a readout.
func TestEightyColumnFrameKeepsTheModeColumn(t *testing.T) {
	hidden := skippedRow(5432, "postgres", tunnels.SkipHidden)
	stub := newStub(row(3000, 3000, "node vite"), hidden)
	stub.prefs.ShowHidden = true

	m := newTestModel(t, deps{tunnels: stub})
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})

	// The body used to start at the column header. It starts at the summary
	// strip now, so the header and the rows are each one line further down —
	// the assertion is about which columns survive 80 cells, not about where
	// the table begins.
	lines := strings.Split(bodyLines(m), "\n")
	header, hiddenRow := lines[1], lines[3]
	if !strings.Contains(header, " M ") {
		t.Errorf("the mode column was dropped at 80 columns:\n%s", header)
	}
	if !strings.Contains(hiddenRow, "✕") {
		t.Errorf("the hidden row is not marked:\n%s", hiddenRow)
	}
	// The column and the glyph have to line up, or the mark is on the wrong
	// row's control.
	var mode column
	for _, c := range m.columns() {
		if c.mode {
			mode = c
		}
	}
	// x is a terminal column and the line carries its left border, so the
	// column index and the rune index are the same thing.
	if got := []rune(hiddenRow)[mode.x]; got != '✕' {
		t.Errorf("the M cell at x=%d holds %q, not the hidden mark", mode.x, string(got))
	}
}

// A warning drawn at the same weight as "3 fwd" is one you have stopped seeing
// by the second day, so the whole top edge changes colour instead.
func TestLANExposureColoursTheWholeTopBorder(t *testing.T) {
	safeRow := row(3000, 3000, "node")
	safe := newTestModel(t, deps{tunnels: newStub(safeRow)})

	exposedRow := row(3000, 3000, "node")
	exposedRow.LocalAddr = "0.0.0.0"
	exposed := newTestModel(t, deps{tunnels: newStub(exposedRow)})

	safeTop := strings.Split(safe.frame(), "\n")[0]
	exposedTop := strings.Split(exposed.frame(), "\n")[0]

	if safeTop == exposedTop {
		t.Fatal("an exposed session's top border looks identical to a safe one")
	}
	if !strings.Contains(ansi.Strip(exposedTop), "LAN EXPOSED") {
		t.Errorf("the warning should still be named:\n%s", exposedTop)
	}
	// The edge itself, not just the label, has to carry the colour — that is
	// the difference between a chip and a border.
	if !strings.Contains(exposedTop, dangerSequence(t)) {
		t.Errorf("the top edge is not drawn in the danger colour:\n%q", exposedTop)
	}
	// And a loopback bind must not cry wolf.
	if strings.Contains(ansi.Strip(safeTop), "LAN EXPOSED") {
		t.Errorf("a loopback bind must not warn:\n%s", safeTop)
	}
}

// dangerSequence is the escape the danger style emits, so the test asserts on
// the real palette rather than a hard-coded colour.
func dangerSequence(t *testing.T) string {
	t.Helper()
	rendered := ui.Danger.Render("x")
	before, _, ok := strings.Cut(rendered, "x")
	if !ok || before == "" {
		t.Skip("the palette is not emitting colour in this environment")
	}
	return before
}

// borderWith drops an oversized label as a unit, so a toast a few characters
// past the frame width does not shrink — it vanishes. That failure is
// invisible: the user is simply never told anything, and on a narrow terminal
// it would happen to every long message.
func TestALongToastIsTruncatedNotDropped(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 24})

	long := strings.Repeat("this message is far too long for the footer ", 4)
	m.showToast(toastMsg{text: long})

	bottom := strings.Split(m.frame(), "\n")
	last := ansi.Strip(bottom[len(bottom)-1])

	if !strings.Contains(last, "this message") {
		t.Errorf("the toast vanished instead of being truncated:\n%s", last)
	}
	if w := ansi.StringWidth(last); w != 60 {
		t.Errorf("the border is %d cells wide, want 60", w)
	}
}

// The help box is chosen by measuring, not by a threshold. The threshold was
// 34 rows and the box it guarded was 48, so at every height in between — an
// ordinary 40-row terminal included — the help was clipped, and the line it
// clipped was the one saying how to close it.
func TestTheHelpAlwaysFitsAndSaysHowToClose(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	for _, size := range [][2]int{{80, 24}, {100, 30}, {120, 40}, {80, 40}, {90, 20}, {60, 16}, {160, 50}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m.showHelp = true

		view := plainView(m)
		if got := strings.Count(view, "\n") + 1; got != size[1] {
			t.Errorf("%dx%d: the frame is %d lines", size[0], size[1], got)
		}
		if !strings.Contains(view, "esc") {
			t.Errorf("%dx%d: the help does not say how to close it:\n%s", size[0], size[1], view)
		}
	}
}

// The narrow key bar dropped hints in order, so `? help` and `esc quit` were
// the first two to go — leaving a first-run user with nothing on screen saying
// how to learn the keyboard or how to get out.
func TestTheKeyBarKeepsHelpAndQuitLongest(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	for _, width := range []int{40, 45, 55, 70} {
		m.Update(tea.WindowSizeMsg{Width: width, Height: 24})
		bar := ansi.Strip(m.keyBar())
		if !strings.Contains(bar, "?") || !strings.Contains(bar, "esc") {
			t.Errorf("at %d columns the bar lost its way out: %q", width, bar)
		}
	}
}

// A security line is two cells of glyph and every other line is one, so
// without padding by the declared width the whole security class sat a column
// to the right — in the interface only, while the log file got it right.
func TestEveryEventLineStartsInTheSameColumn(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	for i, e := range []event.Event{
		{Time: testNow, Service: "tunnels", Class: event.Network, Kind: "opened", Text: "network"},
		{Time: testNow, Service: "1password", Class: event.Security, Kind: "asked", Text: "security"},
		{Time: testNow, Service: "ssh-agent", Class: event.Security, Kind: "signed", Text: "agent"},
	} {
		e.Time = testNow.Add(time.Duration(i) * time.Second)
		m.Update(eventMsg(e))
	}

	var starts []int
	for _, line := range strings.Split(plainView(m), "\n") {
		for _, text := range []string{"network", "security", "agent"} {
			if i := strings.Index(line, text); i >= 0 {
				starts = append(starts, i)
			}
		}
	}
	if len(starts) < 3 {
		t.Fatalf("expected three event lines, found %d:\n%s", len(starts), plainView(m))
	}
	for _, at := range starts[1:] {
		if at != starts[0] {
			t.Errorf("the event text starts at differing columns %v — the left margin wanders", starts)
			break
		}
	}
}

// An overlay wraps rather than truncating. At 60 columns the approval modal
// used to cut "caller details come from the remote box and are not ve" — the
// sentence saying the provenance is unverified.
func TestOverlaysWrapRatherThanTruncate(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 24})

	long := "this is a deliberately long sentence that will not fit inside a sixty column frame without being folded"
	box := ansi.Strip(m.boxOf(long))
	if strings.Contains(box, "…") {
		t.Errorf("the body was truncated rather than wrapped:\n%s", box)
	}
	if !strings.Contains(box, "folded") {
		t.Errorf("the end of the sentence was lost:\n%s", box)
	}
}
