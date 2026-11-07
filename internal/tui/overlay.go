package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/ui"
)

// The overlays — confirms, the row menu, the detail boxes — are drawn as
// strings and composited over the frame, so they have no widgets and no
// layout tree to ask "what is under the pointer". What they do have is text.
//
// A clickable thing in an overlay is therefore named by a piece of its own
// label: the box is rendered, placed exactly where overlayCenter will place
// it, and the label is looked for line by line. That keeps the click and the
// drawing on one path — a button that moved because a line above it wrapped
// is still found, because it is found where it was drawn, not where some
// second calculation thinks it should be.

// button is one clickable control inside an overlay box.
type button struct {
	// needle is text that appears on exactly one line of the box. A click on
	// that run of cells — or anywhere on the line, when wide is set — hits.
	needle string
	id     string
	// wide makes the whole line the target. Menu entries want this: aiming at
	// the word rather than the row is a precision a list does not need.
	wide bool
}

// hitButton reports which of a box's buttons sits under a terminal cell.
func (m *Model) hitButton(box string, buttons []button, x, y int) (string, bool) {
	if box == "" {
		return "", false
	}
	lines := strings.Split(box, "\n")
	boxW := 0
	for _, l := range lines {
		boxW = max(boxW, ansi.StringWidth(l))
	}
	left := max((m.width-boxW)/2, 0)
	top := max((m.height-len(lines))/2, 0)
	row := y - top
	if row < 0 || row >= len(lines) || x < left || x >= left+boxW {
		return "", false
	}
	plain := ansi.Strip(lines[row])
	for _, b := range buttons {
		at := strings.Index(plain, b.needle)
		if at < 0 {
			continue
		}
		if b.wide {
			return b.id, true
		}
		x0 := left + ansi.StringWidth(plain[:at])
		if x >= x0 && x < x0+ansi.StringWidth(b.needle) {
			return b.id, true
		}
	}
	return "", false
}

// insideBox reports whether a cell falls within an overlay box at all, so a
// click on its padding is not mistaken for a click outside it.
func (m *Model) insideBox(box string, x, y int) bool {
	lines := strings.Split(box, "\n")
	boxW := 0
	for _, l := range lines {
		boxW = max(boxW, ansi.StringWidth(l))
	}
	left := max((m.width-boxW)/2, 0)
	top := max((m.height-len(lines))/2, 0)
	return y >= top && y < top+len(lines) && x >= left && x < left+boxW
}

// chip renders a key and a label as one pressable control.
func chip(key, label string, danger bool) string {
	style := ui.Button
	if danger {
		style = ui.DangerButton
	}
	return style.Render(" " + key + "  " + label + " ")
}

// --- confirm ---------------------------------------------------------------

// confirmState is a question that has to be answered before anything happens.
//
// One shape for every confirm, because the rule they enforce is one rule: a
// keystroke that loosens access, or throws state away, names what it will
// change and waits for a deliberate yes. The quit question is the same kind of
// thing and goes through the same box.
type confirmState struct {
	title string
	// body is already styled, one line per entry: what is affected, then what
	// happens next. Saying the consequence is the point — "are you sure?" with
	// no consequence is a box people learn to press y through.
	body []string
	yes  string
	no   string
	// danger paints the yes button red: it loosens or discards.
	danger bool
	// enterIsYes lets enter accept. Only for the quit question, which has
	// always taken enter; a loosening confirm needs the y, so a reflexive
	// enter — the key that dismisses everything else — cannot loosen.
	enterIsYes bool
	run        func(*Model) tea.Cmd
}

// ask puts a confirm on screen, closing whatever lighter overlay it replaces.
func (m *Model) ask(c confirmState) tea.Cmd {
	m.showDetail, m.showHelp = false, false
	m.menu = nil
	m.confirm = &c
	return nil
}

func (m *Model) confirmBox() string {
	c := m.confirm
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(ui.Banner.Render(c.title) + "\n")
	if len(c.body) > 0 {
		b.WriteString("\n")
	}
	for _, line := range c.body {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n" + chip("y", c.yes, c.danger) + "   " + chip("n", c.no, false))
	return m.boxOf(b.String())
}

func (m *Model) confirmButtons() []button {
	if m.confirm == nil {
		return nil
	}
	return []button{
		{needle: " y  " + m.confirm.yes + " ", id: "y"},
		{needle: " n  " + m.confirm.no + " ", id: "n"},
	}
}

func (m *Model) handleConfirmKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "y", "Y":
		return m.acceptConfirm()
	case "enter":
		if m.confirm.enterIsYes {
			return m.acceptConfirm()
		}
	case "n", "N", "esc", "q", "ctrl+c":
		m.confirm = nil
	}
	return nil
}

// acceptConfirm runs what the confirm was guarding.
func (m *Model) acceptConfirm() tea.Cmd {
	c := m.confirm
	m.confirm = nil
	if c == nil || c.run == nil {
		return nil
	}
	return c.run(m)
}

// confirmQuit is the question esc and q ask.
func (m *Model) confirmQuit() tea.Cmd {
	return m.ask(confirmState{
		title:      "Close everything and quit?",
		body:       []string{ui.Muted.Render("Local ports are released and every live grant is dropped.")},
		yes:        "quit",
		no:         "keep running",
		enterIsYes: true,
		run:        func(mm *Model) tea.Cmd { return mm.beginQuit() },
	})
}

// --- the row menu ----------------------------------------------------------

// menuState is the action menu for the selected row: every action the row
// has, with its key, and the ones that cannot run right now shown dimmed with
// the reason.
//
// The reason is the whole point. "That rule came from your config file" used
// to be a toast you got *after* pressing r; listed here, it is something you
// read before you reach for the key.
type menuState struct {
	title  string
	items  []action
	cursor int
}

// openMenu opens the action menu for the selected row.
func (m *Model) openMenu() tea.Cmd {
	if !m.hasSelection() {
		return m.needSelection()
	}
	items := m.rowActions()
	if len(items) == 0 {
		return nil
	}
	m.showDetail = false
	m.menu = &menuState{title: m.rowSummary(), items: items}
	// Start on the first thing that can actually run.
	for i, it := range items {
		if it.reason(m) == "" {
			m.menu.cursor = i
			break
		}
	}
	return nil
}

func (m *Model) menuBox() string {
	if m.menu == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(ui.Banner.Render("actions") + ui.Muted.Render(" · ") + clampWidth(m.menu.title, max(m.width-20, 10)) + "\n\n")
	b.WriteString(m.actionList(m.menu.items, m.menu.cursor))
	b.WriteString("\n" + ui.Muted.Render("↑↓ choose · enter or the key runs it · esc close"))
	return m.boxOf(b.String())
}

// actionList renders actions one per line: a cursor, the key, the title, and
// for an action that cannot run, why not. The detail boxes and the menu share
// it, so an action reads the same wherever it is offered.
func (m *Model) actionList(items []action, cursor int) string {
	var b strings.Builder
	for i, it := range items {
		lead := "  "
		if i == cursor {
			lead = ui.Banner.Render("▸ ")
		}
		k := pad(displayKey(it.key), 6)
		if why := it.reason(m); why != "" {
			b.WriteString(lead + ui.Muted.Render(k+it.title+"  — "+why) + "\n")
			continue
		}
		title := it.title
		if i == cursor {
			title = ui.Selected.Render(title)
		}
		b.WriteString(lead + ui.Banner.Render(k) + title + "\n")
	}
	return b.String()
}

// actionButtons makes every listed action a whole-line click target.
func actionButtons(items []action) []button {
	out := make([]button, 0, len(items))
	for _, it := range items {
		out = append(out, button{needle: pad(displayKey(it.key), 6) + it.title, id: it.key, wide: true})
	}
	return out
}

// displayKey is how a key reads in a list. The palette dispatches "right" and
// "enter" by name; people read arrows.
func displayKey(k string) string {
	switch k {
	case "right":
		return "→"
	}
	return k
}

func (m *Model) handleMenuKey(msg tea.KeyPressMsg) tea.Cmd {
	mu := m.menu
	switch msg.String() {
	case "esc", "q", "ctrl+c", ".":
		m.menu = nil
		return nil
	case "up", "k":
		if mu.cursor > 0 {
			mu.cursor--
		}
		return nil
	case "down", "j":
		if mu.cursor < len(mu.items)-1 {
			mu.cursor++
		}
		return nil
	case "enter":
		if mu.cursor >= 0 && mu.cursor < len(mu.items) {
			return m.runMenuItem(mu.items[mu.cursor])
		}
		return nil
	}
	for _, it := range mu.items {
		if it.key == msg.String() {
			return m.runMenuItem(it)
		}
	}
	return nil
}

// runMenuItem closes the menu and runs the action — or, when it cannot run,
// says why and leaves the menu where it was.
func (m *Model) runMenuItem(it action) tea.Cmd {
	if why := it.reason(m); why != "" {
		return m.showToast(toastMsg{text: why, bad: true})
	}
	m.menu = nil
	return it.run(m)
}

// --- scrolling a tall overlay ----------------------------------------------

// scrollBody fits an overlay's text to the window by showing a slice of it,
// with a line at either end saying how much is above and below.
//
// The alternative is overlayCenter's clipping, which keeps the top of a tall
// box and silently loses the bottom — and the bottom is where the actions
// and the line saying how to close it live.
func (m *Model) scrollBody(body string, offset *int) string {
	lines := strings.Split(m.wrapBody(body), "\n")
	// Two border rows, and a row of frame above and below so it still reads
	// as an overlay.
	room := m.height - 4
	if room < 3 || len(lines) <= room {
		*offset = 0
		return strings.Join(lines, "\n")
	}
	view := room - 2 // the two indicator lines
	*offset = min(max(*offset, 0), len(lines)-view)
	above, below := *offset, len(lines)-*offset-view
	out := make([]string, 0, room)
	out = append(out, ui.Muted.Render(moreLine("↑", above)))
	out = append(out, lines[*offset:*offset+view]...)
	out = append(out, ui.Muted.Render(moreLine("↓", below)))
	return strings.Join(out, "\n")
}

func moreLine(arrow string, n int) string {
	if n <= 0 {
		return ""
	}
	return arrow + " " + itoa(n) + " more line" + plural(n) + " — wheel or pgup/pgdn"
}
