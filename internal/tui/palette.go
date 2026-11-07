package tui

import (
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/ui"
)

// The command palette: `:` and then type what you want.
//
// devtun's keyboard is about twenty-five keys deep across five tabs, and the
// same letter deliberately means different things on different tabs — `r` is
// reverse-sort here and revoke there. That is fine for hands that know it and
// hostile to everyone else, and the honest answer to "the help is a wall of
// text" is not a shorter wall.
//
// So every action is listed once, in one place, with the tab it belongs to and
// the key that runs it. Searching it teaches the key as a side effect: you type
// "hide", you see `Tunnels · x`, and next time you press x. A palette that did
// not show the key would make itself permanent.
//
// Actions from other tabs are offered too, and switch tab before running —
// otherwise the palette is five palettes and you have to know which one you are
// in, which is the problem it exists to solve.

// action is one thing devtun can be asked to do.
//
// The same catalogue feeds the palette, the row menu, the actions listed in a
// detail box, and the key bar. Four surfaces, one list: an action cannot be
// offered by the menu and missing from the palette, or advertised in the key
// bar while the menu says it is unavailable.
type action struct {
	// title is what you search for and read: a verb phrase, because the list
	// is a list of things to do.
	title string
	// short is the key bar's label for it. Empty keeps it off the key bar,
	// which has room for a handful of things and should spend it on those.
	short string
	// tab is where it lives, and where the palette switches to before running
	// it. tabCount means "anywhere".
	tab tab
	// key is the shortcut, shown so the palette teaches its way out of a job.
	key string
	// row marks an action on the selected row. Those make the row menu, and
	// they cannot run with nothing selected.
	row bool
	// run performs it. It is called after the tab switch.
	run func(*Model) tea.Cmd
	// when reports whether the action exists here at all. Nil means always.
	// An action that cannot work in this session is left out rather than
	// offered and refused.
	when func(*Model) bool
	// disabled says why the action cannot run on the selected row right now,
	// or "" when it can. Unlike when, it does not hide the action: knowing
	// that a global rule cannot be revoked *here*, and where it can be, is
	// worth a dimmed line.
	disabled func(*Model) string
	// alt are extra words that should find this action. A curated handful
	// beats fuzzy matching here: somebody looking for the hidden ports types
	// "hide", and "hidden" does not contain "hide". The words people reach for
	// are knowable, and guessing them is this list's job.
	alt string
}

// reason is why the action cannot run right now, or "".
func (a action) reason(m *Model) string {
	if a.row && !m.hasSelection() {
		return "pick a row first"
	}
	if a.disabled != nil {
		return a.disabled(m)
	}
	return ""
}

// palette is the state of the open palette.
type palette struct {
	open   bool
	cursor int
	// offset is the first match on screen. Opened from the header with
	// nothing typed, the palette is the whole menu, which is longer than a
	// short terminal.
	offset int
	// matches is recomputed on each keystroke, so the cursor indexes it rather
	// than the catalogue.
	matches []action
}

// actions is the whole catalogue. Adding a key to a tab and forgetting to add
// it here is the failure this file is meant to prevent, so there is a test that
// walks the tabs' key handlers and complains about anything missing.
func (m *Model) actions() []action {
	press := func(key string) func(*Model) tea.Cmd {
		return func(mm *Model) tea.Cmd { return mm.dispatch(key) }
	}
	return []action{
		{title: "Show this port in detail", short: "detail", tab: tabTunnels, key: "enter", row: true, run: press("enter")},
		{title: "Open this port in a browser", short: "browser", tab: tabTunnels, key: "b", row: true, run: press("b"), alt: "url launch web"},
		{title: "Copy this port's URL", tab: tabTunnels, key: "y", row: true, run: press("y"), alt: "yank clipboard link"},
		{title: "Hide this port", short: "hide", tab: tabTunnels, key: "x", row: true, run: press("x"), alt: "ignore skip unhide"},
		{title: "Forward always / auto / never", tab: tabTunnels, key: "a", row: true, run: press("a"), alt: "mode hide"},
		{title: "Say this port is http or https", tab: tabTunnels, key: "t", row: true, run: press("t")},
		{title: "Pin a local port number", tab: tabTunnels, key: "l", row: true, run: press("l")},
		{title: "Name this port", short: "name", tab: tabTunnels, key: "n", row: true, run: press("n")},
		{title: "Show the ports you have hidden", tab: tabTunnels, key: "H", run: press("H"), alt: "hide unhide reveal"},
		{title: "Pause forwarding new ports", tab: tabTunnels, key: "p", run: press("p"), alt: "stop freeze"},
		{title: "Sort the port table", short: "sort", tab: tabTunnels, key: "s", run: press("s")},
		{title: "Reverse the sort order", tab: tabTunnels, key: "r", run: press("r")},

		{title: "Show this event in full", short: "detail", tab: tabActivity, key: "enter", row: true, run: press("enter")},
		{title: "Copy this log line", short: "copy", tab: tabActivity, key: "y", row: true, run: press("y"), alt: "yank clipboard"},
		{title: "Filter the log by what it is about", short: "filter", tab: tabActivity, key: "f", run: press("f")},

		{title: "Show this rule or grant in detail", short: "detail", tab: tabAccess, key: "enter", row: true, run: press("enter"), alt: "why explain"},
		// "deny" is deliberately not among Revoke's words. It was, and `: deny`
		// then ran Revoke — on a deny row, deleting the very refusal you were
		// asking for.
		{title: "Revoke this rule or grant", short: "revoke", tab: tabAccess, key: "r", row: true, run: press("r"),
			disabled: func(mm *Model) string { return mm.revokeBlocked() }, alt: "remove delete undo take back"},
		{title: "Make this rule a deny", short: "deny", tab: tabAccess, key: "D", row: true, run: press("D"),
			disabled: func(mm *Model) string { return mm.denyBlocked() }, alt: "refuse block tighten never"},
		{title: "Copy the reference, never the secret", short: "copy", tab: tabAccess, key: "y", row: true, run: press("y"),
			disabled: func(mm *Model) string { return mm.copyBlocked() }, alt: "yank clipboard op://"},
		{title: "Forget the live grants — refusals stay", short: "forget", tab: tabAccess, key: "F", run: press("F"),
			disabled: func(mm *Model) string { return mm.forgetBlocked() }, alt: "lock revoke panic"},
		{title: "Clear the \"stop asking\" refusals", tab: tabAccess, key: "X", run: press("X"),
			disabled: func(mm *Model) string { return mm.refusalsBlocked() }, alt: "unrefuse forget refusals ask again"},

		{title: "Turn this service on or off here", short: "on/off", tab: tabServices, key: "e", row: true, run: press("e"), alt: "enable disable toggle 1password agent gpg browser"},

		{title: "Change this setting", short: "change", tab: tabConfig, key: "→", row: true, run: press("right"), alt: "prompt dialog approvals setting"},
		{title: "Edit this setting's value", tab: tabConfig, key: "enter", row: true, run: press("enter")},
		{title: "Edit for this host or for everywhere", short: "where", tab: tabConfig, key: "g", run: press("g")},

		{title: "Show the actions for this row", tab: tabCount, key: ".", run: func(mm *Model) tea.Cmd { return mm.openMenu() },
			when: func(mm *Model) bool { return mm.hasSelection() }, alt: "menu context more"},
		{title: "Search this tab", tab: tabCount, key: "/", run: func(mm *Model) tea.Cmd {
			mm.openSearch()
			return nil
		}, alt: "find filter"},
		{title: "Release the mouse, so the terminal can select text", tab: tabCount, key: "m",
			run:  func(mm *Model) tea.Cmd { return mm.toggleMouse() },
			when: func(mm *Model) bool { return !mm.mouseOff }, alt: "copy select drag"},
		{title: "Take the mouse back, so rows are clickable", tab: tabCount, key: "m",
			run:  func(mm *Model) tea.Cmd { return mm.toggleMouse() },
			when: func(mm *Model) bool { return mm.mouseOff }, alt: "click"},
		{
			title: "Open the web board, and copy its link",
			tab:   tabCount, key: "w",
			run:  func(mm *Model) tea.Cmd { return mm.openWeb() },
			when: func(mm *Model) bool { return mm.d.webURL != "" },
		},
		{title: "Reconnect now", tab: tabCount, key: "R", run: func(mm *Model) tea.Cmd { return mm.reconnect() }},
		{title: "Show every key", tab: tabCount, key: "?", run: func(mm *Model) tea.Cmd {
			mm.showHelp = true
			return nil
		}, alt: "help keys"},
		{title: "Quit", tab: tabCount, key: "esc", run: func(mm *Model) tea.Cmd { return mm.confirmQuit() }, alt: "exit leave"},
	}
}

// rowActions is the selected row's menu: every row action of this tab that
// exists in this session, unavailable ones included.
func (m *Model) rowActions() []action {
	var out []action
	for _, a := range m.actions() {
		if a.tab != m.tab || !a.row || (a.when != nil && !a.when(m)) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// hasSelection reports whether a row is highlighted on the current tab.
func (m *Model) hasSelection() bool {
	i := m.cursor()
	return i >= 0 && i < m.rowCount() && m.selectable(i)
}

// rowSummary names the selected row in a line, for the menu's title.
func (m *Model) rowSummary() string {
	i := m.cursor()
	switch m.tab {
	case tabTunnels:
		if s, ok := m.selectedRow(); ok {
			return "remote :" + itoa(s.RemotePort) + " " + displayProcess(s, "")
		}
	case tabActivity:
		if i >= 0 && i < len(m.logRows) {
			return firstLine(m.logRows[i].Text)
		}
	case tabAccess:
		if r, ok := m.selectedAccess(); ok {
			return r.label() + " " + r.subject()
		}
	case tabServices:
		if i >= 0 && i < len(m.svcRows) {
			return m.svcRows[i].meta.Title
		}
	case tabConfig:
		if s := m.selectedSetting(); s != nil {
			return s.Title
		}
	}
	return ""
}

// dispatch runs a tab's own key handler, so the palette and the key take the
// same path. Anything else would be a second implementation of every action,
// free to drift from the first.
func (m *Model) dispatch(key string) tea.Cmd {
	msg := tea.KeyPressMsg{Text: key}
	switch key {
	case "enter":
		msg = tea.KeyPressMsg{Code: tea.KeyEnter}
	case "right":
		msg = tea.KeyPressMsg{Code: tea.KeyRight}
	}
	switch m.tab {
	case tabActivity:
		return m.handleActivityKey(msg)
	case tabAccess:
		return m.handleAccessKey(msg)
	case tabServices:
		return m.handleServicesKey(msg)
	case tabConfig:
		cmd, _ := m.handleConfigKey(msg)
		return cmd
	default:
		return m.handleTunnelsKey(msg)
	}
}

// openPalette starts a command search.
func (m *Model) openPalette() {
	m.cmd.open = true
	m.cmd.cursor = 0
	m.editor = editorCommand
	m.input.Reset()
	m.refreshPalette()
}

// closePalette dismisses it without running anything.
func (m *Model) closePalette() {
	m.cmd = palette{}
	m.closeEditor()
}

// refreshPalette recomputes the matches for what has been typed.
//
// They are ranked, not filtered in catalogue order. Before, a word found only
// among an action's aliases tied with a word in another action's title, and
// whichever was declared first won — which is how `: deny` came to run Revoke.
// A title match now always beats an alias match, and with nothing typed the
// current tab's actions come first, so the palette opened from the header
// reads as this screen's menu.
func (m *Model) refreshPalette() {
	query := strings.TrimSpace(m.input.Value())
	type scored struct {
		act   action
		score int
		order int
	}
	var found []scored
	for i, act := range m.actions() {
		if act.when != nil && !act.when(m) {
			continue
		}
		score := paletteScore(act, query)
		if score == 0 {
			continue
		}
		// Within a score: this tab, then anywhere, then the other tabs.
		switch act.tab {
		case m.tab:
			score = score*4 + 3
		case tabCount:
			score = score*4 + 2
		default:
			score = score * 4
		}
		found = append(found, scored{act, score, i})
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].score > found[j].score })
	m.cmd.matches = m.cmd.matches[:0]
	for _, f := range found {
		m.cmd.matches = append(m.cmd.matches, f.act)
	}
	if m.cmd.cursor >= len(m.cmd.matches) {
		m.cmd.cursor = max(len(m.cmd.matches)-1, 0)
	}
	m.clampPalette()
}

// paletteScore ranks how well an action answers a query: 3 when every word is
// in the title, 2 when the title and tab name between them have every word, 1
// when it took the aliases, 0 for no match.
//
// The tab name is searched as well as the title, so "config" finds everything
// on the Config tab — which is what somebody who knows roughly where a thing
// lives, and not what it is called, will type.
func paletteScore(act action, query string) int {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return 1
	}
	all := func(hay string) bool {
		hay = strings.ToLower(hay)
		for _, w := range words {
			if !strings.Contains(hay, w) {
				return false
			}
		}
		return true
	}
	switch {
	case all(act.title):
		return 3
	case all(act.title + " " + act.tab.String()):
		return 2
	case all(act.title + " " + act.tab.String() + " " + act.alt):
		return 1
	}
	return 0
}

// paletteRoom is how many matches fit on screen.
func (m *Model) paletteRoom() int {
	// Borders, the input line, the gap under it, the gap and hint at the
	// bottom, and a frame row above and below.
	return max(m.height-8, 3)
}

// clampPalette keeps the cursor on screen.
func (m *Model) clampPalette() {
	room := m.paletteRoom()
	if m.cmd.cursor < m.cmd.offset {
		m.cmd.offset = m.cmd.cursor
	}
	if m.cmd.cursor >= m.cmd.offset+room {
		m.cmd.offset = m.cmd.cursor - room + 1
	}
	m.cmd.offset = min(max(m.cmd.offset, 0), max(len(m.cmd.matches)-room, 0))
}

// movePalette steps the palette's cursor.
func (m *Model) movePalette(delta int) {
	m.cmd.cursor = min(max(m.cmd.cursor+delta, 0), max(len(m.cmd.matches)-1, 0))
	m.clampPalette()
}

// handlePaletteKey routes a key while the palette is open.
func (m *Model) handlePaletteKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.closePalette()
		return nil
	case "up", "ctrl+p":
		m.movePalette(-1)
		return nil
	case "down", "ctrl+n":
		m.movePalette(1)
		return nil
	case "pgup":
		m.movePalette(-m.paletteRoom())
		return nil
	case "pgdown":
		m.movePalette(m.paletteRoom())
		return nil
	case "enter":
		return m.runPaletteChoice()
	}
	if m.input.Update(msg) {
		m.refreshPalette()
	}
	return nil
}

// runPaletteChoice switches to the action's tab and runs it.
//
// The tab switch happens first and is not undone: you asked for a thing that
// lives over there, so over there is where you now are — and the row it acted
// on is in front of you rather than on a screen you never saw.
func (m *Model) runPaletteChoice() tea.Cmd {
	if m.cmd.cursor < 0 || m.cmd.cursor >= len(m.cmd.matches) {
		m.closePalette()
		return nil
	}
	return m.runPaletteAction(m.cmd.matches[m.cmd.cursor])
}

// runPaletteAction closes the palette and runs one of its entries.
func (m *Model) runPaletteAction(act action) tea.Cmd {
	m.closePalette()
	if act.tab != tabCount && act.tab != m.tab {
		m.selectTab(act.tab)
	}
	// Checked after the switch: whether "revoke" can run depends on the row
	// selected over there, not on this tab's.
	if why := act.reason(m); why != "" {
		return m.showToast(toastMsg{text: why, bad: true})
	}
	return act.run(m)
}

// paletteBox renders the palette over the frame. Opened from the header with
// nothing typed, it is the global menu; typing narrows it.
func (m *Model) paletteBox() string {
	var b strings.Builder
	b.WriteString(ui.Banner.Render(":") + " " + m.input.Render() + "\n")

	if len(m.cmd.matches) == 0 {
		b.WriteString("\n" + ui.Muted.Render("nothing matches") + "\n")
	} else {
		b.WriteString("\n")
	}
	end := min(m.cmd.offset+m.paletteRoom(), len(m.cmd.matches))
	// As wide as the longest title on screen, so no title is cut and the
	// columns after it still line up.
	titleW := 0
	for i := m.cmd.offset; i < end; i++ {
		titleW = max(titleW, ansi.StringWidth(m.cmd.matches[i].title)+2)
	}
	titleW = min(titleW, max(m.width-24, 20))
	for i := m.cmd.offset; i < end; i++ {
		act := m.cmd.matches[i]
		where := act.tab.String()
		if act.tab == tabCount {
			where = "anywhere"
		}
		title := pad(act.title, titleW)
		if why := act.reason(m); why != "" && act.tab == m.tab {
			// Dimmed, not hidden: it exists, it just cannot run on this row.
			title = ui.Muted.Render(title)
		}
		line := title + ui.Muted.Render(pad(where, 10)+displayKey(act.key))
		if i == m.cmd.cursor {
			b.WriteString(ui.Banner.Render("▸ ") + line + "\n")
			continue
		}
		b.WriteString("  " + line + "\n")
	}
	hint := "↑↓ choose · enter or click runs it · esc close"
	if len(m.cmd.matches) > m.paletteRoom() {
		hint = itoa(m.cmd.offset+1) + "–" + itoa(end) + " of " + itoa(len(m.cmd.matches)) + " · type to narrow · " + hint
	}
	b.WriteString("\n" + ui.Muted.Render(hint))
	return m.boxOf(b.String())
}

// paletteButtons makes every visible entry a click target.
func (m *Model) paletteButtons() []button {
	var out []button
	end := min(m.cmd.offset+m.paletteRoom(), len(m.cmd.matches))
	for i := m.cmd.offset; i < end; i++ {
		out = append(out, button{needle: m.cmd.matches[i].title, id: itoa(i), wide: true})
	}
	return out
}
