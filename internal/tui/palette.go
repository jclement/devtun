package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"

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

// paletteLimit is how many matches are listed. Beyond about a dozen nobody is
// reading, they are typing more.
const paletteLimit = 12

// action is one thing devtun can be asked to do.
type action struct {
	// title is what you search for and read: a verb phrase, because the list
	// is a list of things to do.
	title string
	// tab is where it lives, and where the palette switches to before running
	// it. tabCount means "anywhere".
	tab tab
	// key is the shortcut, shown so the palette teaches its way out of a job.
	key string
	// run performs it. It is called after the tab switch.
	run func(*Model) tea.Cmd
	// when reports whether the action applies right now. Nil means always.
	// An action that cannot work is left out rather than offered and refused.
	when func(*Model) bool
	// alt are extra words that should find this action. A curated handful
	// beats fuzzy matching here: somebody looking for the hidden ports types
	// "hide", and "hidden" does not contain "hide". The words people reach for
	// are knowable, and guessing them is this list's job.
	alt string
}

// palette is the state of the open palette.
type palette struct {
	open   bool
	cursor int
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
		{title: "Hide this port", tab: tabTunnels, key: "x", run: press("x"), alt: "ignore skip"},
		{title: "Show the ports you have hidden", tab: tabTunnels, key: "H", run: press("H"), alt: "hide unhide reveal"},
		{title: "Forward always / auto / never", tab: tabTunnels, key: "a", run: press("a"), alt: "mode hide"},
		{title: "Open this port in a browser", tab: tabTunnels, key: "b", run: press("b"), alt: "url launch web"},
		{title: "Copy this port's URL", tab: tabTunnels, key: "y", run: press("y"), alt: "yank clipboard link"},
		{title: "Say this port is http or https", tab: tabTunnels, key: "t", run: press("t")},
		{title: "Pin a local port number", tab: tabTunnels, key: "l", run: press("l")},
		{title: "Name this port", tab: tabTunnels, key: "n", run: press("n")},
		{title: "Pause forwarding new ports", tab: tabTunnels, key: "p", run: press("p"), alt: "stop freeze"},
		{title: "Sort the port table", tab: tabTunnels, key: "s", run: press("s")},
		{title: "Reverse the sort order", tab: tabTunnels, key: "r", run: press("r")},
		{title: "Show this port in detail", tab: tabTunnels, key: "enter", run: press("enter")},

		{title: "Filter the log by what it is about", tab: tabActivity, key: "f", run: press("f")},
		{title: "Copy this log line", tab: tabActivity, key: "y", run: press("y"), alt: "yank clipboard"},
		{title: "Show this event in full", tab: tabActivity, key: "enter", run: press("enter")},

		{title: "Revoke this rule or grant", tab: tabAccess, key: "r", run: press("r"), alt: "remove delete deny access"},
		{title: "Turn this rule into a refusal", tab: tabAccess, key: "D", run: press("D"), alt: "deny block"},
		{title: "Copy this secret's reference", tab: tabAccess, key: "y", run: press("y"), alt: "yank clipboard op://"},
		{title: "Forget every live grant", tab: tabAccess, key: "F", run: press("F"), alt: "lock revoke panic"},

		{title: "Turn this service on or off here", tab: tabServices, key: "e", run: press("e"), alt: "enable disable toggle 1password agent gpg browser"},

		{title: "Change this setting", tab: tabConfig, key: "→", run: press("right"), alt: "prompt dialog approvals setting"},
		{title: "Edit this setting's value", tab: tabConfig, key: "enter", run: press("enter")},
		{title: "Edit for this host or for everywhere", tab: tabConfig, key: "g", run: press("g")},

		{title: "Search this tab", tab: tabCount, key: "/", run: func(mm *Model) tea.Cmd {
			mm.openSearch()
			return nil
		}},
		{title: "Reconnect now", tab: tabCount, key: "R", run: func(mm *Model) tea.Cmd { return mm.reconnect() }},
		{
			title: "Open the web board, and copy its link",
			tab:   tabCount, key: "w",
			run:  func(mm *Model) tea.Cmd { return mm.openWeb() },
			when: func(mm *Model) bool { return mm.d.webURL != "" },
		},
		{title: "Release the mouse, so the terminal can select text", tab: tabCount, key: "m",
			run: func(mm *Model) tea.Cmd {
				mm.mouseOff = true
				return mm.showToast(toastMsg{text: "mouse off — the terminal can select text again; m to switch back"})
			},
			when: func(mm *Model) bool { return !mm.mouseOff }},
		{title: "Take the mouse back, so rows are clickable", tab: tabCount, key: "m",
			run: func(mm *Model) tea.Cmd {
				mm.mouseOff = false
				return mm.showToast(toastMsg{text: "mouse on — rows and tabs are clickable"})
			},
			when: func(mm *Model) bool { return mm.mouseOff }},
		{title: "Show every key", tab: tabCount, key: "?", run: func(mm *Model) tea.Cmd {
			mm.showHelp = true
			return nil
		}},
		{title: "Quit", tab: tabCount, key: "esc", run: func(mm *Model) tea.Cmd {
			mm.confirming = true
			return nil
		}},
	}
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
func (m *Model) refreshPalette() {
	query := strings.TrimSpace(m.input.Value())
	m.cmd.matches = m.cmd.matches[:0]
	for _, act := range m.actions() {
		if act.when != nil && !act.when(m) {
			continue
		}
		if !paletteMatches(act, query) {
			continue
		}
		m.cmd.matches = append(m.cmd.matches, act)
		if len(m.cmd.matches) >= paletteLimit {
			break
		}
	}
	if m.cmd.cursor >= len(m.cmd.matches) {
		m.cmd.cursor = max(len(m.cmd.matches)-1, 0)
	}
}

// paletteMatches decides whether an action answers a query.
//
// The tab name is searched as well as the title, so "config" finds everything
// on the Config tab — which is what somebody who knows roughly where a thing
// lives, and not what it is called, will type.
func paletteMatches(act action, query string) bool {
	if query == "" {
		return true
	}
	hay := strings.ToLower(act.title + " " + act.tab.String() + " " + act.alt)
	for _, word := range strings.Fields(strings.ToLower(query)) {
		if !strings.Contains(hay, word) {
			return false
		}
	}
	return true
}

// handlePaletteKey routes a key while the palette is open.
func (m *Model) handlePaletteKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.closePalette()
		return nil
	case "up", "ctrl+p":
		if m.cmd.cursor > 0 {
			m.cmd.cursor--
		}
		return nil
	case "down", "ctrl+n":
		if m.cmd.cursor < len(m.cmd.matches)-1 {
			m.cmd.cursor++
		}
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
	act := m.cmd.matches[m.cmd.cursor]
	m.closePalette()

	if act.tab != tabCount && act.tab != m.tab {
		m.selectTab(act.tab)
	}
	return act.run(m)
}

// paletteBox renders the palette over the frame.
func (m *Model) paletteBox() string {
	var b strings.Builder
	b.WriteString(ui.Banner.Render(":") + " " + m.input.Render() + "\n")

	if len(m.cmd.matches) == 0 {
		b.WriteString("\n" + ui.Muted.Render("nothing matches") + "\n")
	}
	for i, act := range m.cmd.matches {
		where := act.tab.String()
		if act.tab == tabCount {
			where = "anywhere"
		}
		line := pad(act.title, 46) + ui.Muted.Render(pad(where, 10)+act.key)
		if i == m.cmd.cursor {
			b.WriteString(ui.Banner.Render("▸ ") + line + "\n")
			continue
		}
		b.WriteString("  " + line + "\n")
	}

	b.WriteString("\n" + ui.Muted.Render("↑↓ choose · enter run · esc close"))
	return m.boxOf(b.String())
}
