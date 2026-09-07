package tui

import (
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/ui"
)

// viewMenu is the popup behind `c`: this host's settings, and nothing else.
//
// Every option here changes what you look at, never what is forwarded or which
// secret is released — that separation is the point of the menu existing, since
// a "view" toggle that quietly opened a tunnel is exactly the surprise it was
// built to remove. Which is also why the items come from each service's own
// Configurable rather than being listed here: a service decides what of its
// presentation is adjustable, and a fourth service gets a row for free.
type viewMenu struct {
	open   bool
	cursor int
}

// menuItem is one row of the settings popup.
type menuItem struct {
	title string
	help  string
	// owner names the service the setting belongs to, empty for the ones the
	// interface owns itself.
	owner string
	// options is nil for a boolean, which renders as a checkbox.
	options []string
	get     func() string
	set     func(string)
}

// sortChoices are the orderings worth reaching without knowing that `s`
// cycles them.
var sortChoices = []string{"port", "recent", "traffic", "process"}

func (m *Model) menuItems() []menuItem {
	items := []menuItem{{
		title:   "Sort by",
		help:    "the order the tunnel table is listed in",
		options: sortChoices,
		get: func() string {
			if m.sortKey == SortAge {
				return "recent"
			}
			return m.sortKey.String()
		},
		set: func(v string) {
			m.sortKey = sortKeyNamed(v)
			m.savePrefs()
			m.reload()
		},
	}}

	// Whether a service runs at all is a per-host setting like any other, and
	// this is the popup people open looking for one. It stays on the Services
	// tab too: that tab is where the reason a service cannot run here is
	// written, which is what you want in front of you while switching it off.
	for _, svc := range m.d.services {
		meta := svc.Meta()
		items = append(items, menuItem{
			title: meta.Glyph + " " + meta.Title,
			help:  m.serviceHelp(meta.ID, meta.Short),
			owner: "services",
			get:   func() string { return strconv.FormatBool(m.serviceEnabled(meta.ID)) },
			set: func(v string) {
				if m.d.store == nil {
					return
				}
				m.d.store.SetEnabled(m.d.host, meta.ID, v == "true")
				m.reloadServices()
			},
		})
	}

	for _, svc := range m.d.services {
		cfg, ok := svc.(service.Configurable)
		if !ok {
			continue
		}
		title := svc.Meta().Title
		for _, s := range cfg.Settings() {
			items = append(items, menuItem{
				title:   s.Title,
				help:    s.Help,
				owner:   title,
				options: s.Options,
				get:     s.Get,
				set:     s.Set,
			})
		}
	}
	return items
}

// serviceHelp is the line under a service toggle: the reason it cannot run
// here if there is one, since that is what the user has to act on, and
// otherwise what it does plus when a change lands.
func (m *Model) serviceHelp(id, short string) string {
	if detail := m.svcState[id].detail; detail != "" {
		return detail
	}
	return short + " — a change applies from the next connection"
}

// activateMenuItem applies the row under the cursor: a boolean flips, a choice
// steps to the next option.
func (m *Model) activateMenuItem(i int) tea.Cmd { return m.stepMenuItem(i, 1) }

// stepMenuItem moves the row under the cursor by delta options. A boolean has
// only two states, so either direction flips it; a choice walks its list, which
// is why left exists at all — a four-option setting you overshot should not
// need three more presses to come back to.
func (m *Model) stepMenuItem(i, delta int) tea.Cmd {
	items := m.menuItems()
	if i < 0 || i >= len(items) {
		return nil
	}
	item := items[i]
	if len(item.options) == 0 {
		item.set(map[bool]string{true: "false", false: "true"}[item.get() == "true"])
	} else {
		at := 0
		for j, o := range item.options {
			if o == item.get() {
				at = j
				break
			}
		}
		next := (at + delta) % len(item.options)
		if next < 0 {
			next += len(item.options)
		}
		item.set(item.options[next])
	}
	// A service-owned setting was written through the service, so the model's
	// copy of the presentation settings is now the stale one.
	m.syncPrefs()
	m.reload()
	return nil
}

// syncPrefs re-reads the settings the tunnels service owns, after something
// other than the model has changed them.
func (m *Model) syncPrefs() {
	m.prefs = m.d.tunnels.ViewPrefs()
	m.sortKey = sortKeyNamed(m.prefs.Sort)
	m.reverse = m.prefs.Reverse
}

// savePrefs pushes the presentation settings back to the tunnels service,
// which persists them for this host.
func (m *Model) savePrefs() {
	m.prefs.Sort = m.sortKey.String()
	m.prefs.Reverse = m.reverse
	m.d.tunnels.SetViewPrefs(m.prefs)
}

// handleMenuKey routes a key press while the settings popup is open.
func (m *Model) handleMenuKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "c", "q":
		m.menu.open = false
		return nil
	case "up", "k":
		if m.menu.cursor > 0 {
			m.menu.cursor--
		}
		return nil
	case "down", "j":
		if m.menu.cursor < len(m.menuItems())-1 {
			m.menu.cursor++
		}
		return nil
	case " ", "enter", "right", "l":
		return m.stepMenuItem(m.menu.cursor, 1)
	case "left", "h":
		return m.stepMenuItem(m.menu.cursor, -1)
	}
	return nil
}

// menuRowAt maps a terminal row to a menu item, or -1 if the click missed one.
// The menu is centred, and each item occupies two rows: its own and the help
// line beneath it.
func (m *Model) menuRowAt(y int) int {
	lines := strings.Count(m.menuBox(), "\n") + 1
	top := max((m.height-lines)/2, 0)
	// Border, title, subtitle and the blank line beneath them.
	first := top + 4
	for i := range m.menuItems() {
		if y == first+i*2 {
			return i
		}
	}
	return -1
}

// menuBox renders the settings popup.
func (m *Model) menuBox() string {
	items := m.menuItems()

	var b strings.Builder
	b.WriteString(ui.Banner.Render("Settings") + ui.Muted.Render("  ·  remembered for "+m.d.host) + "\n")
	b.WriteString(ui.Muted.Render("what runs here, what is listed, and how — nothing releases a secret") + "\n\n")

	for i, item := range items {
		selected := i == m.menu.cursor

		var line string
		if len(item.options) == 0 {
			mark := " "
			if item.get() == "true" {
				mark = "×"
			}
			line = "[" + mark + "] " + pad(item.title, 22)
		} else {
			line = "    " + pad(item.title, 22)
			var opts []string
			for _, o := range item.options {
				if o == item.get() {
					opts = append(opts, ui.OK.Render("("+o+")"))
				} else {
					opts = append(opts, ui.Muted.Render(" "+o+" "))
				}
			}
			line += strings.Join(opts, " ")
		}

		if selected {
			b.WriteString(ui.Banner.Render("▸ ") + line)
		} else {
			b.WriteString("  " + line)
		}
		b.WriteString("\n")
		switch {
		case selected && item.help != "":
			b.WriteString("    " + ui.Muted.Render(item.help) + "\n")
		case selected && item.owner != "":
			b.WriteString("    " + ui.Muted.Render(item.owner) + "\n")
		default:
			b.WriteString("\n")
		}
	}

	b.WriteString(ui.Muted.Render("↑↓ move · ←→ change · esc close"))
	return m.boxOf(b.String())
}
