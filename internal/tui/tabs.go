package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/ui"
)

// tab is one of the four views over the session. There is one screen and one
// connection; the tabs are four ways of looking at it, not four modes.
type tab int

const (
	tabTunnels tab = iota
	tabActivity
	tabSecrets
	tabServices
	tabCount
)

var tabTitles = [tabCount]string{"Tunnels", "Activity", "Secrets", "Services"}

// String names the tab, for toasts and for the help box.
func (t tab) String() string {
	if t < 0 || t >= tabCount {
		return ""
	}
	return tabTitles[t]
}

// next steps to the following tab, wrapping.
func (t tab) next(delta int) tab {
	n := (int(t) + delta) % int(tabCount)
	if n < 0 {
		n += int(tabCount)
	}
	return tab(n)
}

// tabBar renders the row under the header and records where each tab landed,
// so a click selects the tab the user actually pointed at rather than one
// computed from a width that may since have changed.
func (m *Model) tabBar() string {
	var b strings.Builder
	m.tabZones = m.tabZones[:0]

	// The bar starts one cell in, past the left border.
	x := 1
	for i := tab(0); i < tabCount; i++ {
		if i > 0 {
			sep := ui.Muted.Render(" │")
			b.WriteString(sep)
			x += 2
		}
		marker, style := " ", ui.Muted
		if i == m.tab {
			marker, style = "▸", ui.Selected
		}
		label := marker + i.String() + " "
		b.WriteString(style.Render(label))
		m.tabZones = append(m.tabZones, zone{x0: x, x1: x + ansi.StringWidth(label), id: itoa(int(i))})
		x += ansi.StringWidth(label)
	}
	return b.String()
}

// tabAt returns the tab under a terminal x position on the tab row.
func (m *Model) tabAt(x int) (tab, bool) {
	for i, z := range m.tabZones {
		if z.contains(x) {
			return tab(i), true
		}
	}
	return 0, false
}
