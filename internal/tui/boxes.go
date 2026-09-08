package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/ui"
)

// detailBox is whatever the active tab has to say about the selected row.
func (m *Model) detailBox() string {
	switch m.tab {
	case tabActivity:
		return m.activityDetailBox()
	case tabTunnels:
		return m.tunnelDetailBox()
	default:
		return ""
	}
}

func (m *Model) confirmBox() string {
	body := ui.Banner.Render("Close everything and quit?") + "\n\n" +
		ui.Muted.Render("Local ports are released and every live grant is dropped.") + "\n\n" +
		ui.Banner.Render("y") + ui.Muted.Render(" yes") + ui.Muted.Render("   ·   ") +
		ui.Banner.Render("n") + ui.Muted.Render(" keep running")
	return m.boxOf(body)
}

// helpBox lists the whole keyboard surface, grouped by what it acts on.
//
// Which layout it uses is decided by measuring, not by a threshold. The
// threshold was 34 rows and the box it guarded was 48, so at every height from
// 34 to 47 — which includes an ordinary 40-row terminal — the help was clipped,
// and the line it clipped was "? or esc to close". The help did not say how to
// dismiss the help.
func (m *Model) helpBox() string {
	// The box carries its own border, so the only reservation is one frame row
	// above and below — enough that it reads as an overlay rather than as a
	// replacement for the screen.
	room := m.height - 2
	for _, layout := range []func() string{m.wideHelpBox, m.tallHelpBox, m.compactHelpBox, m.tinyHelpBox} {
		box := layout()
		if strings.Count(box, "\n")+1 <= room {
			return box
		}
	}
	return m.tinyHelpBox()
}

// tinyHelpBox is for a window too short for even the compact list: the keys
// somebody stuck in a twenty-row terminal actually needs, and — first, so that
// it survives any clipping — how to get out of this box.
func (m *Model) tinyHelpBox() string {
	var b strings.Builder
	b.WriteString(ui.Banner.Render("? or esc") + ui.Muted.Render(" closes this") + "\n\n")
	for _, k := range [][2]string{
		{"tab, ← →", "switch tab"},
		{"↑↓ / j k", "move"},
		{"x · H", "hide a port · list hidden"},
		{"b · y", "browser · copy"},
		{"c · /", "settings · search"},
		{":", "every action, by name"},
		{"m", "mouse off, to select text"},
		{"esc, q", "quit"},
	} {
		b.WriteString("  " + ui.Banner.Render(pad(k[0], 10)) + ui.Muted.Render(k[1]) + "\n")
	}
	b.WriteString(ui.Muted.Render("a taller window shows the rest"))
	return m.boxOf(b.String())
}

// helpSections is the whole keyboard surface, in one place so the layouts
// cannot disagree about what the keys are — which is exactly how the compact
// box came to be missing three of them.
func (m *Model) helpSections() []struct {
	title string
	keys  [][2]string
} {
	sections := []struct {
		title string
		keys  [][2]string
	}{
		{"everywhere", [][2]string{
			{"tab, ← →, 1-5", "switch tab"},
			{"↑ ↓ / j k", "move"},
			{"g / G", "first / last"},
			{"/", "search this tab"},
			{":", "the command palette — every action, by name"},
			{"c", "the Config tab"},
			{"w", "open the web board here, and copy its URL"},
			{"m", "mouse off — lets the terminal select and copy text"},
			{"R", "reconnect now"},
			{"esc, q", "quit (asks first)"},
			{"ctrl+c", "quit immediately"},
		}},
		{"a port", [][2]string{
			{"enter, d", "detail"},
			{"x", "hide this port (remembered)"},
			{"H", "list the ports you hid, so x can unhide one"},
			{"a", "auto → on → hidden (remembered)"},
			{"t", "say http or https (remembered)"},
			{"b, o, space", "open in browser — asks HTTP/HTTPS when needed"},
			{"l", "set the local port (remembered)"},
			{"n", "name this port (remembered)"},
			{"y", "copy URL, or host:port for raw TCP"},
			{"s / r", "cycle sort / reverse"},
			{"p", "pause new automatic tunnels; current ones stay up"},
		}},
		{"activity", [][2]string{
			{"f", "filter: all → security → network → lifecycle"},
			{"enter", "the event in full, fields included"},
			{"y", "copy the line"},
		}},
		{"access — rules and live grants", [][2]string{
			{"r", "revoke the selected rule or grant"},
			{"D", "rewrite the selected allow rule as a deny"},
			{"y", "copy the op:// reference — never the secret"},
			{"F", "forget every live grant and cached value"},
		}},
		{"services", [][2]string{
			{"e", "on or off for this host, from the next connection"},
		}},
		{"config — the value, and which file said so", [][2]string{
			{"← →, space", "change the setting under the cursor"},
			{"enter", "change it, or open the editor for a list"},
			{"g", "aim edits at this host or at every host"},
		}},
		{"mouse", [][2]string{
			{"click", "select a row, or a tab, or a key bar action"},
			{"double click", "open in browser"},
			{"click M / VIA", "cycle mode / protocol"},
			{"click header", "sort by that column"},
		}},
	}

	return sections
}

// tallHelpBox is one column: every section, one under the other.
func (m *Model) tallHelpBox() string {
	var b strings.Builder
	b.WriteString(ui.Banner.Render("devtun " + m.d.version))
	b.WriteString("\n")
	for _, sec := range m.helpSections() {
		b.WriteString("\n" + ui.Muted.Render(sec.title) + "\n")
		for _, k := range sec.keys {
			b.WriteString("  " + ui.Banner.Render(pad(k[0], 14)) + ui.Muted.Render(k[1]) + "\n")
		}
	}
	b.WriteString("\n" + ui.Muted.Render("? or esc to close"))
	return m.boxOf(b.String())
}

// wideHelpBox is the same content in two columns, which is what makes the whole
// keyboard fit on a normal terminal without abbreviating any of it.
func (m *Model) wideHelpBox() string {
	const columnWidth = 46
	if m.width < columnWidth*2+8 {
		// Two columns in a narrow frame is worse than one; say so by failing
		// the fit test rather than rendering something cramped.
		return strings.Repeat("\n", m.height+1)
	}

	sections := m.helpSections()
	var left, right []string
	// Split by rendered height rather than by count, so a long section does
	// not leave one column twice the length of the other.
	total := 0
	for _, sec := range sections {
		total += len(sec.keys) + 2
	}
	used := 0
	for _, sec := range sections {
		lines := []string{ui.Muted.Render(sec.title)}
		for _, k := range sec.keys {
			lines = append(lines, "  "+ui.Banner.Render(pad(k[0], 13))+ui.Muted.Render(k[1]))
		}
		lines = append(lines, "")
		if used*2 < total {
			left = append(left, lines...)
		} else {
			right = append(right, lines...)
		}
		used += len(sec.keys) + 2
	}

	var b strings.Builder
	b.WriteString(ui.Banner.Render("devtun "+m.d.version) + "\n\n")
	for i := 0; i < max(len(left), len(right)); i++ {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if w := ansi.StringWidth(l); w < columnWidth {
			l += strings.Repeat(" ", columnWidth-w)
		}
		b.WriteString(strings.TrimRight(l+r, " ") + "\n")
	}
	b.WriteString(ui.Muted.Render("? or esc to close"))
	return m.boxOf(b.String())
}

// compactHelpBox keeps the whole keyboard surface visible in the common 80×24
// terminal instead of rendering a tall popup whose lower half is clipped.
func (m *Model) compactHelpBox() string {
	row := func(keys, desc string) string {
		return "  " + ui.Banner.Render(pad(keys, 13)) + ui.Muted.Render(desc) + "\n"
	}
	var b strings.Builder
	b.WriteString(ui.Banner.Render("devtun "+m.d.version) + "\n")
	b.WriteString(ui.Muted.Render("everywhere") + "\n")
	b.WriteString(row("tab, ←→, 1-5", "switch tab"))
	b.WriteString(row("↑↓ / j k / gG", "move / first / last"))
	b.WriteString(row(": · /", "every action by name · search this tab"))
	b.WriteString(row("c · w", "Config tab · web board"))
	b.WriteString(row("m · R", "mouse off (select text) · reconnect"))
	b.WriteString(ui.Muted.Render("a port") + "\n")
	b.WriteString(row("enter, d", "detail"))
	b.WriteString(row("x · H", "hide · list hidden"))
	b.WriteString(row("a · t", "auto/on/hidden · http/https"))
	b.WriteString(row("b, o, space · y", "open in browser · copy"))
	b.WriteString(row("l · n", "local port · name"))
	b.WriteString(row("s / r · p", "sort / reverse · pause"))
	b.WriteString(ui.Muted.Render("other tabs") + "\n")
	b.WriteString(row("f", "activity: filter by class"))
	b.WriteString(row("r · D · y · F", "access: revoke · deny · copy ref · forget"))
	b.WriteString(row("e", "services: on/off for this host"))
	b.WriteString(row("←→ · g", "config: change · this host or every host"))
	b.WriteString(ui.Muted.Render("leave") + "\n")
	b.WriteString(row("esc, q / ^C", "ask to quit / quit now"))
	b.WriteString(ui.Muted.Render("? or esc to close"))
	return m.boxOf(b.String())
}
