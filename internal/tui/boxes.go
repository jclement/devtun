package tui

import (
	"strings"

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
func (m *Model) helpBox() string {
	if m.height < 34 {
		return m.compactHelpBox()
	}

	sections := []struct {
		title string
		keys  [][2]string
	}{
		{"everywhere", [][2]string{
			{"tab / 1-4", "switch tab"},
			{"↑ ↓ / j k", "move"},
			{"g / G", "first / last"},
			{"/", "search this tab"},
			{"c", "settings: what is listed and how"},
			{"esc, q", "quit (asks first)"},
			{"ctrl+c", "quit immediately"},
		}},
		{"a port", [][2]string{
			{"enter, d", "detail"},
			{"x", "hide this port (remembered)"},
			{"H", "list the ports you hid, so x can unhide one"},
			{"a", "auto → on → hidden (remembered)"},
			{"t", "say http or https (remembered)"},
			{"o, space", "open in browser — asks HTTP/HTTPS when needed"},
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
		{"secrets", [][2]string{
			{"r", "revoke the selected rule"},
			{"y", "copy the op:// reference — never the secret"},
			{"F", "forget every live grant and cached value"},
		}},
		{"services", [][2]string{
			{"e", "on or off for this host, from the next connection"},
		}},
		{"mouse", [][2]string{
			{"click", "select a row, or a tab, or a key bar action"},
			{"double click", "open in browser"},
			{"click M / VIA", "cycle mode / protocol"},
			{"click header", "sort by that column"},
		}},
	}

	var b strings.Builder
	b.WriteString(ui.Banner.Render("devtun " + m.d.version))
	b.WriteString("\n")
	for _, sec := range sections {
		b.WriteString("\n" + ui.Muted.Render(sec.title) + "\n")
		for _, k := range sec.keys {
			b.WriteString("  " + ui.Banner.Render(pad(k[0], 14)) + ui.Muted.Render(k[1]) + "\n")
		}
	}
	b.WriteString("\n" + ui.Muted.Render("? or esc to close"))
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
	b.WriteString(row("tab / 1-4", "switch tab"))
	b.WriteString(row("↑↓ / j k / gG", "move / first / last"))
	b.WriteString(row("/ · c", "search · settings"))
	b.WriteString(ui.Muted.Render("a port") + "\n")
	b.WriteString(row("enter, d", "detail"))
	b.WriteString(row("x · H", "hide · list hidden"))
	b.WriteString(row("a · t", "auto/on/hidden · http/https"))
	b.WriteString(row("o, space · y", "open in browser · copy"))
	b.WriteString(row("l · n", "local port · name"))
	b.WriteString(row("s / r · p", "sort / reverse · pause"))
	b.WriteString(ui.Muted.Render("other tabs") + "\n")
	b.WriteString(row("f", "activity: filter by class"))
	b.WriteString(row("r · y · F", "secrets: revoke · copy ref · forget"))
	b.WriteString(row("e", "services: on/off for this host"))
	b.WriteString(ui.Muted.Render("leave") + "\n")
	b.WriteString(row("esc, q / ^C", "ask to quit / quit now"))
	b.WriteString(ui.Muted.Render("? or esc to close"))
	return m.boxOf(b.String())
}
