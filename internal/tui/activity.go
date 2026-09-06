package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/ui"
)

// logFilters is the cycle the `f` key steps through. Diagnostic is not on it:
// it is the class you ask for with --verbose, not one you browse to, and
// putting it in the cycle would mean pressing f four times to get back to
// where you started.
var logFilters = []event.Class{"", event.Security, event.Network, event.Lifecycle}

// reloadActivity applies the class filter and the search to the scrollback.
func (m *Model) reloadActivity() {
	q := strings.ToLower(strings.TrimSpace(m.search[tabActivity]))
	rows := make([]event.Event, 0, len(m.log))
	for _, e := range m.log {
		if m.logFilter != "" && e.Class != m.logFilter {
			continue
		}
		if q != "" && !matchesEvent(e, q) {
			continue
		}
		rows = append(rows, e)
	}
	m.logRows = rows
}

func matchesEvent(e event.Event, q string) bool {
	return strings.Contains(strings.ToLower(e.Text), q) ||
		strings.Contains(strings.ToLower(e.Service), q) ||
		strings.Contains(strings.ToLower(e.Kind), q) ||
		strings.Contains(string(e.Class), q)
}

// activityView renders the scrollback, newest at the bottom — the direction a
// log is read in, so a stream that is moving reads the way `tail -f` does.
func (m *Model) activityView() string {
	// A list nobody has scrolled sits at the bottom, on the newest line.
	if m.cursor() == noSelection {
		m.offsets[tabActivity] = max(len(m.logRows)-m.listHeight(), 0)
	}

	var lines []string
	end := min(m.offset()+m.listHeight(), len(m.logRows))
	for i := m.offset(); i < end; i++ {
		line := clampWidth(eventLine(m.logRows[i]), m.inner())
		if i == m.cursor() {
			if w := ansi.StringWidth(line); w < m.inner() {
				line += strings.Repeat(" ", m.inner()-w)
			}
			line = ui.Selected.Reverse(true).Render(ansi.Strip(line))
		}
		lines = append(lines, line)
	}

	empty := "nothing yet"
	switch {
	case m.search[tabActivity] != "":
		empty = "nothing matches " + m.search[tabActivity]
	case m.logFilter != "":
		empty = "no " + string(m.logFilter) + " events yet"
	}
	return m.listView(lines, m.listHeight(), empty)
}

func (m *Model) handleActivityKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "f":
		return m.cycleLogFilter()
	case "enter", "d":
		return m.toggleDetail()
	case "y":
		return m.copyLogLine()
	}
	return nil
}

// cycleLogFilter steps the class filter, which is the fastest way to answer
// "what has this box asked for out of my vault today" without reading past
// every port that opened in between.
func (m *Model) cycleLogFilter() tea.Cmd {
	next := 0
	for i, c := range logFilters {
		if c == m.logFilter {
			next = (i + 1) % len(logFilters)
			break
		}
	}
	m.logFilter = logFilters[next]
	m.cursors[tabActivity] = noSelection
	m.reloadActivity()
	m.clampCursor()
	if m.logFilter == "" {
		return m.showToast(toastMsg{text: "showing everything"})
	}
	return m.showToast(toastMsg{text: "showing " + string(m.logFilter) + " only"})
}

// copyLogLine yanks the selected line as plain text.
func (m *Model) copyLogLine() tea.Cmd {
	i := m.cursor()
	if i < 0 || i >= len(m.logRows) {
		return m.needSelection()
	}
	e := m.logRows[i]
	text := fmt.Sprintf("%s %s %s", e.Time.Format("15:04:05"), e.Service, e.Text)
	return tea.Batch(yank(text), m.showToast(toastMsg{text: "copied the line"}))
}

// activityDetailBox shows one event in full, including the structured fields
// the single line has no room for.
func (m *Model) activityDetailBox() string {
	i := m.cursor()
	if i < 0 || i >= len(m.logRows) {
		return ""
	}
	e := m.logRows[i]

	row := func(label, value string) string {
		if value == "" {
			return ""
		}
		return ui.Muted.Render(pad(label, 10)) + value + "\n"
	}

	var b strings.Builder
	b.WriteString(ui.ClassStyle(e.Class).Render(ui.ClassGlyph(e.Class)+" "+e.Time.Format("15:04:05")) + "\n\n")
	b.WriteString(row("service", e.Service))
	b.WriteString(row("kind", e.Kind))
	b.WriteString(row("class", string(e.Class)))
	b.WriteString(row("level", e.Level.String()))
	b.WriteString(row("text", e.Text))
	for j := 0; j+1 < len(e.Fields); j += 2 {
		key, ok := e.Fields[j].(string)
		if !ok {
			continue
		}
		b.WriteString(row(key, fmt.Sprint(e.Fields[j+1])))
	}
	b.WriteString("\n" + ui.Muted.Render("esc to close"))
	return m.boxOf(strings.TrimRight(b.String(), "\n"))
}
