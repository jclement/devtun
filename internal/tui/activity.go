package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/sahilm/fuzzy"

	"github.com/jclement/devtun/internal/authz"
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
	rows := make([]event.Event, 0, len(m.log))
	for _, e := range m.log {
		if m.logFilter != "" && e.Class != m.logFilter {
			continue
		}
		rows = append(rows, e)
	}
	if q := strings.TrimSpace(m.search[tabActivity]); q != "" {
		rows = matchEvents(rows, q)
	}
	m.logRows = rows
}

// matchEvents keeps the events matching a query, in the order they happened.
//
// The tunnel table ranks its matches and this deliberately does not: a log is
// read by time, newest at the bottom, and a scrollback reordered by how well
// each line scored is no longer a scrollback — the line above stops being the
// thing that happened before.
func matchEvents(rows []event.Event, query string) []event.Event {
	matches := fuzzy.FindFromNoSort(query, eventNames(rows))
	out := make([]event.Event, 0, len(matches))
	for _, match := range matches {
		out = append(out, rows[match.Index])
	}
	return out
}

// eventNames is the searchable text of each event.
type eventNames []event.Event

func (e eventNames) Len() int { return len(e) }

func (e eventNames) String(i int) string {
	return strings.Join([]string{e[i].Text, e[i].Service, e[i].Kind, string(e[i].Class)}, " ")
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
		line := clampWidth(eventLine(m.logRows[i]), m.listWidth())
		if i == m.cursor() {
			if w := ansi.StringWidth(line); w < m.listWidth() {
				line += strings.Repeat(" ", m.listWidth()-w)
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
	case "o":
		return m.showDeciding()
	case "n":
		return m.newRuleFromEvent()
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

// activityDetailBox shows one event in full. For a decision — something a
// broker gave or refused — it leads with why: what decided, where that lives,
// and what else matched and lost. That is the question somebody opening a
// refusal is asking, and the raw fields underneath only half answer it.
func (m *Model) activityDetailBox() string {
	e, ok := m.selectedEvent()
	if !ok {
		return ""
	}

	row := func(label, value string) string {
		if value == "" {
			return ""
		}
		return ui.Muted.Render(pad(label, 10)) + value + "\n"
	}

	var b strings.Builder
	b.WriteString(ui.ClassStyle(e.Class).Render(ui.EventGlyph(e)+" "+e.Time.Format("15:04:05")) + "  " + e.Text + "\n")
	if why := m.whyText(e); why != "" {
		b.WriteString("\n" + why)
	}
	b.WriteString("\n")
	b.WriteString(row("service", e.Service))
	b.WriteString(row("kind", e.Kind))
	b.WriteString(row("class", string(e.Class)))
	b.WriteString(row("level", e.Level.String()))
	for j := 0; j+1 < len(e.Fields); j += 2 {
		key, ok := e.Fields[j].(string)
		if !ok {
			continue
		}
		b.WriteString(row(key, fmt.Sprint(e.Fields[j+1])))
	}
	return m.detailFrame(b.String())
}

// selectedEvent is the highlighted Activity line.
func (m *Model) selectedEvent() (event.Event, bool) {
	i := m.cursors[tabActivity]
	if i < 0 || i >= len(m.logRows) {
		return event.Event{}, false
	}
	return m.logRows[i], true
}

// eventField reads one structured field of an event as text.
func eventField(e event.Event, key string) string {
	for j := 0; j+1 < len(e.Fields); j += 2 {
		if k, ok := e.Fields[j].(string); ok && k == key {
			return fmt.Sprint(e.Fields[j+1])
		}
	}
	return ""
}

// sourceFor is the broker an event came from, when it is one the Access tab
// shows.
func (m *Model) sourceFor(e event.Event) (accessSource, bool) {
	for _, src := range m.d.secrets {
		if src.id == e.Service {
			return src, true
		}
	}
	return accessSource{}, false
}

// whyText explains a decision event, or returns "" for any other event.
func (m *Model) whyText(e event.Event) string {
	by := eventField(e, "by")
	if by == "" {
		return ""
	}
	src, ok := m.sourceFor(e)
	refused := e.Kind == "denied" || e.Kind == "refused"
	verb := "given"
	if refused {
		verb = "refused"
	}

	var b strings.Builder
	head := func(s string) { b.WriteString(ui.Banner.Render(s) + "\n") }
	switch authz.DeciderKind(by) {
	case authz.ByRule:
		id := eventField(e, "rule")
		var r authz.Rule
		found := false
		if ok {
			r, found = src.ctrl.Rule(id)
		}
		if !found {
			head(verb + " by a rule that has since been changed or removed")
			break
		}
		head(verb + " by a rule — " + sourceWho(r) + ", " + m.sourceWhere(r))
		b.WriteString("    " + m.matchLine(src, authz.Matched{Rule: &r}) + "\n")
	case authz.ByGrant:
		id := eventField(e, "grant")
		var g *authz.Grant
		if ok {
			for _, live := range src.ctrl.Grants() {
				if live.ID == id {
					gg := live
					g = &gg
				}
			}
		}
		if g == nil {
			head(verb + " by a grant from a prompt answer — it has since lapsed or been revoked")
			break
		}
		head(verb + " by a live grant from a prompt answer")
		b.WriteString("    " + m.matchLine(src, authz.Matched{Grant: g}) + "\n")
	case authz.ByUnmatched:
		if eventField(e, "unmatched") == string(authz.ActionDeny) {
			head("refused because nothing matched, and this broker's \"unmatched\" is deny")
		} else {
			head("nothing matched, so you were asked")
		}
	case authz.ByPrompt:
		head("you answered the prompt")
	case authz.ByTimeout:
		head("nobody answered within the prompt timeout, which counts as No")
		b.WriteString("    " + ui.Muted.Render("Approvals appear: "+m.promptNow.String()+" — Config ▸ prompt") + "\n")
	case authz.ByUnreadable:
		head("refused because a policy file could not be read — everything is, until it is fixed")
	default:
		head(verb + " — decided by " + by)
	}

	// What else matched, asked now. Policy may have changed since, so it is
	// labelled as now and not passed off as what happened then.
	subject := eventField(e, "subject")
	if ok && subject != "" {
		ex := src.ctrl.Explain(m.d.host, subject)
		var lost []authz.Matched
		for _, mt := range ex.Matches {
			if !mt.Decided && !m.sameDecider(mt, e) {
				lost = append(lost, mt)
			}
		}
		if len(lost) > 0 {
			b.WriteString(ui.Muted.Render("also matching now, and losing (a deny always wins):") + "\n")
			for _, mt := range lost {
				b.WriteString("    " + m.matchLine(src, mt) + "\n")
			}
		}
		if now := ex.Verdict.Action; now != "" && (now == authz.ActionDeny) != refused {
			b.WriteString(ui.Warn.Render("policy has changed since: the same request would now be "+verdictWord(now)) + "\n")
		}
	}
	return b.String()
}

// sameDecider reports whether an explanation entry is the thing the event
// says decided, so it is not listed again among the losers.
func (m *Model) sameDecider(mt authz.Matched, e event.Event) bool {
	switch {
	case mt.Rule != nil:
		return mt.Rule.ID == eventField(e, "rule")
	case mt.Grant != nil:
		return mt.Grant.ID == eventField(e, "grant")
	}
	return false
}

func verdictWord(a authz.Action) string {
	switch a {
	case authz.ActionAllow:
		return "allowed"
	case authz.ActionDeny:
		return "refused"
	}
	return "asked about"
}

// decidingBlocked says why "show the deciding rule" cannot run, or "".
func (m *Model) decidingBlocked() string {
	e, ok := m.selectedEvent()
	if !ok {
		return "pick a line first"
	}
	if eventField(e, "rule") == "" && eventField(e, "grant") == "" {
		return "no rule or grant decided this line"
	}
	if _, ok := m.accessRowFor(e); !ok {
		return "that rule or grant is gone now"
	}
	return ""
}

// accessRowFor finds the Access row that decided an event.
func (m *Model) accessRowFor(e event.Event) (int, bool) {
	rule, grant := eventField(e, "rule"), eventField(e, "grant")
	for i, r := range m.accessRows {
		if r.heading != "" || r.source.id != e.Service {
			continue
		}
		if (rule != "" && !r.isGrant && r.rule.ID == rule) || (grant != "" && r.isGrant && r.grant.ID == grant) {
			return i, true
		}
	}
	return 0, false
}

// showDeciding jumps to the Access row that decided the selected event.
func (m *Model) showDeciding() tea.Cmd {
	e, ok := m.selectedEvent()
	if !ok {
		return m.needSelection()
	}
	// The search on Access could be hiding it; a jump that lands nowhere is
	// worse than one that clears a filter.
	m.search[tabAccess] = ""
	m.reloadAccess()
	i, found := m.accessRowFor(e)
	if !found {
		return m.showToast(toastMsg{text: "that rule or grant is gone now", bad: true})
	}
	m.showDetail = false
	m.selectTab(tabAccess)
	m.setCursor(i)
	m.clampCursor()
	return nil
}

// newRuleFromEvent is `n` on a decision: the rule form, seeded with what was
// asked for, on the Access tab where the rule will appear.
func (m *Model) newRuleFromEvent() tea.Cmd {
	if why := m.newFromEventBlocked(); why != "" {
		return m.showToast(toastMsg{text: why, bad: true})
	}
	e, _ := m.selectedEvent()
	src, _ := m.sourceFor(e)
	m.showDetail = false
	m.selectTab(tabAccess)
	return m.openForm(formSeed{src: m.sourceIndex(src.id), subject: eventField(e, "subject"), effect: authz.ActionAllow})
}

// newFromEventBlocked says why `n` cannot start from the selected line, or "".
func (m *Model) newFromEventBlocked() string {
	e, ok := m.selectedEvent()
	if !ok {
		return "pick a line first"
	}
	if _, found := m.sourceFor(e); !found || eventField(e, "subject") == "" {
		return "not a request to a broker"
	}
	return ""
}
