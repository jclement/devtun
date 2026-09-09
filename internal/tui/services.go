package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/ui"
)

// svcState is what the session has said about one service.
//
// It is learned from the event stream rather than asked for. The session
// reports every attach outcome through the bus stamped with the service's own
// id, so this needs no second channel to the supervisor, and it is right again
// after a reconnect without anyone arranging for that.
type svcState struct {
	running bool
	// detail is the last thing said about it — the Support reason when a
	// service cannot run here, which is the sentence the user has to act on.
	detail string
}

// serviceRow is one line of the Services tab.
type serviceRow struct {
	meta    service.Meta
	enabled bool
	state   svcState
}

// noteService files an event against the service it is about, reporting
// whether anything changed.
func (m *Model) noteService(e event.Event) bool {
	if e.Service == "" || e.Service == "session" {
		if e.Kind != "disconnected" && e.Kind != "connect-failed" {
			return false
		}
		// The link went away and every instance went with it.
		for id, st := range m.svcState {
			st.running = false
			m.svcState[id] = st
		}
		return true
	}
	st := m.svcState[e.Service]
	switch e.Kind {
	case "started":
		st.running, st.detail = true, ""
	case "unavailable", "attach-failed", "disabled":
		st.running, st.detail = false, e.Text
	default:
		return false
	}
	m.svcState[e.Service] = st
	return true
}

func (m *Model) reloadServices() {
	q := strings.ToLower(strings.TrimSpace(m.search[tabServices]))
	rows := make([]serviceRow, 0, len(m.d.services))
	for _, svc := range m.d.services {
		meta := svc.Meta()
		if q != "" && !strings.Contains(strings.ToLower(meta.ID+" "+meta.Title+" "+meta.Short), q) {
			continue
		}
		rows = append(rows, serviceRow{
			meta:    meta,
			enabled: m.serviceEnabled(meta),
			state:   m.svcState[meta.ID],
		})
	}
	m.svcRows = rows
}

// serviceEnabled reports whether a service is switched on for this host.
//
// The default is the service's own — on, unless it is one that has to be asked
// for. Without a config store (a --no-config run, or a test) that default is
// all there is, which is the same answer the session arrives at.
func (m *Model) serviceEnabled(meta service.Meta) bool {
	if m.d.store == nil {
		return !meta.OptIn
	}
	return m.d.store.Enabled(m.d.host, meta.ID, !meta.OptIn)
}

func (m *Model) servicesView() string {
	var lines []string
	end := min(m.offset()+m.listHeight(), len(m.svcRows))
	for i := m.offset(); i < end; i++ {
		lines = append(lines, m.serviceLine(m.svcRows[i], i == m.cursor()))
	}
	return m.listView(lines, m.listHeight(), "no services on this session")
}

func (m *Model) serviceLine(r serviceRow, selected bool) string {
	// A filled dot for enabled, blank for off. `×` was the obvious glyph for a
	// checkbox and the wrong one: in a column headed by nothing, × reads as
	// "no" — so a fully working service looked switched off.
	mark, status := " ", ui.Muted.Render(pad("off", 12))
	if r.enabled {
		mark = "●"
		switch {
		case r.state.running:
			status = ui.OK.Render(pad("running", 12))
		case r.state.detail != "":
			status = ui.Warn.Render(pad("unavailable", 12))
		case m.status.State == session.Connected:
			status = ui.Muted.Render(pad("starting…", 12))
		default:
			status = ui.Muted.Render(pad("waiting", 12))
		}
	}

	line := " [" + mark + "] " + pad(r.meta.Glyph+" "+r.meta.Title, 16) + "  " + status + "  "
	// The reason a service cannot work here is the only thing on this tab the
	// user can act on, so it wins the space over the description.
	if r.state.detail != "" && r.enabled {
		line += ui.Muted.Render(r.state.detail)
	} else {
		line += ui.Muted.Render(r.meta.Short)
	}

	line = clampWidth(line, m.listWidth())
	switch {
	case selected:
		if w := ansi.StringWidth(line); w < m.listWidth() {
			line += strings.Repeat(" ", m.listWidth()-w)
		}
		return ui.Selected.Reverse(true).Render(ansi.Strip(line))
	case !r.enabled:
		return ui.Muted.Render(ansi.Strip(line))
	default:
		return line
	}
}

func (m *Model) handleServicesKey(msg tea.KeyPressMsg) tea.Cmd {
	if msg.String() == "e" {
		return m.toggleService()
	}
	return nil
}

// toggleService switches a service on or off for this host and remembers it.
//
// It takes effect on the next connection, not this one: starting and stopping
// a service mid-session is the supervisor's business, and a toggle that half
// did it would be worse than one that plainly does not.
func (m *Model) toggleService() tea.Cmd {
	i := m.cursor()
	if i < 0 || i >= len(m.svcRows) {
		return m.needSelection()
	}
	row := m.svcRows[i]
	if m.d.store == nil {
		return m.showToast(toastMsg{text: "nowhere to record that — no config file", bad: true})
	}

	enabled := !row.enabled
	m.d.store.SetEnabled(m.d.host, row.meta.ID, enabled)
	m.reloadServices()

	if enabled {
		return m.showToast(toastMsg{text: row.meta.Title + " on for " + m.d.host + " — from the next connection"})
	}
	return m.showToast(toastMsg{text: row.meta.Title + " off for " + m.d.host + " — from the next connection"})
}
