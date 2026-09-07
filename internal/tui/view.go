package tui

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// Fixed rows of the frame, used for drawing and for mouse hit-testing alike,
// so a click always lands on what was actually rendered.
const (
	rowTop  = 0 // top border: host, connection, counts, uptime
	rowTabs = 1
	rowRule = 2
	rowBody = 3 // first line of the tab's own content
)

const (
	// The activity pane under every tab scales with the window rather than
	// sitting at a fixed height.
	//
	// It exists so an approval cannot scroll away unnoticed while you are
	// looking at the port table, and three lines is barely enough to notice
	// one — on a tall terminal it is a waste of a screen that has room to
	// spare. On a short one the opposite is true: every line it takes is a
	// port you cannot see, and below a certain height the table matters more
	// than the history does.
	tickerMin     = 3  // below this it is not worth the rule that frames it
	tickerWant    = 8  // what it grows to when there is room
	tickerShare   = 4  // at most a quarter of the frame
	tickerRoomFor = 10 // body rows that must survive before it grows at all

	// baseChrome is every line the body never gets regardless of the activity
	// pane: the header, the tab bar and its rule, and the key bar.
	baseChrome = rowBody + 1

	// A frame narrower or shorter than this cannot be drawn without lying
	// about something, so it is not drawn at all.
	minWidth  = 40
	minHeight = baseChrome + tickerMin + 2
)

// Box-drawing pieces.
const (
	cornerTL = "╭"
	cornerTR = "╮"
	cornerBL = "╰"
	cornerBR = "╯"
	edgeH    = "─"
	edgeV    = "│"
	teeL     = "├"
	teeR     = "┤"
)

// View renders the current frame.
func (m *Model) View() tea.View {
	view := tea.NewView(m.frame())
	view.AltScreen = true
	// Cell motion rather than all motion: everything clickable is a press, and
	// all-motion is the mode terminals support least well.
	view.MouseMode = tea.MouseModeCellMotion
	return view
}

func (m *Model) frame() string {
	if m.quit {
		// Leave the terminal clean on exit.
		return ""
	}
	if m.dissolving != nil {
		return m.dissolving.View()
	}
	if m.width < minWidth || m.height < minHeight {
		return m.tooSmallView()
	}

	view := m.baseView()
	switch {
	case m.approval != nil:
		view = overlayCenter(view, m.approvalBox(), m.width, m.height)
	case m.setup != nil:
		view = overlayCenter(view, m.setupBox(), m.width, m.height)
	case m.confirming:
		view = overlayCenter(view, m.confirmBox(), m.width, m.height)
	case m.showHelp:
		view = overlayCenter(view, m.helpBox(), m.width, m.height)
	case m.showDetail:
		view = overlayCenter(view, m.detailBox(), m.width, m.height)
	case m.protocolPrompt:
		view = overlayCenter(view, m.protocolBox(), m.width, m.height)
	case m.menu.open:
		view = overlayCenter(view, m.menuBox(), m.width, m.height)
	case m.offline():
		view = overlayCenter(view, m.reconnectBox(), m.width, m.height)
	}
	return view
}

// tooSmallView says what is wrong instead of drawing a frame that would wrap.
// A sheared table is worse than no table: it looks like data.
func (m *Model) tooSmallView() string {
	msg := fmt.Sprintf("devtun needs %d×%d — this window is %d×%d",
		minWidth, minHeight, m.width, m.height)

	lines := make([]string, max(m.height, 1))
	mid := len(lines) / 2
	for i := range lines {
		if i == mid && m.width > 0 {
			lines[i] = clampWidth(ui.Warn.Render(msg), m.width)
		}
	}
	return strings.Join(lines, "\n")
}

// baseView is the interface without any overlay, and the frame the dissolve
// captures.
func (m *Model) baseView() string {
	var b strings.Builder
	b.WriteString(m.topBorder())
	b.WriteByte('\n')
	b.WriteString(m.boxLine(m.tabBar()))
	b.WriteByte('\n')
	b.WriteString(m.separator(""))
	b.WriteByte('\n')
	b.WriteString(m.body())
	b.WriteByte('\n')
	// The activity pane disappears entirely on a frame too short to spare the
	// rows. Its rule goes with it: a labelled separator over nothing is worse
	// than no pane, because it looks like something failed to render.
	if ticker := m.ticker(); ticker != "" {
		b.WriteString(m.separator("activity"))
		b.WriteByte('\n')
		b.WriteString(ticker)
		b.WriteByte('\n')
	}
	b.WriteString(m.bottomBorder())
	return b.String()
}

// body renders the active tab, always exactly bodyHeight lines.
func (m *Model) body() string {
	switch m.tab {
	case tabActivity:
		return m.activityView()
	case tabAccess:
		return m.accessView()
	case tabServices:
		return m.servicesView()
	default:
		return m.tunnelsView()
	}
}

// inner is the width available between the frame's side borders.
func (m *Model) inner() int {
	if m.width < 4 {
		return 1
	}
	return m.width - 2
}

// bodyHeight is how many lines the active tab gets.
func (m *Model) bodyHeight() int {
	if h := m.height - m.chrome(); h > 1 {
		return h
	}
	return 1
}

// listTop is the first terminal row occupied by a selectable row.
func (m *Model) listTop() int {
	if m.tab == tabTunnels {
		return rowBody + 1 // the column header sits above the data
	}
	return rowBody
}

// tickerHeight is how many lines the activity pane gets.
//
// It is zero on a frame with no room to spare — a pane that costs three of the
// eight rows you have is not helping — and otherwise grows toward tickerWant
// without ever taking more than a quarter of the screen.
func (m *Model) tickerHeight() int {
	// Everything the body and the pane share, the pane's own rule included.
	available := m.height - baseChrome
	if available < tickerMin+1+tickerRoomFor {
		return 0
	}
	height := available / tickerShare
	if height < tickerMin {
		return 0
	}
	if height > tickerWant {
		return tickerWant
	}
	return height
}

// chrome is every line the active tab's body does not get.
func (m *Model) chrome() int {
	if h := m.tickerHeight(); h > 0 {
		return baseChrome + h + 1 // the pane, plus the rule above it
	}
	return baseChrome
}

// listHeight is how many rows of the active tab's list fit on screen.
func (m *Model) listHeight() int {
	h := m.bodyHeight() - (m.listTop() - rowBody)
	if h < 1 {
		return 1
	}
	return h
}

// boxLine wraps content in the frame's side borders, padding it to fit.
func (m *Model) boxLine(content string) string {
	edge := ui.Muted.Render(edgeV)
	w := ansi.StringWidth(content)
	if w > m.inner() {
		content = ansi.Truncate(content, m.inner(), "")
		w = ansi.StringWidth(content)
	}
	return edge + content + strings.Repeat(" ", m.inner()-w) + edge
}

// listView lays out a list of already-rendered lines inside the frame,
// padding to the full height so the frame never changes shape.
func (m *Model) listView(lines []string, height int, empty string) string {
	if len(lines) == 0 {
		return m.emptyView(height, empty)
	}
	out := make([]string, 0, height)
	for _, line := range lines {
		out = append(out, m.boxLine(line))
	}
	for len(out) < height {
		out = append(out, m.boxLine(""))
	}
	return strings.Join(out[:height], "\n")
}

// emptyView explains an empty list rather than showing a blank rectangle.
func (m *Model) emptyView(h int, msg string) string {
	lines := make([]string, h)
	mid := h / 2
	for i := range lines {
		content := ""
		if i == mid {
			content = lipgloss.PlaceHorizontal(m.inner(), lipgloss.Center, ui.Muted.Render(msg))
		}
		lines[i] = m.boxLine(content)
	}
	return strings.Join(lines, "\n")
}

// rule draws a horizontal run of the frame's edge.
func (m *Model) rule(n int) string { return m.ruleIn(ui.Muted, n) }

// ruleIn draws a horizontal rule in a given style, so one border can be
// coloured differently from the rest of the frame.
func (m *Model) ruleIn(style lipgloss.Style, n int) string {
	if n <= 0 {
		return ""
	}
	return style.Render(strings.Repeat(edgeH, n))
}

// borderWith composes a horizontal rule carrying a left and a right label.
// Labels are dropped rather than truncated when the frame is too narrow.
func (m *Model) borderWith(left, right, lc, rc string) string {
	return m.borderIn(ui.Muted, left, right, lc, rc)
}

// borderIn is borderWith with the edge style chosen by the caller.
func (m *Model) borderIn(edge lipgloss.Style, left, right, lc, rc string) string {
	lw, rw := ansi.StringWidth(left), ansi.StringWidth(right)
	if lw > 0 {
		lw += 2 // the spaces either side of the label
	}
	if rw > 0 {
		rw += 2
	}

	// Two corners plus one edge segment beside each.
	const fixed = 4
	if fixed+lw+rw > m.width {
		right, rw = "", 0
	}
	if fixed+lw > m.width {
		left, lw = "", 0
	}

	var b strings.Builder
	b.WriteString(edge.Render(lc))
	b.WriteString(m.ruleIn(edge, 1))
	if left != "" {
		b.WriteString(" " + left + " ")
	}
	b.WriteString(m.ruleIn(edge, m.width-fixed-lw-rw))
	if right != "" {
		b.WriteString(" " + right + " ")
	}
	b.WriteString(m.ruleIn(edge, 1))
	b.WriteString(edge.Render(rc))
	return b.String()
}

func (m *Model) separator(label string) string {
	if label == "" {
		return ui.Muted.Render(teeL) + m.rule(m.inner()) + ui.Muted.Render(teeR)
	}
	return m.borderWith(ui.Muted.Render(label), "", teeL, teeR)
}

func (m *Model) topBorder() string {
	title := ui.Banner.Render("devtun") + ui.Muted.Render(" ▸ ") + ui.Host.Render(m.d.host)
	status := m.statusLine()

	if m.exposed() {
		// borderWith drops an overlong right label as a unit. A safety warning
		// is not optional decoration, so compact the summary before that can
		// happen, and keep the warning as the last thing standing.
		if 4+ansi.StringWidth(title)+2+ansi.StringWidth(status)+2 > m.width {
			status = m.lanWarning() + ui.Muted.Render(" · ") + m.statusChip()
		}
		if 4+ansi.StringWidth(title)+2+ansi.StringWidth(status)+2 > m.width {
			status = m.lanWarning()
		}
	}
	// When tunnels are reachable from other machines the whole top edge goes
	// red, rather than the warning being a chip among equals. This is the one
	// condition on screen where the cost of not noticing is somebody else
	// reaching your dev box, and a warning drawn at the same weight as "3 fwd"
	// is one you have stopped seeing by the second day.
	edge := ui.Muted
	if m.exposed() {
		edge = ui.Danger
	}
	return m.borderIn(edge, title, status, cornerTL, cornerTR)
}

func (m *Model) bottomBorder() string {
	if m.editing() {
		return m.borderWith(m.editorLabel(), "", cornerBL, cornerBR)
	}
	if m.hasToast {
		style := ui.OK
		if m.toast.bad {
			style = ui.Error
		}
		// Clamp rather than hand borderWith something too long: it drops an
		// oversized label as a unit, so a message a few characters past the
		// frame width does not shrink — it disappears. A toast that vanishes
		// on a narrow terminal, or on a machine whose home directory happens
		// to have a longer name, is worse than a truncated one, and the
		// failure is invisible until somebody notices they were never told
		// anything.
		text := clampWidth("▸ "+m.toast.text, m.width-6)
		return m.borderWith(style.Render(text), "", cornerBL, cornerBR)
	}
	return m.borderWith(m.keyBar(), m.viewChip(), cornerBL, cornerBR)
}

// statusLine is the connection and tunnel summary in the top border.
func (m *Model) statusLine() string {
	parts := []string{m.statusChip()}

	if m.d.tunnels.Policy().Paused {
		parts = append(parts, ui.Warn.Render("PAUSED"))
	}
	if m.exposed() {
		parts = append(parts, m.lanWarning())
	}

	// The hidden count comes from the manager rather than from the rows: the
	// rows deliberately omit hidden ports, so counting them here would only
	// ever work while *show hidden* was on — which is exactly when the number
	// stops being interesting. What you want is a count of what you cannot see.
	hidden := m.d.tunnels.Hidden()

	active := 0
	for _, r := range m.rows {
		if r.Status == tunnels.StatusActive {
			active++
		}
	}
	parts = append(parts, ui.OK.Render(fmt.Sprintf("%d fwd", active)))
	if hidden > 0 {
		parts = append(parts, ui.Muted.Render(fmt.Sprintf("%d hidden", hidden)))
	}
	parts = append(parts, ui.Muted.Render(FormatUptime(m.uptime())))
	return strings.Join(parts, ui.Muted.Render(" · "))
}

// uptime is how long the current connection has been up, falling back to how
// long the interface has been open before there has been one.
func (m *Model) uptime() time.Duration {
	if !m.status.Since.IsZero() {
		return m.d.now().Sub(m.status.Since)
	}
	return m.d.now().Sub(m.started)
}

// statusChip renders the connection indicator.
func (m *Model) statusChip() string {
	switch m.status.State {
	case session.Connected:
		return ui.OK.Render("● connected")
	case session.Reconnecting:
		s := "reconnecting"
		if m.status.Attempt > 0 {
			s += fmt.Sprintf(" #%d", m.status.Attempt)
		}
		return ui.Warn.Render("◦ " + s)
	case session.Disconnected:
		return ui.Error.Render("○ disconnected")
	case session.Stopped:
		return ui.Muted.Render("○ stopped")
	default:
		return ui.Warn.Render("◦ connecting")
	}
}

// exposed reports whether the tunnels are reachable from other machines.
//
// The bind address is read off the rows rather than passed in, because it is
// the listeners that are exposed: with nothing forwarded there is nothing for
// anyone on the LAN to reach, and the warning would be about a hypothetical.
func (m *Model) exposed() bool {
	bind := strings.TrimSpace(m.bind)
	if bind == "" || strings.EqualFold(bind, "localhost") {
		return false
	}
	ip := net.ParseIP(strings.Trim(bind, "[]"))
	return ip == nil || !ip.IsLoopback()
}

func (m *Model) lanWarning() string {
	return ui.Danger.Render("LAN EXPOSED " + m.bind)
}

// viewChip shows the active search and per-tab view state in the bottom
// border.
func (m *Model) viewChip() string {
	var parts []string
	if q := m.search[m.tab]; q != "" {
		parts = append(parts, ui.Tunnel.Render("/"+q))
	}
	switch m.tab {
	case tabTunnels:
		if m.prefs.ShowHidden {
			parts = append(parts, ui.Muted.Render("+hidden"))
		}
	case tabActivity:
		if m.logFilter != "" {
			parts = append(parts, ui.ClassStyle(m.logFilter).Render(string(m.logFilter)))
		}
	}
	return strings.Join(parts, ui.Muted.Render(" · "))
}

// editorLabel renders the inline editor shown in the bottom border.
func (m *Model) editorLabel() string {
	var prompt, hint string
	switch m.editor {
	case editorSearch:
		prompt, hint = "search", "enter to keep · esc to clear"
	case editorLocalPort:
		prompt = fmt.Sprintf("local port for remote %d", m.editorPort)
		hint = "blank resets · enter to apply · esc to cancel"
	case editorPortLabel:
		prompt = fmt.Sprintf("name for remote %d", m.editorPort)
		hint = "blank clears · enter to remember · esc to cancel"
	}
	return ui.Banner.Render(prompt) + ui.Muted.Render(" ▸ ") + m.input.Render() +
		ui.Muted.Render("   "+hint)
}

// keyBar renders the clickable key hints for the active tab, dropping whole
// entries that do not fit rather than truncating one mid-word.
func (m *Model) keyBar() string {
	// Deliberately short. Everything else is one keystroke away behind ?, and
	// a key bar nobody can read is not a key bar.
	keys := [][2]string{{"↑↓", "move"}}
	switch m.tab {
	case tabActivity:
		keys = append(keys, [2]string{"f", "filter"}, [2]string{"/", "search"})
	case tabAccess:
		keys = append(keys, [2]string{"r", "revoke"}, [2]string{"D", "deny"}, [2]string{"y", "copy ref"})
	case tabServices:
		keys = append(keys, [2]string{"e", "enable"})
	default:
		keys = append(keys, [2]string{"x", "hide"}, [2]string{"b", "browser"}, [2]string{"enter", "detail"})
	}
	keys = append(keys, [2]string{"c", "config"}, [2]string{"?", "help"}, [2]string{"esc", "quit"})

	// Reserve room for the right-hand chip plus the border decorations.
	budget := m.width - 6 - ansi.StringWidth(m.viewChip())

	sep := ui.Muted.Render(" · ")
	var bar strings.Builder
	used := 0
	m.footerZones = m.footerZones[:0]
	for i, k := range keys {
		hint := ui.Banner.Render(k[0]) + " " + ui.Muted.Render(k[1])
		width := ansi.StringWidth(k[0]) + 1 + ansi.StringWidth(k[1])
		lead := 0
		if i > 0 {
			lead = 3 // " · "
		}
		if used+lead+width > budget {
			break
		}
		if i > 0 {
			bar.WriteString(sep)
		}
		bar.WriteString(hint)
		// The bar starts after "╰─ ", three cells in.
		m.footerZones = append(m.footerZones, zone{
			x0: 3 + used + lead,
			x1: 3 + used + lead + width,
			id: k[0],
		})
		used += lead + width
	}
	return bar.String()
}

// ticker renders the last few events, under every tab.
//
// The treatment is the log renderer's, deliberately: time, class glyph,
// service, sentence. A line read here and the same line read in a log file must
// look like the same line, because the class colouring is the thing that makes
// a secret leaving your vault distinguishable from a port opening at a glance.
func (m *Model) ticker() string {
	height := m.tickerHeight()
	if height == 0 {
		return ""
	}

	recent := make([]event.Event, 0, height)
	for i := len(m.log) - 1; i >= 0 && len(recent) < height; i-- {
		// Diagnostic events are dropped for the same reason the log drops them
		// without --verbose: a ticker that shows everything is a ticker nobody
		// reads. The activity tab still has them.
		if m.log[i].Class == event.Diagnostic {
			continue
		}
		recent = append(recent, m.log[i])
	}

	// Oldest at the top, so the newest line is nearest the key bar and the pane
	// reads downward like the log it mirrors.
	lines := make([]string, height)
	for i := range lines {
		content := ""
		if from := len(recent) - height + i; from >= 0 {
			content = clampWidth(eventLine(recent[from]), m.inner())
		}
		lines[i] = m.boxLine(content)
	}
	return strings.Join(lines, "\n")
}

// eventLine renders one event the way render.Log does.
func eventLine(e event.Event) string {
	return fmt.Sprintf("%s %s %s  %s",
		ui.Muted.Render(e.Time.Format("15:04:05")),
		ui.ClassGlyph(e.Class),
		ui.ClassStyle(e.Class).Render(pad(shortService(e.Service), 4)),
		ui.LevelStyle(e.Level).Render(e.Text),
	)
}

// shortService abbreviates service ids to keep the column narrow.
//
// It mirrors render.short, which is unexported: the names are ours, so both are
// a lookup rather than a truncation, and both must produce the same three
// letters or the ticker and the log would name the same service differently.
func shortService(service string) string {
	switch service {
	case "1password":
		return "op"
	case "tunnels":
		return "tun"
	case "browser":
		return "web"
	case "session":
		return "ssh"
	default:
		return service
	}
}

// overlayCenter composites box over base, centred, preserving the styling of
// the content it covers on either side.
func overlayCenter(base, box string, width, height int) string {
	if box == "" {
		return base
	}
	boxLines := strings.Split(box, "\n")
	boxW := 0
	for _, l := range boxLines {
		if w := ansi.StringWidth(l); w > boxW {
			boxW = w
		}
	}
	x := (width - boxW) / 2
	y := (height - len(boxLines)) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	baseLines := strings.Split(base, "\n")
	for len(baseLines) < y+len(boxLines) {
		baseLines = append(baseLines, "")
	}

	for i, bl := range boxLines {
		row := y + i
		if row >= len(baseLines) {
			break
		}
		left := ansi.Truncate(baseLines[row], x, "")
		if w := ansi.StringWidth(left); w < x {
			left += strings.Repeat(" ", x-w)
		}
		right := ansi.TruncateLeft(baseLines[row], x+ansi.StringWidth(bl), "")
		baseLines[row] = left + "\x1b[0m" + bl + "\x1b[0m" + right
	}
	return strings.Join(baseLines, "\n")
}

// ring emits a terminal bell without going through the renderer.
//
// It writes to the controlling terminal rather than to stdout so it works when
// output is redirected, and drops the bell entirely rather than risking a
// stray byte in a pipe when there is no terminal to ring.
func ring() {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer func() { _ = tty.Close() }()
	_, _ = tty.WriteString("\a")
}

// boxOf renders an overlay panel, clamped so it can never be wider than the
// frame it sits on.
func (m *Model) boxOf(body string) string {
	// Two border cells and two of padding on each side.
	limit := m.width - 6
	if limit < 10 {
		limit = 10
	}
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		lines = append(lines, clampWidth(line, limit))
	}
	return ui.Panel.Render(strings.Join(lines, "\n"))
}

// boxOfStyle is boxOf with a caller-chosen frame, for the one overlay that
// must not look like the others.
func (m *Model) boxOfStyle(style lipgloss.Style, body string) string {
	limit := m.width - 6
	if limit < 10 {
		limit = 10
	}
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		lines = append(lines, clampWidth(line, limit))
	}
	return style.Render(strings.Join(lines, "\n"))
}
