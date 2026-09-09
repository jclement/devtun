package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// Column widths. PROCESS absorbs whatever is left over.
const (
	wMark = 1
	wMode = 1
	// The port columns carry a sort indicator on top of their title, so they
	// are one cell wider than "REMOTE" needs on its own.
	wLocal  = 7
	wArrow  = 1
	wRemote = 7
	wScheme = 7 // fits "unknown"
	wAge    = 5
	wConns  = 6
	wBytes  = 8
	gap     = 2
	minProc = 11
	// A very wide terminal should not stretch PROCESS across the whole screen:
	// that strands AGE/CONNS/IN/OUT far from the row they describe and leaves a
	// canyon of whitespace in between. Past this the table just stops growing.
	// It is generous rather than tight because the alternative is ~35 dead
	// columns on a wide terminal and a command cut mid-flag.
	maxProc = 96
)

// legendMaxRows is the table size below which the glyph legend goes in the
// space under it. Above it the space belongs to the rows.
const legendMaxRows = 8

// Recency windows for the activity marker. These are what make a busy table
// scannable: the thing you just started, and the thing you are actually using,
// should be findable without reading every row.
const (
	freshWindow = 20 * time.Second // recently created
	liveWindow  = 5 * time.Second  // recently carried traffic
)

// activity classifies a row for highlighting.
type activity int

const (
	activityNone activity = iota
	activityFresh
	activityLive
)

// activityOf reports whether a row is new or currently in use.
func activityOf(s tunnels.State, now time.Time) activity {
	if s.Status != tunnels.StatusActive {
		return activityNone
	}
	if s.ActiveConns > 0 || (!s.LastByte.IsZero() && now.Sub(s.LastByte) < liveWindow) {
		return activityLive
	}
	if !s.Created.IsZero() && now.Sub(s.Created) < freshWindow {
		return activityFresh
	}
	return activityNone
}

// tunnelsView renders the summary strip, the column header and the table.
func (m *Model) tunnelsView() string {
	lines, _ := m.tableRows()

	empty := "no services yet — start something on the remote and it will appear here"
	switch {
	case m.search[tabTunnels] != "":
		empty = "nothing matches " + m.search[tabTunnels]
	case m.status.State != session.Connected:
		empty = "waiting for the connection…"
	}

	return m.boxLine(m.summaryStrip()) + "\n" +
		m.boxLine(ui.Header.Render(m.columnHeader())) + "\n" +
		m.listView(m.withLegend(lines), m.listHeight(), empty)
}

// tableRows renders the visible slice of the table and reports which row each
// line belongs to.
//
// A row is one line unless a bind error wraps, so the slice cannot be taken by
// index arithmetic the way every other tab's can: after a wrapped row, every
// line is one further down the screen than its row index says, and a click
// would select the row above the one under the pointer.
func (m *Model) tableRows() (lines []string, rowOf []int) {
	height := m.listHeight()
	offset := m.offset()
	for {
		lines, rowOf = m.tableRowsFrom(offset, height)
		// clampCursor sizes the window in rows, so a wrapped row above the
		// cursor pushes the cursor off the bottom of a window it believes it
		// is inside. Give up the extra row here rather than leave the
		// selection somewhere the eye cannot follow it.
		if offset >= len(m.rows)-1 || m.cursor() == noSelection ||
			(len(rowOf) > 0 && rowOf[len(rowOf)-1] >= m.cursor()) {
			break
		}
		offset++
	}
	m.offsets[tabTunnels] = offset
	return lines, rowOf
}

func (m *Model) tableRowsFrom(offset, height int) (lines []string, rowOf []int) {
	for i := offset; i < len(m.rows) && len(lines) < height; i++ {
		for _, line := range m.rowView(m.rows[i], i == m.cursor()) {
			if len(lines) == height {
				break
			}
			lines = append(lines, line)
			rowOf = append(rowOf, i)
		}
	}
	return lines, rowOf
}

// withLegend fills the space under a short table with what the glyphs mean.
//
// Six of them carry the whole state of a row and none is documented on screen.
// A table with room to spare is exactly the table somebody seeing devtun for
// the first time is looking at, and the space was blank anyway.
func (m *Model) withLegend(lines []string) []string {
	if len(lines) == 0 || len(lines) >= legendMaxRows || len(lines)+2 > m.listHeight() {
		return lines
	}
	legend := m.legend()
	if legend == "" {
		return lines
	}
	return append(lines, "", legend)
}

func (m *Model) legend() string {
	keys := [][2]string{
		{"●", "live"}, {"◦", "new"}, {"≠", "remapped"},
		{"✕", "hidden"}, {"+", "always on"}, {"!", "error"},
	}
	var b strings.Builder
	for _, k := range keys {
		part := k[0] + " " + k[1]
		if b.Len() > 0 {
			part = "   " + part
		}
		// Dropped whole, from the end: half a legend entry explains nothing.
		if ansi.StringWidth(b.String())+ansi.StringWidth(part) > m.tableWidth() {
			break
		}
		b.WriteString(part)
	}
	return ui.Muted.Render(b.String())
}

// summaryStrip is the one line that answers "is anything wrong" without
// reading thirty rows: how many ports are in each state, and what is moving
// through all of them together.
func (m *Model) summaryStrip() string {
	hidden := m.d.tunnels.Hidden()
	if len(m.rows) == 0 && hidden == 0 {
		return ""
	}

	now := m.d.now()
	var live, fresh, failed int
	var in, out uint64
	for _, r := range m.rows {
		switch activityOf(r, now) {
		case activityLive:
			live++
		case activityFresh:
			fresh++
		}
		if r.Status == tunnels.StatusError {
			failed++
		}
		in, out = in+r.BytesIn, out+r.BytesOut
	}

	// Ordered as the eye reads them, but given up in the order a narrow
	// terminal can afford: the error count is the last thing standing, because
	// it is the one state on this line that is asking for something.
	chips := []struct {
		style      lipgloss.Style
		glyph, key string
		n, keep    int
	}{
		{ui.Active, "●", "live", live, 3},
		{ui.Fresh, "◦", "new", fresh, 1},
		{ui.Muted, "✕", "hidden", hidden, 2},
		{ui.Error, "!", "error", failed, 4},
	}

	for {
		var parts []string
		width, weakest, weakestAt := 0, 5, -1
		for i, c := range chips {
			if c.n == 0 {
				continue
			}
			if len(parts) > 0 {
				width += 3
			}
			text := fmt.Sprintf("%s %s %d", c.glyph, c.key, c.n)
			parts = append(parts, c.style.Render(text))
			width += ansi.StringWidth(text)
			if c.keep < weakest {
				weakest, weakestAt = c.keep, i
			}
		}

		left := strings.Join(parts, "   ")
		right := ui.Muted.Render(FormatBytes(in) + "↓  " + FormatBytes(out) + "↑")
		// The throughput goes before any count does: it is the part you can
		// also read off a row, and a count cut mid-number says nothing at all.
		switch gap := m.tableWidth() - width - ansi.StringWidth(right); {
		case gap >= 2:
			return left + strings.Repeat(" ", gap) + right
		case width <= m.tableWidth() || weakestAt < 0:
			return clampWidth(left, m.tableWidth())
		}
		chips[weakestAt].n = 0
	}
}

type columnKind int

const (
	colLocal columnKind = iota
	colArrow
	colRemote
	colMode
	colScheme
	colProcess
	colAge
	colConns
	colIn
	colOut
)

// column is one table column's position and meaning. The renderer and the
// mouse hit-testing both read this, so a click always lands on the column the
// user actually sees.
type column struct {
	kind     columnKind
	title    string
	x        int // first cell, in terminal coordinates
	w        int
	right    bool    // right-aligned
	sort     SortKey // what clicking the header sorts by
	sortable bool
	scheme   bool // clicking a cell here cycles the protocol
	mode     bool // clicking a cell here cycles auto/on/hidden
}

// columns computes a responsive table layout. The mapping and service identity
// are always present; secondary metrics disappear as groups when the terminal
// narrows, instead of letting the right edge get blindly truncated.
func (m *Model) columns() []column {
	showMode, showScheme := true, true
	showAge, showConns, showTraffic := true, true, true

	build := func(procW int) []column {
		cols := []column{
			{kind: colLocal, title: "LOCAL", w: wLocal, right: true, sort: SortLocal, sortable: true},
			{kind: colArrow, w: wArrow},
			{kind: colRemote, title: "REMOTE", w: wRemote, right: true, sort: SortRemote, sortable: true},
		}
		if showMode {
			cols = append(cols, column{kind: colMode, title: "M", w: wMode, mode: true})
		}
		if showScheme {
			cols = append(cols, column{kind: colScheme, title: "VIA", w: wScheme, scheme: true})
		}
		cols = append(cols, column{kind: colProcess, title: "PROCESS", w: procW, sort: SortProcess, sortable: true})
		if showAge {
			cols = append(cols, column{kind: colAge, title: "AGE", w: wAge, right: true, sort: SortAge, sortable: true})
		}
		if showConns {
			cols = append(cols, column{kind: colConns, title: "CONNS", w: wConns, right: true, sort: SortConns, sortable: true})
		}
		if showTraffic {
			cols = append(cols,
				column{kind: colIn, title: "IN", w: wBytes, right: true, sort: SortTraffic, sortable: true},
				column{kind: colOut, title: "OUT", w: wBytes, right: true, sort: SortTraffic, sortable: true})
		}
		return cols
	}
	widthOf := func(cols []column) int {
		w := wMark + 1
		for i, c := range cols {
			if i > 0 {
				w += gap
			}
			w += c.w
		}
		return w
	}
	// Dropped in order of what a narrow terminal can most afford to lose. M
	// goes last of all, and only when nothing else is left: it is one cell
	// wide, it is where the ✕ says which of these rows you hid, and it is a
	// control — a column you click to change the port's mode.
	fits := func() bool { return widthOf(build(minProc)) <= m.tableWidth() }
	if !fits() {
		showTraffic = false
	}
	if !fits() {
		showConns = false
	}
	if !fits() {
		showAge = false
	}
	if !fits() {
		showScheme = false
	}
	if !fits() {
		showMode = false
	}

	cols := build(minProc)
	extra := m.tableWidth() - widthOf(cols)
	procW := minProc
	if extra > 0 {
		procW += extra
		if procW > maxProc {
			procW = maxProc
		}
		cols = build(procW)
	}

	x := 1 + wMark + 1 // left border, activity marker, space
	for i := range cols {
		cols[i].x = x
		x += cols[i].w + gap
	}
	return cols
}

// tableWidth is the width the table lays out in: everything inside the frame
// except the last cell, which belongs to the scroll track. Reserving it at
// every size costs one column and keeps a right-aligned byte count from being
// clipped by a scrollbar that appeared when a port did.
func (m *Model) tableWidth() int { return m.listWidth() }

// columnAt returns the column under a terminal x position.
func (m *Model) columnAt(x int) (column, bool) {
	for _, c := range m.columns() {
		if x >= c.x && x < c.x+c.w {
			return c, true
		}
	}
	return column{}, false
}

func (m *Model) columnHeader() string {
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", wMark+1))
	for i, c := range m.columns() {
		if i > 0 {
			b.WriteString(strings.Repeat(" ", gap))
		}
		title := c.title
		// Mark the active sort so the header explains the current ordering.
		if c.sortable && c.sort == m.sortKey {
			// ▲ for ascending, which is the default. It read ↓ for ascending,
			// under a column already headed ↓REMOTE — two arrows on one line
			// meaning two different things, one of them backwards.
			arrow := "▲"
			if m.reverse {
				arrow = "▼"
			}
			if c.right {
				title = arrow + title
			} else {
				title += arrow
			}
		}
		if c.right {
			b.WriteString(padLeft(title, c.w))
		} else {
			b.WriteString(pad(title, c.w))
		}
	}
	return b.String()
}

// modeGlyph renders a port's standing decision. A hidden row is only ever on
// screen when the user asked to see hidden rows, and the ✕ is what tells them
// which of the rows in front of them are the ones they hid.
func modeGlyph(mode tunnels.Mode) string {
	switch mode {
	case tunnels.ModeOn:
		return "+"
	case tunnels.ModeHidden:
		return "✕"
	default:
		return " "
	}
}

// rowView renders one service, as one line or — when a bind error has to wrap
// — two.
func (m *Model) rowView(s tunnels.State, selected bool) []string {
	now := m.d.now()

	local, arrow, remote := "————", " ", itoa(s.RemotePort)
	switch s.Status {
	case tunnels.StatusActive:
		local = itoa(s.LocalPort)
		if s.Remapped {
			arrow = "≠"
		} else {
			arrow = "←"
		}
	case tunnels.StatusError:
		arrow = "!"
	}

	cmd := s.Cmd
	if cmd == "" {
		cmd = "(unknown)"
	}

	act := activityOf(s, now)
	text, wrapped := m.rowText(s, act, local, arrow, remote, cmd, now)
	lines := []string{clampWidth(text, m.tableWidth())}
	if wrapped != "" {
		lines = append(lines, clampWidth(errorIndent+wrapped, m.tableWidth()))
	}

	for i, line := range lines {
		if selected {
			// Pad the selection to the full table width so the highlight is a
			// bar, and over both lines so a wrapped row highlights as one row.
			if w := ansi.StringWidth(line); w < m.tableWidth() {
				line += strings.Repeat(" ", m.tableWidth()-w)
			}
			// Reverse video rather than a background colour of its own: it is
			// the one highlight that still reads on a stripped palette.
			lines[i] = ui.Selected.Reverse(true).Render(ansi.Strip(line))
			continue
		}
		switch {
		case s.Status == tunnels.StatusError:
			lines[i] = ui.Error.Render(line)
		case s.Status != tunnels.StatusActive:
			lines[i] = ui.Muted.Render(line)
		case act == activityLive:
			lines[i] = ui.Active.Render(line)
		case act == activityFresh:
			lines[i] = ui.Fresh.Render(line)
		}
	}
	return lines
}

// rowText lays out one row's columns without applying the row-level style,
// and returns whatever of a bind error would not fit on the line.
func (m *Model) rowText(s tunnels.State, act activity, local, arrow, remote, cmd string, now time.Time) (line, wrapped string) {
	prefix := marker(act) + " "
	cols := m.columns()
	procAt := -1
	for i, c := range cols {
		if c.kind == colProcess {
			procAt = i
			break
		}
	}

	reason := ""
	switch s.Status {
	case tunnels.StatusError:
		reason = s.Err
	case tunnels.StatusOffline:
		reason = "offline"
	case tunnels.StatusSkipped:
		reason = string(s.Skip)
		if s.Skip == tunnels.SkipHidden {
			reason = "hidden by you"
		}
	}
	hasTail := procAt >= 0 && procAt < len(cols)-1

	var values []string
	for i, c := range cols {
		if reason != "" && hasTail && i > procAt {
			break
		}
		value := ""
		switch c.kind {
		case colLocal:
			value = local
		case colArrow:
			value = arrow
		case colRemote:
			value = remote
		case colMode:
			value = modeGlyph(s.Mode)
		case colScheme:
			value = schemeLabel(s)
		case colProcess:
			value = displayProcess(s, cmd)
			if reason != "" && !hasTail {
				// Narrow enough that PROCESS is the last column, so this is
				// where the reason goes — and where it wraps from.
				value, wrapped = splitReason(s, reason, c.w)
			}
		case colAge:
			value = FormatAge(now.Sub(s.Created))
		case colConns:
			value = itoa(s.ActiveConns)
		case colIn:
			value = FormatBytes(s.BytesIn)
		case colOut:
			value = FormatBytes(s.BytesOut)
		}
		if c.right {
			values = append(values, padLeft(value, c.w))
		} else {
			values = append(values, pad(value, c.w))
		}
	}
	line = prefix + strings.Join(values, strings.Repeat(" ", gap))
	if reason == "" || !hasTail {
		return line, wrapped
	}
	line += strings.Repeat(" ", gap)
	head, rest := splitReason(s, reason, m.tableWidth()-ansi.StringWidth(line))
	return line + head, rest
}

const (
	// errorIndent is where a wrapped error's second line starts: clear of the
	// activity marker, and short enough that the width it buys is the point.
	errorIndent = "    "
	// minReasonHead is the least room worth starting the sentence in. Below it
	// the whole message goes to the second line: a row ending "liste" is not a
	// first line, it is a hyphenation without the hyphen.
	minReasonHead = 8
)

// splitReason decides how much of a row's reason the row itself carries and
// how much wraps onto the line beneath it.
//
// Only an error wraps. The other reasons are two words devtun wrote and they
// fit; a bind failure is a sentence sshd wrote, it is the whole content of the
// row, and at 80 columns the tail after PROCESS cut it to "listen tcp 12" — a
// row that looks like data and says nothing.
func splitReason(s tunnels.State, reason string, room int) (head, rest string) {
	if s.Status != tunnels.StatusError || ansi.StringWidth(reason) <= room {
		return reason, ""
	}
	if room < minReasonHead {
		return "", reason
	}
	return splitAt(reason, room)
}

// splitAt breaks text at the last space that fits, falling back to a hard cut
// when one word is wider than the room available.
func splitAt(text string, width int) (head, rest string) {
	if width <= 0 {
		return "", text
	}
	runes := []rune(text)
	cut := min(width, len(runes))
	for i := cut; i > width/2; i-- {
		if runes[i-1] == ' ' {
			return string(runes[:i-1]), string(runes[i:])
		}
	}
	return string(runes[:cut]), string(runes[cut:])
}

// schemeLabel marks a pinned scheme, so a protocol you chose is visibly a
// decision rather than an observation that might change under you.
func schemeLabel(s tunnels.State) string {
	if s.Scheme == tunnels.SchemeUnknown {
		return "?"
	}
	if s.SchemePinned {
		return "+" + string(s.Scheme)
	}
	return string(s.Scheme)
}

func displayProcess(s tunnels.State, fallback string) string {
	if s.Label == "" {
		return fallback
	}
	if fallback == "" || fallback == "(unknown)" {
		return s.Label
	}
	return s.Label + " · " + fallback
}

// marker is the leading activity glyph: a filled dot for a tunnel carrying
// traffic, a hollow one for a tunnel that just appeared.
func marker(act activity) string {
	switch act {
	case activityLive:
		return "●"
	case activityFresh:
		return "◦"
	default:
		return " "
	}
}

// --- keys and mouse --------------------------------------------------------

func (m *Model) handleTunnelsKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "enter", "d":
		return m.toggleDetail()
	case "a":
		return m.cycleMode()
	case "x":
		return m.hideSelected()
	// H, not ctrl+h: ctrl+h is byte 0x08, which most terminals and tmux send
	// for backspace, so the binding silently does nothing on the machines
	// where it matters. ctrl+h stays accepted for the terminals that do
	// deliver it distinctly.
	case "H", "ctrl+h":
		return m.toggleShowHidden()
	case "t":
		return m.cycleScheme()
	// b as well as o and space: b is what the key bar advertises and what a
	// browser is called, and o is already three other things elsewhere.
	// "space", not " ": Bubble Tea v2 reports a space press as the named key
	// `space`, so matching the literal never fired and the key README has
	// advertised since the first release did nothing at all.
	case "space", "o", "b":
		return m.openSelected()
	case "y":
		return m.copySelected()
	case "l":
		return m.openLocalPort()
	case "n":
		return m.openLabel()
	case "p":
		return m.togglePause()
	case "s":
		m.sortKey = m.sortKey.Next()
		m.savePrefs()
		m.reload()
		return m.showToast(toastMsg{text: "sort: " + m.sortKey.String()})
	case "r":
		m.reverse = !m.reverse
		m.savePrefs()
		m.reload()
	}
	return nil
}

// tableRowAt maps a terminal row to a table row. It goes through the same
// layout the renderer used rather than through rowAt's arithmetic, which
// assumes one line per row and so points a click after a wrapped error at the
// row above the one under the pointer.
func (m *Model) tableRowAt(y int) int {
	_, rowOf := m.tableRows()
	i := y - m.listTop()
	if i < 0 || i >= len(rowOf) {
		return -1
	}
	return rowOf[i]
}

// handleTunnelsClick handles the parts of the table that are controls rather
// than readouts.
func (m *Model) handleTunnelsClick(e tea.Mouse) tea.Cmd {
	// Clicking a column header sorts by it, and clicking it again reverses.
	if e.Y == m.listTop()-1 {
		if c, ok := m.columnAt(e.X); ok && c.sortable {
			if m.sortKey == c.sort {
				m.reverse = !m.reverse
			} else {
				m.sortKey, m.reverse = c.sort, false
			}
			m.savePrefs()
			m.reload()
			return m.showToast(toastMsg{text: "sort: " + m.sortKey.String()})
		}
		return nil
	}

	idx := m.tableRowAt(e.Y)
	if idx < 0 {
		return nil
	}
	m.setCursor(idx)
	m.clampCursor()

	// The M and VIA cells are controls, not just readouts.
	if c, ok := m.columnAt(e.X); ok {
		switch {
		case c.mode:
			m.lastClickPort = 0
			return m.cycleMode()
		case c.scheme:
			m.lastClickPort = 0
			return m.cycleScheme()
		}
	}

	now := m.d.now()
	port := m.selectedPort()
	isDouble := port == m.lastClickPort && now.Sub(m.lastClickAt) < doubleClickWindow
	m.lastClickPort, m.lastClickAt = port, now

	if !isDouble {
		return nil
	}
	m.lastClickPort = 0 // a third click starts a new pair
	return m.openSelected()
}

// --- actions ---------------------------------------------------------------

// hideSelected takes a port off the table, or puts it back when hidden rows
// are being shown. It is the one decision that needs no explanation: yes,
// postgres is running, stop telling me.
func (m *Model) hideSelected() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	if st.Mode == tunnels.ModeHidden {
		m.d.tunnels.SetMode(st.RemotePort, tunnels.ModeAuto)
		m.reload()
		return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + ": back to automatic"})
	}
	m.d.tunnels.SetMode(st.RemotePort, tunnels.ModeHidden)
	m.reload()
	if m.prefs.ShowHidden {
		return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + ": hidden (remembered)"})
	}
	return m.showToast(toastMsg{text: hiddenToast(st)})
}

// hiddenToast says the same thing either way; the named version just says it
// with a straight face. The information — which port, and how to get it back —
// is identical, so nothing is traded away for the joke.
func hiddenToast(st tunnels.State) string {
	name := st.Proc
	if st.Label != "" {
		name = st.Label
	}
	if name == "" {
		return "remote " + itoa(st.RemotePort) + " hidden — H lists hidden ports"
	}
	return "remote " + itoa(st.RemotePort) + " hidden — " + name + " can stop telling you about itself (H lists hidden)"
}

// toggleShowHidden lists or unlists the ports the user hid. It forwards
// nothing: it is the only way back to a row you hid, and nothing more.
func (m *Model) toggleShowHidden() tea.Cmd {
	m.prefs.ShowHidden = !m.prefs.ShowHidden
	m.savePrefs()
	m.reload()
	if m.prefs.ShowHidden {
		return m.showToast(toastMsg{text: "showing hidden ports — x unhides the selected one"})
	}
	return m.showToast(toastMsg{text: "hiding hidden ports"})
}

// cycleMode steps the selected port through auto → on → hidden.
func (m *Model) cycleMode() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	mode := m.d.tunnels.CycleMode(st.RemotePort)
	m.reload()

	switch mode {
	case tunnels.ModeOn:
		return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + ": always forward (remembered)"})
	case tunnels.ModeHidden:
		return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + ": hidden (remembered)"})
	default:
		return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + ": back to automatic"})
	}
}

// cycleScheme steps the selected row through unknown → http → https.
func (m *Model) cycleScheme() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	scheme := m.d.tunnels.CycleScheme(st.RemotePort)
	m.reload()
	if scheme == tunnels.SchemeUnknown {
		return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + ": protocol unset"})
	}
	return m.showToast(toastMsg{text: "remote " + itoa(st.RemotePort) + " is " + string(scheme) + " (remembered)"})
}

func (m *Model) openSelected() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	if st.Status != tunnels.StatusActive {
		return m.showToast(toastMsg{text: "no tunnel to open", bad: true})
	}
	// Opening an unidentified port needs a protocol choice. The chooser both
	// opens it and remembers the answer, instead of making the user press two
	// unrelated shortcuts in sequence.
	if st.Scheme == tunnels.SchemeUnknown {
		m.protocolPrompt = true
		return nil
	}
	url := st.URL()
	if err := m.openURL(url); err != nil {
		return m.showToast(toastMsg{text: "open failed: " + err.Error(), bad: true})
	}
	return m.showToast(toastMsg{text: "opened " + url})
}

// openURL hands a URL to the platform launcher, defaulting to the shared one.
func (m *Model) openURL(url string) error {
	open := m.d.openURL
	if open == nil {
		open = ui.OpenURL
	}
	return open(context.Background(), url)
}

func (m *Model) copySelected() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	if st.Status != tunnels.StatusActive {
		return m.showToast(toastMsg{text: "no tunnel to copy", bad: true})
	}
	value := st.Endpoint()
	if st.Scheme != tunnels.SchemeUnknown {
		value = st.URL()
	}
	return tea.Batch(yank(value), m.showToast(toastMsg{text: "copied " + value}))
}

func (m *Model) togglePause() tea.Cmd {
	p := m.d.tunnels.Policy()
	p.Paused = !p.Paused
	m.d.tunnels.SetPolicy(p)
	m.reload()
	if p.Paused {
		return m.showToast(toastMsg{text: "paused: current tunnels stay up; new automatic tunnels will wait"})
	}
	return m.showToast(toastMsg{text: "resumed"})
}

// openLocalPort starts editing the selected row's local port.
func (m *Model) openLocalPort() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	m.editor = editorLocalPort
	m.editorPort = st.RemotePort
	if st.PinnedLocal > 0 {
		m.input.SetValue(itoa(st.PinnedLocal))
	} else {
		m.input.SetValue("")
	}
	return nil
}

// openLabel starts editing the selected port's remembered display name.
func (m *Model) openLabel() tea.Cmd {
	st, ok := m.selectedRow()
	if !ok {
		return m.needSelection()
	}
	m.editor = editorPortLabel
	m.editorPort = st.RemotePort
	m.input.SetValue(st.Label)
	return nil
}

func (m *Model) handleProtocolKey(msg tea.KeyPressMsg) tea.Cmd {
	var scheme tunnels.Scheme
	switch msg.String() {
	case "enter", "h", "1":
		scheme = tunnels.SchemeHTTP
	case "s", "2":
		scheme = tunnels.SchemeHTTPS
	case "esc", "q":
		m.protocolPrompt = false
		return nil
	default:
		return nil
	}
	return m.chooseProtocol(scheme)
}

func (m *Model) chooseProtocol(scheme tunnels.Scheme) tea.Cmd {
	st, ok := m.selectedRow()
	m.protocolPrompt = false
	if !ok {
		return m.needSelection()
	}
	m.d.tunnels.SetScheme(st.RemotePort, scheme)
	m.reload()
	return m.openSelected()
}

// --- boxes -----------------------------------------------------------------

func (m *Model) protocolBox() string {
	s, ok := m.selectedRow()
	if !ok {
		return ""
	}
	body := ui.Banner.Render(fmt.Sprintf("Open remote :%d", s.RemotePort)) + "\n\n" +
		ui.Muted.Render("Choose the web protocol. This is remembered for this host and port.") + "\n\n" +
		ui.Banner.Render("enter / h") + ui.Muted.Render(" http") + ui.Muted.Render("   ·   ") +
		ui.Banner.Render("s") + ui.Muted.Render(" https") + ui.Muted.Render("   ·   ") +
		ui.Banner.Render("esc") + ui.Muted.Render(" cancel")
	return m.boxOf(body)
}

// protocolChoiceAt maps a click inside the protocol box onto a choice.
func (m *Model) protocolChoiceAt(x, y int) (tunnels.Scheme, bool) {
	box := m.protocolBox()
	lines := strings.Split(box, "\n")
	if len(lines) < 2 {
		return tunnels.SchemeUnknown, false
	}
	boxW := 0
	for _, line := range lines {
		if w := ansi.StringWidth(line); w > boxW {
			boxW = w
		}
	}
	left := max((m.width-boxW)/2, 0)
	top := max((m.height-len(lines))/2, 0)
	choiceRow := len(lines) - 2
	if y != top+choiceRow {
		return tunnels.SchemeUnknown, false
	}
	plain := ansi.Strip(lines[choiceRow])
	for _, choice := range []struct {
		needle string
		scheme tunnels.Scheme
	}{
		{"enter / h http", tunnels.SchemeHTTP},
		{"s https", tunnels.SchemeHTTPS},
	} {
		start := strings.Index(plain, choice.needle)
		if start < 0 {
			continue
		}
		cellStart := ansi.StringWidth(plain[:start])
		cellEnd := cellStart + ansi.StringWidth(choice.needle)
		if x >= left+cellStart && x < left+cellEnd {
			return choice.scheme, true
		}
	}
	return tunnels.SchemeUnknown, false
}

// tunnelDetailBox is the per-port detail overlay.
func (m *Model) tunnelDetailBox() string {
	s, ok := m.selectedRow()
	if !ok {
		return ""
	}
	row := func(label, value string) string {
		if value == "" {
			return ""
		}
		return ui.Muted.Render(pad(label, 13)) + value + "\n"
	}

	var b strings.Builder
	b.WriteString(ui.Banner.Render(fmt.Sprintf("remote :%d", s.RemotePort)) + "\n\n")
	b.WriteString(row("name", s.Label))
	if s.Status == tunnels.StatusActive {
		if s.Scheme == tunnels.SchemeUnknown {
			b.WriteString(row("endpoint", s.Endpoint()))
		} else {
			b.WriteString(row("url", s.URL()))
		}
		b.WriteString(row("local", fmt.Sprintf("%s:%d", s.LocalAddr, s.LocalPort)))
		if s.Remapped {
			b.WriteString(row("", ui.Warn.Render("remapped — the remote port was busy locally")))
		}
	}
	b.WriteString(row("status", string(s.Status)))
	if s.Skip != "" {
		b.WriteString(row("reason", string(s.Skip)))
	}
	b.WriteString(row("mode", modeName(s.Mode)))
	if s.PinnedLocal > 0 {
		b.WriteString(row("pinned to", fmt.Sprintf("local %d", s.PinnedLocal)))
	}
	b.WriteString(row("protocol", s.Scheme.Label()))
	b.WriteString(row("command", s.Cmd))
	if s.PID > 0 {
		b.WriteString(row("pid", itoa(s.PID)))
	}
	b.WriteString(row("bound to", s.Binds))
	b.WriteString(row("first seen", FormatAge(m.d.now().Sub(s.FirstSeen))+" ago"))
	if s.Status == tunnels.StatusActive {
		b.WriteString(row("open since", FormatAge(m.d.now().Sub(s.Created))))
		b.WriteString(row("connections", fmt.Sprintf("%d active · %d total", s.ActiveConns, s.TotalConns)))
		b.WriteString(row("traffic", fmt.Sprintf("%s in · %s out", FormatBytes(s.BytesIn), FormatBytes(s.BytesOut))))
		if !s.LastByte.IsZero() {
			b.WriteString(row("last byte", FormatAge(m.d.now().Sub(s.LastByte))+" ago"))
		}
	}
	if s.Err != "" {
		b.WriteString(row("error", ui.Error.Render(s.Err)))
	}
	b.WriteString("\n" + ui.Muted.Render("esc to close"))
	return m.boxOf(strings.TrimRight(b.String(), "\n"))
}

// reconnectBox is the waiting screen shown while the link is down.
//
// It says what is remembered, not just what is broken: the local assignments
// are retained and devtun tries to reclaim them after reconnecting.
func (m *Model) reconnectBox() string {
	held := 0
	for _, r := range m.rows {
		if r.Status == tunnels.StatusOffline || r.Status == tunnels.StatusActive {
			held++
		}
	}

	var b strings.Builder
	if m.status.State == session.Reconnecting {
		b.WriteString(ui.Warn.Render("◦  Reconnecting to " + m.d.host))
	} else {
		b.WriteString(ui.Error.Render("○  Connection lost"))
	}
	b.WriteString("\n\n")

	if detail := strings.TrimSpace(m.status.Detail); detail != "" {
		b.WriteString(ui.Muted.Render(firstLine(detail)) + "\n\n")
	}

	if held > 0 {
		b.WriteString(fmt.Sprintf("Remembering %d tunnel assignment%s.", held, plural(held)) + "\n")
		b.WriteString(ui.Muted.Render("devtun will try to reclaim the same local port numbers.") + "\n\n")
	}

	switch {
	case m.status.State == session.Reconnecting:
		b.WriteString(ui.Muted.Render("Trying now…"))
	case !m.status.NextRetry.IsZero():
		wait := m.status.NextRetry.Sub(m.d.now())
		if wait < 0 {
			wait = 0
		}
		b.WriteString(ui.Muted.Render(fmt.Sprintf("Next attempt in %ds", int(wait.Seconds()+0.5))))
	default:
		b.WriteString(ui.Muted.Render("Waiting…"))
	}
	if m.status.Attempt > 1 {
		b.WriteString(ui.Muted.Render(fmt.Sprintf("   (attempt %d)", m.status.Attempt)))
	}

	b.WriteString("\n\n")
	b.WriteString(ui.Banner.Render("r") + ui.Muted.Render(" try now") + ui.Muted.Render("   ·   ") +
		ui.Banner.Render("esc") + ui.Muted.Render(" quit"))

	return m.boxOf(b.String())
}

// modeName spells out a port's standing decision for the detail box.
//
// ModeAuto's string is empty and `row` drops empty values, so the one field
// the whole hide-and-show model turns on was invisible in the one place that
// exists to explain a port.
func modeName(mode tunnels.Mode) string {
	if mode == "" {
		return string(tunnels.ModeAuto)
	}
	return string(mode)
}
