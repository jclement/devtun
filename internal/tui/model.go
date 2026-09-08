package tui

import (
	"context"
	"math/rand"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
)

// tunnelCtrl is the slice of the tunnels service this interface drives.
//
// It is an interface so the whole view layer is testable with a stub: no SSH,
// no listeners, no clock. *tunnels.Manager and *tunnels.Service between them
// satisfy it; tunnelAdapter joins the two.
type tunnelCtrl interface {
	States() []tunnels.State
	SetMode(remotePort int, mode tunnels.Mode) tunnels.Mode
	CycleMode(remotePort int) tunnels.Mode
	CycleScheme(remotePort int) tunnels.Scheme
	SetScheme(remotePort int, scheme tunnels.Scheme) tunnels.Scheme
	SetLocalPort(remotePort, local int) error
	SetLabel(remotePort int, label string) error
	Policy() tunnels.Policy
	SetPolicy(tunnels.Policy)
	ViewPrefs() tunnels.ViewPrefs
	SetViewPrefs(tunnels.ViewPrefs)
	// Hidden counts ports the user has hidden. It cannot come from States,
	// which omits them.
	Hidden() int
}

// secretsCtrl is the slice of a broker that the Access tab drives.
type secretsCtrl interface {
	Rules() []authz.Rule
	GlobalRules() []authz.Rule
	Revoke(index int) error
	Deny(index int) error
	Grants() []authz.Grant
	RevokeGrant(host, subject string) bool
	Forget() (grants, cached int)
}

// accessSource is one broker's slice of the Access tab.
//
// There are two now — the vault and the agent — and there will be more. They
// are listed together rather than on separate tabs because the question the tab
// answers is "what is open in my name right now", and that question does not
// care which broker holds the door. The source is a column, not a screen.
type accessSource struct {
	id    string
	title string
	ctrl  secretsCtrl
}

// configStore is where the Services and Config tabs read and record devtun's
// own settings.
//
// Everything is addressed as (section, key) at one level — an empty label is
// the global file — rather than resolved, because telling "this host says tui"
// from "the global file says tui" is the whole point of showing a setting at
// all, and a resolving read cannot.
type configStore interface {
	Enabled(label, serviceID string, fallback bool) bool
	SetEnabled(label, serviceID string, enabled bool)
	Setting(label, section, key string) string
	SetSetting(label, section, key, value string) error
	Save() error
}

// deps is everything the model needs, narrowed to interfaces and functions.
// Run builds one from Options; a test builds one by hand.
type deps struct {
	tunnels  tunnelCtrl
	secrets  []accessSource
	store    configStore
	services []service.Service

	// status and retry are the session, narrowed to the two things the
	// interface asks of it: how are we doing, and try again now.
	status func() session.Status
	retry  func()

	// promptBackend is where approvals are appearing right now, and
	// applyPrompt puts a changed setting into effect without a reconnect —
	// the one config change this session can honour immediately, and the one
	// where waiting for the next connection would mean missing the request you
	// were trying to catch.
	promptBackend prompt.Backend
	applyPrompt   func(prompt.Backend)

	host    string
	version string
	// webURL is the browser board, when one is running. It carries a token, so
	// it is long and unmemorable — and it arrives in the activity log, which
	// the mouse cannot select because the mouse belongs to the table. `w` is
	// the way to get at it without asking anybody to retype forty characters.
	webURL string

	// dissolve enables the exit animation.
	dissolve bool
	// now is injectable for deterministic tests.
	now func() time.Time
	// rng seeds the dissolve animation.
	rng *rand.Rand
	// openURL is the browser launcher.
	openURL func(context.Context, string) error
}

// Messages the model handles beyond Bubble Tea's own.
type (
	// eventMsg is one line of activity, forwarded from the bus.
	eventMsg event.Event
	// fatalMsg terminates the interface with an error.
	fatalMsg struct{ err error }
	// toastMsg shows a transient message in the footer.
	toastMsg struct {
		text string
		bad  bool
	}
	refreshMsg      time.Time
	dissolveMsg     time.Time
	toastExpiredMsg int
)

const (
	refreshInterval  = 400 * time.Millisecond
	dissolveInterval = 33 * time.Millisecond
	toastDuration    = 3 * time.Second
	// scrollback is how many events the activity tab keeps. It matches the
	// bus's own retention, so scrolling to the top of the tab reaches exactly
	// as far back as the session remembers.
	scrollback = 2000
)

// editorKind names the inline text entry currently open.
type editorKind int

const (
	editorNone editorKind = iota
	editorSearch
	editorLocalPort
	editorPortLabel
	editorConfigValue
)

// noSelection is the cursor value meaning "nothing highlighted yet".
const noSelection = -1

// Model is the Bubble Tea model for the whole interface.
type Model struct {
	d deps

	width, height int
	started       time.Time
	tab           tab

	// cursors and offsets are per tab: switching away and back should return
	// you to where you were, not to the top.
	cursors [tabCount]int
	offsets [tabCount]int
	search  [tabCount]string

	// Tunnels tab.
	rows    []tunnels.State
	sortKey SortKey
	reverse bool
	prefs   tunnels.ViewPrefs
	// bind is the local address tunnels are listening on, learned from the
	// rows themselves. It drives the LAN warning.
	bind string

	// Activity tab. log is everything; logRows is what the filter and the
	// search have left of it.
	log       []event.Event
	logRows   []event.Event
	logFilter event.Class

	// Secrets and Services tabs.
	accessRows []accessRow
	svcRows    []serviceRow
	// svcState is what the session has said about each service, keyed by id.
	svcState map[string]svcState

	// Config tab. cfgLevel is the file the next edit lands in, and it is state
	// rather than a per-row question so that arming it once covers a run of
	// edits — which is how somebody setting a box up actually works.
	cfgRows  []cfgRow
	cfgLevel cfgLevel
	// dialogPick memoises which program could raise a desktop dialog here.
	dialogPick *string
	// promptNow is where approvals are appearing, which the command line can
	// have decided rather than the files.
	promptNow prompt.Backend

	// Inline editor in the bottom border.
	editor        editorKind
	editorPort    int
	editorSetting string
	input         textInput

	showHelp   bool
	showDetail bool
	// mouseOff suspends mouse reporting so the terminal's own selection works
	// again. See View: while devtun is reading the mouse, you cannot drag
	// across a URL to copy it.
	mouseOff bool
	// protocolPrompt asks http or https before opening a port we cannot
	// classify.
	protocolPrompt bool
	confirming     bool
	approval       *approvalState
	setup          *setupState

	status session.Status
	// everConnected gates the reconnect screen: a drop only counts as an
	// outage once there has been something to lose.
	everConnected bool

	toast    toastMsg
	toastID  int
	hasToast bool

	lastClickPort int
	lastClickAt   time.Time
	// footerZones and tabZones map clickable spans, recorded as they render so
	// a click always hits what is actually on screen.
	footerZones []zone
	tabZones    []zone

	dissolving *dissolve

	fatal error
	quit  bool
}

// zone is a clickable span on a single line.
type zone struct {
	x0, x1 int // half-open range of terminal columns
	id     string
}

// contains reports whether x falls inside the zone.
func (z zone) contains(x int) bool { return x >= z.x0 && x < z.x1 }

// newModel builds a model. It does no I/O.
func newModel(d deps) *Model {
	if d.now == nil {
		d.now = time.Now
	}
	if d.rng == nil {
		d.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if d.tunnels == nil {
		d.tunnels = tunnelAdapter{}
	}

	prefs := d.tunnels.ViewPrefs()
	m := &Model{
		d:       d,
		width:   80,
		height:  24,
		started: d.now(),
		prefs:   prefs,
		sortKey: sortKeyNamed(prefs.Sort),
		reverse: prefs.Reverse,
		status:  session.Status{State: session.Connecting},
		// Edits start aimed at this host: the per-host file is the one people
		// mean, and a first keystroke that quietly changed every box would be
		// the wrong direction to be surprised in.
		cfgLevel:  levelHost,
		promptNow: d.promptBackend,
		svcState:  map[string]svcState{},
	}
	for i := range m.cursors {
		// Nothing is highlighted until you move: a selection bar on arrival
		// implies you already chose something.
		m.cursors[i] = noSelection
	}
	m.reload()
	return m
}

// Init starts the refresh ticker.
func (m *Model) Init() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return refreshMsg(t) })
}

// Err returns the error the interface exited with, if any.
func (m *Model) Err() error { return m.fatal }

// editing reports whether an inline text entry is open.
func (m *Model) editing() bool { return m.editor != editorNone }

// overlayOpen reports whether a modal layer is covering the body.
// overlayOpen reports whether a modal layer is covering the body.
//
// offline() belongs here and was missing, which made the "connection lost" box
// the one overlay you could act straight through: a click still moved the
// table's cursor and `x` still hid a port, behind a box that said the
// connection was gone.
func (m *Model) overlayOpen() bool {
	return m.approval != nil || m.setup != nil || m.confirming || m.showHelp ||
		m.showDetail || m.protocolPrompt || m.editing() || m.offline()
}

// Update handles one message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clampCursor()
		return m, nil

	case fatalMsg:
		m.fatal = msg.err
		m.quit = true
		return m, tea.Quit

	case eventMsg:
		m.record(event.Event(msg))
		return m, nil

	case seedMsg:
		for _, e := range msg {
			m.record(e)
		}
		return m, nil

	case bellMsg:
		// Written straight to the terminal, not through tea.Printf and not
		// into the view.
		//
		// The view is a cell buffer, which would draw a bare \a as a character
		// rather than ring anything. tea.Printf is worse: it prints a line
		// *above* the program, which scrolls the frame and eats the top row —
		// the window losing its first line at apparently random moments, which
		// is exactly what it did.
		//
		// BEL moves no cursor and occupies no cell, so writing it directly
		// past the renderer disturbs nothing.
		ring()
		return m, nil

	case toastMsg:
		return m, m.showToast(msg)

	case toastExpiredMsg:
		if int(msg) == m.toastID {
			m.hasToast = false
		}
		return m, nil

	case refreshMsg:
		if m.dissolving == nil {
			m.status = m.sessionStatus()
			if m.status.State == session.Connected {
				m.everConnected = true
			}
			m.reload()
		}
		return m, tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return refreshMsg(t) })

	case dissolveMsg:
		if m.dissolving == nil {
			return m, nil
		}
		m.dissolving.Advance()
		if m.dissolving.Done() {
			m.quit = true
			return m, tea.Quit
		}
		return m, tea.Tick(dissolveInterval, func(t time.Time) tea.Msg { return dissolveMsg(t) })

	case approvalMsg:
		return m, m.openApproval(msg)

	case approvalCancelMsg:
		m.dismissApproval(msg.reply)
		return m, nil

	case setupMsg:
		m.setup = &setupState{plan: msg.plan, reply: msg.reply}
		return m, nil

	case setupCancelMsg:
		if m.setup != nil && m.setup.reply == msg.reply {
			m.setup = nil
		}
		return m, nil

	case tea.MouseWheelMsg:
		return m, m.handleWheel(msg.Mouse())

	case tea.MouseClickMsg:
		return m, m.handleClick(msg.Mouse())

	case tea.KeyPressMsg:
		return m, m.handleKey(msg)
	}
	return m, nil
}

// sessionStatus reads the supervisor's current state, tolerating a model built
// without one.
func (m *Model) sessionStatus() session.Status {
	if m.d.status == nil {
		return m.status
	}
	return m.d.status()
}

// record files one event: into the scrollback, and into the per-service state
// the Services tab reads.
//
// The session reports every attach outcome through the bus stamped with the
// service's own id, so the Services tab needs no second channel to the
// supervisor — and it is right again after a reconnect for free.
func (m *Model) record(e event.Event) {
	m.log = append(m.log, e)
	if len(m.log) > scrollback {
		copy(m.log, m.log[len(m.log)-scrollback:])
		m.log = m.log[:scrollback]
	}
	if m.noteService(e) {
		// The Services tab reads this event stream, so a service coming up or
		// failing to must land on it now rather than on the next refresh tick.
		m.reloadServices()
	}
	m.reloadActivity()
}

// showToast puts a transient line in the footer.
func (m *Model) showToast(t toastMsg) tea.Cmd {
	m.toast = t
	m.hasToast = true
	m.toastID++
	id := m.toastID
	return tea.Tick(toastDuration, func(time.Time) tea.Msg { return toastExpiredMsg(id) })
}

// --- selection -------------------------------------------------------------

// rowCount is how many rows the current tab has.
func (m *Model) rowCount() int {
	switch m.tab {
	case tabActivity:
		return len(m.logRows)
	case tabAccess:
		return len(m.accessRows)
	case tabServices:
		return len(m.svcRows)
	case tabConfig:
		return len(m.cfgRows)
	default:
		return len(m.rows)
	}
}

// selectable reports whether a row can hold the cursor. Only the Config tab has
// rows that cannot: its section headings are structure, not settings.
func (m *Model) selectable(i int) bool {
	if m.tab != tabConfig {
		return true
	}
	return i >= 0 && i < len(m.cfgRows) && m.cfgRows[i].setting != nil
}

// nextSelectable walks from i in the direction of travel to the first row that
// can hold the cursor, turning back at the end of the list rather than leaving
// the selection on a heading.
func (m *Model) nextSelectable(i, delta int) int {
	step := 1
	if delta < 0 {
		step = -1
	}
	n := m.rowCount()
	for j := i; j >= 0 && j < n; j += step {
		if m.selectable(j) {
			return j
		}
	}
	for j := i; j >= 0 && j < n; j -= step {
		if m.selectable(j) {
			return j
		}
	}
	return i
}

func (m *Model) cursor() int     { return m.cursors[m.tab] }
func (m *Model) offset() int     { return m.offsets[m.tab] }
func (m *Model) setCursor(i int) { m.cursors[m.tab] = i }

// move steps the selection, starting it at the first row if nothing is
// highlighted yet.
func (m *Model) move(delta int) {
	n := m.rowCount()
	if n == 0 {
		m.setCursor(noSelection)
		return
	}
	// Once a row is highlighted, moving stays within the list: stepping off
	// the top should stop at the first row, not fall back to no selection.
	target := 0
	if m.cursor() == noSelection {
		if delta < 0 {
			target = n - 1
		}
	} else {
		target = m.cursor() + delta
	}
	if target < 0 {
		target = 0
	}
	if target >= n {
		target = n - 1
	}
	m.setCursor(m.nextSelectable(target, delta))
	m.clampCursor()
}

// clampCursor keeps the cursor inside the list and the list inside the window.
func (m *Model) clampCursor() {
	n, h := m.rowCount(), m.listHeight()
	if n == 0 {
		m.cursors[m.tab], m.offsets[m.tab] = noSelection, 0
		return
	}
	if m.cursors[m.tab] == noSelection {
		m.offsets[m.tab] = 0
		return
	}
	if m.cursors[m.tab] >= n {
		m.cursors[m.tab] = n - 1
	}
	if m.cursors[m.tab] < 0 {
		m.cursors[m.tab] = 0
	}
	if m.cursors[m.tab] < m.offsets[m.tab] {
		m.offsets[m.tab] = m.cursors[m.tab]
	}
	if h > 0 && m.cursors[m.tab] >= m.offsets[m.tab]+h {
		m.offsets[m.tab] = m.cursors[m.tab] - h + 1
	}
	if max := n - h; m.offsets[m.tab] > max {
		m.offsets[m.tab] = max
	}
	if m.offsets[m.tab] < 0 {
		m.offsets[m.tab] = 0
	}
}

// --- reload ----------------------------------------------------------------

// reload pulls fresh state for every tab. It runs on the refresh tick, so the
// cost of it is paid twice a second whatever is on screen — cheap, and it
// keeps the header counts honest regardless of which tab is showing.
func (m *Model) reload() {
	m.reloadTunnels()
	m.reloadActivity()
	m.reloadAccess()
	m.reloadServices()
	m.reloadConfig()
	m.clampCursor()
}

// reloadTunnels pulls fresh tunnel state, preserving the selected port across
// reorderings.
func (m *Model) reloadTunnels() {
	selected := m.selectedPort()

	rows := m.d.tunnels.States()
	if len(rows) > 0 {
		// Every listener shares one bind address, so any row can report it.
		// Remembering it means the LAN warning survives the table emptying.
		m.bind = rows[0].LocalAddr
	}
	rows = filterStates(rows, m.search[tabTunnels])
	sortStates(rows, m.sortKey, m.reverse, m.prefs.InactiveLast)
	m.rows = rows

	if selected > 0 {
		m.cursors[tabTunnels] = noSelection
		for i, r := range rows {
			if r.RemotePort == selected {
				m.cursors[tabTunnels] = i
				break
			}
		}
	}
}

func (m *Model) selectedPort() int {
	if st, ok := m.selectedRow(); ok {
		return st.RemotePort
	}
	return 0
}

func (m *Model) selectedRow() (tunnels.State, bool) {
	i := m.cursors[tabTunnels]
	if i >= 0 && i < len(m.rows) {
		return m.rows[i], true
	}
	return tunnels.State{}, false
}

// needSelection nudges the user when an action requires a highlighted row.
func (m *Model) needSelection() tea.Cmd {
	if m.rowCount() == 0 {
		return nil
	}
	return m.showToast(toastMsg{text: "pick a row first — ↑↓ or click", bad: true})
}

// --- keys ------------------------------------------------------------------

// handleKey routes a key press through the modal layers, innermost first.
func (m *Model) handleKey(msg tea.KeyPressMsg) tea.Cmd {
	if m.dissolving != nil {
		// Once the screen is falling apart, any key skips to the end.
		m.quit = true
		return tea.Quit
	}
	// The approval modal is the most modal thing in the app: a request is
	// waiting on an answer, and everything else can wait for it.
	if m.approval != nil {
		return m.handleApprovalKey(msg)
	}
	if m.setup != nil {
		return m.handleSetupKey(msg)
	}
	if m.confirming {
		return m.handleConfirmKey(msg)
	}
	if m.editing() {
		return m.handleEditorKey(msg)
	}
	if m.protocolPrompt {
		return m.handleProtocolKey(msg)
	}
	if m.offline() {
		if cmd, handled := m.handleOfflineKey(msg); handled {
			return cmd
		}
	}
	if m.showHelp {
		switch msg.String() {
		case "?", "esc", "q", "enter":
			m.showHelp = false
			return nil
		}
	}
	if m.showDetail {
		switch msg.String() {
		case "esc", "enter", "d", "q":
			m.showDetail = false
			return nil
		}
	}
	// The Config tab is the one that claims keys *before* the global handler:
	// it needs ← and → to change a value, and `g` to arm which file an edit
	// lands in. Everything it does not claim — tab, the digits, search, quit —
	// still falls through, so nothing else is traded away.
	if m.tab == tabConfig {
		if cmd, handled := m.handleConfigKey(msg); handled {
			return cmd
		}
	}
	if cmd, handled := m.handleGlobalKey(msg); handled {
		return cmd
	}
	switch m.tab {
	case tabActivity:
		return m.handleActivityKey(msg)
	case tabAccess:
		return m.handleAccessKey(msg)
	case tabServices:
		return m.handleServicesKey(msg)
	default:
		return m.handleTunnelsKey(msg)
	}
}

// handleGlobalKey handles what every tab shares: leaving, moving, switching
// tab, searching and help.
func (m *Model) handleGlobalKey(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "ctrl+c":
		// Ctrl-C is the impatient exit: no confirmation, no animation.
		m.quit = true
		return tea.Quit, true

	case "q", "esc":
		m.confirming = true
		return nil, true

	// Left and right walk the tabs, which is what a hand reaches for before it
	// finds tab/shift+tab. The places that need them for something of their
	// own — the inline editor, and the Config tab, where they change the value
	// under the cursor — take their keys before this handler sees them.
	case "tab", "right":
		return m.selectTab(m.tab.next(1)), true
	case "shift+tab", "left":
		return m.selectTab(m.tab.next(-1)), true
	case "1", "2", "3", "4", "5":
		n, _ := strconv.Atoi(msg.String())
		return m.selectTab(tab(n - 1)), true

	case "up", "k":
		m.move(-1)
		return nil, true
	case "down", "j":
		m.move(1)
		return nil, true
	case "pgup", "ctrl+u":
		m.move(-m.listHeight())
		return nil, true
	case "pgdown", "ctrl+d":
		m.move(m.listHeight())
		return nil, true
	case "home", "g":
		m.setCursor(0)
		m.clampCursor()
		return nil, true
	case "end", "G":
		m.setCursor(m.rowCount() - 1)
		m.clampCursor()
		return nil, true

	case "/":
		m.openSearch()
		return nil, true
	case "?":
		m.showHelp = !m.showHelp
		return nil, true
	// c kept its meaning when the settings popup became a tab. It is in
	// people's fingers, and the tab bar is not where somebody looks for a
	// keystroke they already know.
	case "c":
		return m.selectTab(tabConfig), true
	case "w":
		return m.openWeb(), true
	case "R":
		return m.reconnect(), true
	case "m":
		m.mouseOff = !m.mouseOff
		if m.mouseOff {
			return m.showToast(toastMsg{text: "mouse off — the terminal can select text again; m to switch back"}), true
		}
		return m.showToast(toastMsg{text: "mouse on — rows and tabs are clickable"}), true
	}
	return nil, false
}

// openWeb opens the browser board and puts its URL on the clipboard.
//
// Both, rather than a choice: opening it is what you wanted, and the copy is
// for the case where the browser is on another machine — or where it opened
// somewhere you did not expect and you want to paste it somewhere you did.
// OSC 52 means the copy works over SSH, which is the case that matters.
func (m *Model) openWeb() tea.Cmd {
	if m.d.webURL == "" {
		return m.showToast(toastMsg{text: "no web board — start devtun with --web", bad: true})
	}
	if err := m.openURL(m.d.webURL); err != nil {
		// The clipboard still works, so this is a warning and not a dead end.
		return tea.Batch(yank(m.d.webURL), m.showToast(toastMsg{
			text: "copied the web board URL — could not open it: " + err.Error(), bad: true,
		}))
	}
	return tea.Batch(yank(m.d.webURL), m.showToast(toastMsg{text: "opened the web board · URL copied"}))
}

// selectTab switches tabs, keeping each tab's own cursor.
func (m *Model) selectTab(t tab) tea.Cmd {
	if t < 0 || t >= tabCount || t == m.tab {
		return nil
	}
	m.tab = t
	m.showDetail = false
	m.clampCursor()
	return nil
}

func (m *Model) handleConfirmKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "y", "Y", "enter":
		m.confirming = false
		return m.beginQuit()
	case "n", "N", "esc", "q", "ctrl+c":
		m.confirming = false
		return nil
	}
	return nil
}

// handleOfflineKey handles the reconnect screen. Only the key it owns is
// claimed; quitting and the rest of the interface still work behind it.
// handleOfflineKey answers the reconnect box.
//
// `r` works here for the hands that already learned it, but the binding that
// matters is the global `R`: `r` means "reverse the sort" on the tunnels tab
// and "revoke" on the access tab, so which of the three it meant depended on
// whether the link happened to be up. A key whose meaning changes with the
// connection state is a key nobody can rely on.
func (m *Model) handleOfflineKey(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	if msg.String() != "r" {
		return nil, false
	}
	return m.reconnect(), true
}

// reconnect cuts the backoff short. It is what you press after opening a
// laptop lid: the wait was measured against an outage that has already ended.
func (m *Model) reconnect() tea.Cmd {
	if m.d.retry == nil {
		return nil
	}
	m.d.retry()
	m.status.NextRetry = time.Time{}
	return m.showToast(toastMsg{text: "reconnecting…"})
}

func (m *Model) handleEditorKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "ctrl+c":
		kind := m.editor
		m.closeEditor()
		if kind == editorSearch {
			m.search[m.tab] = ""
			m.reload()
		}
		return nil
	case "enter":
		switch m.editor {
		case editorLocalPort:
			return m.applyLocalPort()
		case editorPortLabel:
			return m.applyLabel()
		case editorConfigValue:
			return m.applyConfigValue()
		}
		m.closeEditor()
		return nil
	}
	if m.input.Update(msg) && m.editor == editorSearch {
		m.search[m.tab] = m.input.Value()
		m.setCursor(noSelection)
		m.reload()
	}
	return nil
}

// closeEditor dismisses the inline editor.
func (m *Model) closeEditor() {
	m.editor = editorNone
	m.editorPort = 0
	m.editorSetting = ""
	m.input.Reset()
}

// openSearch starts a search of the current tab.
func (m *Model) openSearch() {
	m.editor = editorSearch
	m.input.SetValue(m.search[m.tab])
}

// beginQuit starts the dissolve, or quits immediately when it is disabled.
func (m *Model) beginQuit() tea.Cmd {
	if !m.d.dissolve || m.width <= 0 || m.height <= 0 {
		m.quit = true
		return tea.Quit
	}
	m.dissolving = newDissolve(m.baseView(), m.width, m.height, m.d.rng)
	return tea.Tick(dissolveInterval, func(t time.Time) tea.Msg { return dissolveMsg(t) })
}

// --- mouse -----------------------------------------------------------------

// doubleClickWindow is how close two clicks must be to count as a double click.
const doubleClickWindow = 450 * time.Millisecond

// handleWheel scrolls the list regardless of where the pointer is.
func (m *Model) handleWheel(e tea.Mouse) tea.Cmd {
	if m.dissolving != nil || m.overlayOpen() {
		return nil
	}
	switch e.Button {
	case tea.MouseWheelUp:
		m.move(-1)
	case tea.MouseWheelDown:
		m.move(1)
	}
	return nil
}

// handleClick routes a left click over the whole interface: the tab bar
// switches tab, the column headers sort, the key bar runs its action, a row
// selects, the M and VIA cells cycle, a double click opens, and an open
// overlay swallows the click.
func (m *Model) handleClick(e tea.Mouse) tea.Cmd {
	if m.dissolving != nil || e.Button != tea.MouseLeft {
		return nil
	}

	// A request waiting on an answer is not something to click past — and
	// neither is a lost connection, which used to be the one box you could
	// reach through: a click behind it still moved the cursor, and `x` still
	// hid a port, while the box said the link was gone.
	if m.approval != nil || m.setup != nil || m.offline() {
		return nil
	}
	if m.protocolPrompt {
		if scheme, ok := m.protocolChoiceAt(e.X, e.Y); ok {
			return m.chooseProtocol(scheme)
		}
		m.protocolPrompt = false
		return nil
	}
	// A click anywhere dismisses a detail or help overlay, the way clicking
	// outside a popover does everywhere else.
	if m.showDetail || m.showHelp {
		m.showDetail, m.showHelp = false, false
		return nil
	}
	// The quit confirmation is deliberately modal: it must be answered.
	if m.confirming {
		return nil
	}
	// A click outside an open editor commits it rather than silently editing
	// something else.
	if m.editing() {
		switch m.editor {
		case editorLocalPort:
			return m.applyLocalPort()
		case editorPortLabel:
			return m.applyLabel()
		case editorConfigValue:
			return m.applyConfigValue()
		}
		m.closeEditor()
		return nil
	}

	if e.Y == rowTabs {
		if t, ok := m.tabAt(e.X); ok {
			return m.selectTab(t)
		}
		return nil
	}

	// The key bar is clickable, which makes every action discoverable without
	// knowing a single shortcut.
	if e.Y == m.height-1 {
		for _, z := range m.footerZones {
			if z.contains(e.X) {
				return m.runAction(z.id)
			}
		}
		return nil
	}

	if m.tab == tabTunnels {
		return m.handleTunnelsClick(e)
	}
	// A click on a Config section heading selects nothing: it is a label, and
	// moving the cursor onto it would arm keys that have nothing to act on.
	if i := m.rowAt(e.Y); i >= 0 && m.selectable(i) {
		m.setCursor(i)
		m.clampCursor()
	}
	return nil
}

// rowAt maps a terminal row to a list index, or -1 if it is not a data row.
func (m *Model) rowAt(y int) int {
	top := m.listTop()
	idx := y - top + m.offset()
	if y < top || idx >= m.rowCount() || idx-m.offset() >= m.listHeight() {
		return -1
	}
	return idx
}

// runAction performs the action a key bar entry names, so a click on the key
// bar and the keystroke it advertises go down exactly the same path.
//
// Everything the bar offers except the three below is a single printable key,
// and several of them mean different things on different tabs — y copies a URL
// here and a vault reference there. Replaying the keystroke keeps that
// resolution in one place instead of two.
func (m *Model) runAction(id string) tea.Cmd {
	switch id {
	case "↑↓", "←→":
		return nil
	case "esc":
		m.confirming = true
		return nil
	case "enter":
		// enter is "open the detail" on the tabs that have one and "change
		// this setting" on the Config tab, exactly as the key is.
		if m.tab == tabConfig {
			return m.stepConfig(1)
		}
		return m.toggleDetail()
	}
	return m.handleKey(keyPress(id))
}

// keyPress builds the message a printable key arrives as.
func keyPress(s string) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: []rune(s)[0], Text: s}
}

// toggleDetail opens the detail box for the selected row, where the tab has
// one worth showing.
func (m *Model) toggleDetail() tea.Cmd {
	switch m.tab {
	case tabTunnels:
		if _, ok := m.selectedRow(); !ok {
			return m.needSelection()
		}
	case tabActivity:
		if m.cursor() < 0 || m.cursor() >= len(m.logRows) {
			return m.needSelection()
		}
	default:
		return nil
	}
	m.showDetail = !m.showDetail
	return nil
}

// applyLabel commits the port-name editor.
func (m *Model) applyLabel() tea.Cmd {
	label := strings.TrimSpace(m.input.Value())
	port := m.editorPort
	m.closeEditor()
	if err := m.d.tunnels.SetLabel(port, label); err != nil {
		m.reload()
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	m.reload()
	if label == "" {
		return m.showToast(toastMsg{text: "remote " + itoa(port) + ": name cleared"})
	}
	return m.showToast(toastMsg{text: "remote " + itoa(port) + ": named " + label + " (remembered)"})
}

// applyLocalPort commits the local-port editor.
func (m *Model) applyLocalPort() tea.Cmd {
	text := strings.TrimSpace(m.input.Value())
	port := m.editorPort
	m.closeEditor()

	local := 0
	if text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > 65535 {
			return m.showToast(toastMsg{text: "not a port number: " + text, bad: true})
		}
		local = n
	}
	if err := m.d.tunnels.SetLocalPort(port, local); err != nil {
		m.reload()
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	m.reload()
	if local == 0 {
		return m.showToast(toastMsg{text: "remote " + itoa(port) + " back to its default local port"})
	}
	return m.showToast(toastMsg{text: "remote " + itoa(port) + " pinned to local " + itoa(local) + " (remembered)"})
}

// offline reports whether the link has gone away since we were connected.
func (m *Model) offline() bool {
	if !m.everConnected {
		return false
	}
	return m.status.State == session.Disconnected || m.status.State == session.Reconnecting
}
