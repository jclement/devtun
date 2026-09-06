package tunnels

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/tunnels/probe"
)

// Event kinds. These are the machine-readable contract `devtun --json`
// consumers match on, so they are stable strings rather than anything derived.
const (
	KindOpened = "opened"
	KindClosed = "closed"
	KindFailed = "failed"
)

// Status is the lifecycle state of a discovered remote service.
type Status string

const (
	// StatusActive means a local listener is open and forwarding.
	StatusActive Status = "active"
	// StatusSkipped means the service is known but policy says don't forward.
	StatusSkipped Status = "skipped"
	// StatusError means forwarding was attempted and failed, usually a local
	// port conflict under --same-port.
	StatusError Status = "error"
	// StatusOffline means the tunnel existed but the SSH link is down.
	StatusOffline Status = "offline"
)

// State is an immutable snapshot of one row for the UI. Values are copied out
// under the manager lock so renderers never touch live tunnel state.
type State struct {
	RemotePort int
	LocalPort  int
	LocalAddr  string
	Remapped   bool

	PID   int
	Proc  string
	Cmd   string
	Binds string

	Status Status
	Skip   Skip
	Err    string
	Scheme Scheme
	// SchemePinned reports that the user chose the scheme, rather than it
	// being detected. Pinned choices are remembered between runs.
	SchemePinned bool
	// Label is the user's remembered name for this host and port.
	Label string

	// Mode is the user's standing decision for this port.
	Mode Mode
	// PinnedLocal is a local port the user chose, or zero.
	PinnedLocal int

	FirstSeen time.Time
	Created   time.Time
	LastByte  time.Time

	BytesIn     uint64
	BytesOut    uint64
	ActiveConns int
	TotalConns  uint64
}

// URL returns the address to point a browser at, or "" when not forwarding.
func (s State) URL() string {
	if s.Status != StatusActive || s.Scheme == SchemeUnknown {
		return ""
	}
	return s.Scheme.URLScheme() + "://" + s.Endpoint()
}

// Endpoint returns the local host:port for an active tunnel. It is useful for
// raw TCP services where inventing an HTTP URL would be misleading.
func (s State) Endpoint() string {
	if s.Status != StatusActive {
		return ""
	}
	host := s.LocalAddr
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return net.JoinHostPort(host, strconv.Itoa(s.LocalPort))
}

// entry is the manager's private record for one remote port.
type entry struct {
	svc         probe.Service
	fwd         *forwarder
	skip        Skip
	err         string
	mode        Mode // auto follows policy; on and hidden are user decisions
	pinnedLocal int  // a local port the user chose, or zero
	label       string
	// pausedKeep means this automatic tunnel was already active when forwarding
	// was paused. It stays up (and returns after a reconnect) while new automatic
	// tunnels remain suspended.
	pausedKeep bool
	firstSeen  time.Time
	missing    int

	scheme Scheme
	pinned bool // the user chose the scheme; never overwrite it by observation
}

// Manager keeps local listeners in sync with the set of services discovered on
// the remote host.
//
// It outlives any one SSH connection: a reconnect swaps the dialer and nothing
// else, which is what lets a service come back on the local port number it had
// before the link dropped.
//
// It is safe for concurrent use: Sync runs on the poller goroutine while the UI
// calls States and the mutators.
type Manager struct {
	// summarised records that the first burst of opens has been folded into a
	// single line. It lives here rather than on the connection so a reconnect
	// does not re-summarise a board the user has already seen.
	summarised bool

	alloc  *Allocator
	grace  int // consecutive missed scans tolerated before teardown
	now    func() time.Time
	events event.Sink
	mu     sync.Mutex
	dialer Dialer

	policy  Policy
	entries map[int]*entry
	// globalHide comes from devtun's top-level config and applies to every
	// host. It reads exactly like a per-host hide but is never written back to
	// a host's file, so removing it from the global list restores the row
	// everywhere at once.
	globalHide map[int]bool
	showHidden bool

	settings *Store
}

// ManagerOptions configures a Manager.
type ManagerOptions struct {
	Policy Policy
	// Settings, if set, persists the user's per-port decisions.
	Settings *Store
	// GlobalHide is the hide list that applies to every host.
	GlobalHide []int
	// Grace is how many consecutive scans a service may be absent before its
	// tunnel is torn down. Two absorbs a single dropped scan without leaving
	// dead listeners around.
	Grace int
	// Events, if set, receives every change. It is called without the manager
	// lock held.
	Events event.Sink
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// NewManager returns a Manager that allocates through alloc and forwards over
// dialer. dialer may be nil initially and supplied later with SetDialer.
func NewManager(alloc *Allocator, dialer Dialer, opts ManagerOptions) *Manager {
	if opts.Grace <= 0 {
		opts.Grace = 2
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Policy.MaxPort == 0 {
		opts.Policy.MaxPort = 65535
	}
	m := &Manager{
		alloc:      alloc,
		dialer:     dialer,
		grace:      opts.Grace,
		now:        opts.Now,
		events:     opts.Events,
		policy:     opts.Policy,
		entries:    map[int]*entry{},
		globalHide: map[int]bool{},
		settings:   opts.Settings,
	}
	for _, p := range opts.GlobalHide {
		m.globalHide[p] = true
	}
	if opts.Settings != nil {
		m.showHidden = opts.Settings.View().ShowHidden
	}
	return m
}

// Sync reconciles the live tunnels with a freshly observed snapshot.
func (m *Manager) Sync(snap probe.Snapshot) {
	var events []event.Event

	m.mu.Lock()
	now := m.now()

	for port, svc := range snap {
		e, ok := m.entries[port]
		if !ok {
			e = &entry{svc: svc, firstSeen: now, mode: ModeAuto}
			// Restore whatever the user decided about this port last time.
			if m.settings != nil {
				saved := m.settings.Port(port)
				e.scheme = ParseScheme(saved.Scheme)
				e.pinned = e.scheme != SchemeUnknown
				e.mode = ParseMode(saved.Mode)
				e.pinnedLocal = saved.Local
				e.label = saved.Label
			}
			m.entries[port] = e
		}
		e.missing = 0
		// Keep an already-resolved command line if this scan lost it.
		if svc.Cmd == "" {
			svc.Cmd = e.svc.Cmd
		}
		e.svc = svc
		events = append(events, m.applyLocked(e, now)...)
	}

	for port, e := range m.entries {
		if _, ok := snap[port]; ok {
			continue
		}
		e.missing++
		if e.missing < m.grace {
			continue
		}
		if e.fwd != nil {
			events = append(events, m.closeLocked(e, "remote service went away"))
		}
		delete(m.entries, port)
	}
	m.mu.Unlock()

	m.emit(events)
}

// applyLocked opens or closes the tunnel for e to match current policy.
// Caller holds m.mu.
func (m *Manager) applyLocked(e *entry, now time.Time) []event.Event {
	want := m.wantLocked(e)

	if !want.forward {
		e.skip = want.skip
		if e.fwd != nil {
			return []event.Event{m.closeLocked(e, string(want.skip))}
		}
		return nil
	}

	e.skip = SkipNone
	if e.fwd != nil {
		return nil
	}
	if m.dialer == nil {
		return nil // link is down; Sync will retry once reconnected
	}

	ln, remapped, err := m.alloc.Allocate(e.svc.Port, e.pinnedLocal)
	if err != nil {
		if e.err == err.Error() {
			return nil // already reported; don't spam the log each scan
		}
		e.err = err.Error()
		return []event.Event{failedEvent(now, m.stateLocked(e), e.err)}
	}
	e.err = ""
	port := e.svc.Port
	// What a service turns out to be is learned from the replies it sends
	// through the tunnel, never by probing it.
	e.fwd = newForwarder(ln, m.dialer, e.svc.DialAddr(), remapped, now, func(scheme Scheme) {
		m.observeScheme(port, scheme)
	})
	return []event.Event{openedEvent(now, m.stateLocked(e))}
}

// observeScheme records what a service revealed itself to be. A scheme the
// user pinned is never overwritten.
func (m *Manager) observeScheme(port int, scheme Scheme) {
	if scheme == SchemeUnknown {
		return
	}
	m.mu.Lock()
	e, ok := m.entries[port]
	changed := ok && !e.pinned && e.scheme != scheme
	if changed {
		e.scheme = scheme
	}
	m.mu.Unlock()
}

// CycleScheme steps a port's scheme through unknown → http → https and
// remembers the choice. Returns the new scheme.
func (m *Manager) CycleScheme(remotePort int) Scheme {
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return SchemeUnknown
	}
	e.scheme = e.scheme.Next()
	// Cycling back to unknown releases the pin, so detection may run again on
	// a later reconnect.
	e.pinned = e.scheme != SchemeUnknown
	scheme := e.scheme
	m.mu.Unlock()

	m.persist(remotePort)
	return scheme
}

type want struct {
	forward bool
	skip    Skip
}

// wantLocked applies the user's standing decision for the port if there is
// one, otherwise the policy.
func (m *Manager) wantLocked(e *entry) want {
	switch e.mode {
	case ModeOn:
		// "On" beats every filter except --exclude. Excluding a port on the
		// command line is a statement about this run — "not this, whatever the
		// file says" — and a stored preference that could override it would
		// leave no way to suppress a port for one session.
		if m.policy.Exclude.Contains(e.svc.Port) {
			return want{skip: SkipExcluded}
		}
		return want{forward: true}
	case ModeHidden:
		return want{skip: SkipHidden}
	}
	if m.globalHide[e.svc.Port] {
		return want{skip: SkipHidden}
	}
	if m.policy.Paused && e.pausedKeep {
		return want{forward: true}
	}
	skip := m.policy.Eval(e.svc)
	return want{forward: skip == SkipNone, skip: skip}
}

// closeLocked tears down e's forwarder. Caller holds m.mu.
func (m *Manager) closeLocked(e *entry, reason string) event.Event {
	fwd := e.fwd
	e.fwd = nil
	st := m.stateLocked(e)
	st.LocalPort = fwd.local
	st.Status = StatusSkipped
	// Release the local port synchronously so a reconnect can immediately
	// re-bind it, but drain in-flight connections in the background rather
	// than blocking a scan on a slow peer.
	fwd.stop()
	go fwd.Close()
	return closedEvent(m.now(), st, reason)
}

// stateLocked snapshots e for display. Caller holds m.mu.
func (m *Manager) stateLocked(e *entry) State {
	st := State{
		RemotePort:   e.svc.Port,
		LocalAddr:    m.alloc.Bind(),
		PID:          e.svc.PID,
		Proc:         e.svc.Proc,
		Cmd:          e.svc.Command(),
		Binds:        e.svc.BindSummary(),
		Skip:         e.skip,
		Err:          e.err,
		Mode:         e.mode,
		PinnedLocal:  e.pinnedLocal,
		Label:        e.label,
		FirstSeen:    e.firstSeen,
		Scheme:       e.scheme,
		SchemePinned: e.pinned,
	}
	switch {
	case e.fwd != nil:
		f := e.fwd
		st.Status = StatusActive
		st.LocalPort = f.local
		st.Remapped = f.remapped
		st.Created = f.created
		st.BytesIn = f.in.Load()
		st.BytesOut = f.out.Load()
		st.ActiveConns = int(f.active.Load())
		st.TotalConns = f.total.Load()
		if ns := f.last.Load(); ns != 0 {
			st.LastByte = time.Unix(0, ns)
		}
		if msg := f.err(); msg != "" {
			st.Err = msg
		}
	case e.err != "":
		st.Status = StatusError
	case m.dialer == nil && m.wantLocked(e).forward:
		// The link is down but the port is still ours: the local port stays
		// reserved and comes back on the same number.
		st.Status = StatusOffline
	default:
		st.Status = StatusSkipped
	}
	return st
}

// hiddenLocked reports whether an entry is filtered out of the table entirely.
// A live tunnel always keeps a row visible, and so does a standing "on", which
// the user needs to see in order to change their mind about it.
func (m *Manager) hiddenLocked(e *entry) bool {
	if e.fwd != nil || e.mode == ModeOn {
		return false
	}
	if e.skip == SkipHidden {
		return !m.showHidden
	}
	return e.mode == ModeAuto && e.skip.Filtered()
}

// States returns every service worth showing, ordered by remote port.
func (m *Manager) States() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]State, 0, len(m.entries))
	for _, e := range m.entries {
		if m.hiddenLocked(e) {
			continue
		}
		out = append(out, m.stateLocked(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemotePort < out[j].RemotePort })
	return out
}

// ShowHidden reports whether hidden rows are currently listed.
func (m *Manager) ShowHidden() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.showHidden
}

// SetShowHidden lists or unlists the ports the user hid. It is a view choice:
// nothing is forwarded or stopped by it.
func (m *Manager) SetShowHidden(v bool) {
	m.mu.Lock()
	m.showHidden = v
	m.mu.Unlock()
}

// Policy returns the active policy.
func (m *Manager) Policy() Policy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policy
}

// SetPolicy replaces the policy and reconciles every known service against it.
func (m *Manager) SetPolicy(p Policy) {
	m.mu.Lock()
	wasPaused := m.policy.Paused
	if !wasPaused && p.Paused {
		for _, e := range m.entries {
			e.pausedKeep = e.mode == ModeAuto && e.fwd != nil
		}
	} else if wasPaused && !p.Paused {
		for _, e := range m.entries {
			e.pausedKeep = false
		}
	}
	m.policy = p
	now := m.now()
	var events []event.Event
	for _, e := range m.sortedEntriesLocked() {
		events = append(events, m.applyLocked(e, now)...)
	}
	m.mu.Unlock()
	m.emit(events)
}

// CycleMode steps a port through auto → on → hidden and remembers the choice.
func (m *Manager) CycleMode(remotePort int) Mode {
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return ModeAuto
	}
	e.mode = e.mode.Next()
	if e.mode != ModeAuto {
		e.pausedKeep = false
	}
	if e.mode != ModeHidden {
		e.err = "" // choosing to forward is an explicit retry
	}
	events := m.applyLocked(e, m.now())
	mode := e.mode
	m.mu.Unlock()

	m.persist(remotePort)
	m.emit(events)
	return mode
}

// SetMode records a standing decision for a port directly, rather than by
// cycling. Returns the mode actually in force.
func (m *Manager) SetMode(remotePort int, mode Mode) Mode {
	mode = ParseMode(string(mode))
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return ModeAuto
	}
	e.mode = mode
	if mode != ModeAuto {
		e.pausedKeep = false
	}
	if mode != ModeHidden {
		e.err = ""
	}
	events := m.applyLocked(e, m.now())
	m.mu.Unlock()

	m.persist(remotePort)
	m.emit(events)
	return mode
}

// ForwardNow opens a tunnel for a listed port that policy is skipping, for
// this session only. Naming one port in a browser request is more specific
// than a blanket rule like --min-port, so it wins; a port the user hid is left
// alone, because that decision was about this port in particular.
func (m *Manager) ForwardNow(remotePort int) error {
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("remote port %d is not listed", remotePort)
	}
	if e.mode == ModeHidden {
		m.mu.Unlock()
		return fmt.Errorf("remote port %d is hidden", remotePort)
	}
	e.mode = ModeOn
	e.pausedKeep = false
	e.err = ""
	events := m.applyLocked(e, m.now())
	failed := e.err
	m.mu.Unlock()

	m.emit(events)
	if failed != "" {
		return errors.New(failed)
	}
	return nil
}

// SetScheme sets a port's protocol directly and remembers it. Unknown clears
// the pin so passive detection may classify future traffic again.
func (m *Manager) SetScheme(remotePort int, scheme Scheme) Scheme {
	scheme = ParseScheme(string(scheme))
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return SchemeUnknown
	}
	e.scheme = scheme
	e.pinned = scheme != SchemeUnknown
	m.mu.Unlock()
	m.persist(remotePort)
	return scheme
}

// SetLabel gives a remote port a human-friendly name and remembers it. An
// empty label restores the process command as the row's primary identity.
func (m *Manager) SetLabel(remotePort int, label string) error {
	label = strings.Join(strings.Fields(label), " ")
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("remote port %d is not listed", remotePort)
	}
	e.label = label
	m.mu.Unlock()
	m.persist(remotePort)
	return nil
}

// SetLocalPort pins the local port a service is forwarded to. Zero restores
// the default of mirroring the remote port. The tunnel is reopened so the
// change takes effect immediately.
func (m *Manager) SetLocalPort(remotePort, local int) error {
	return m.setLocalPort(remotePort, local, true)
}

// TryLocalPort moves a tunnel to a specific local port for this session only,
// without remembering the choice. It is what a browser request needs: a login
// flow's callback has to arrive on the exact port the remote baked into its
// redirect URI, but the throwaway high port it picked this once should not be
// pinned for that host forever.
func (m *Manager) TryLocalPort(remotePort, local int) error {
	return m.setLocalPort(remotePort, local, false)
}

func (m *Manager) setLocalPort(remotePort, local int, remember bool) error {
	if local < 0 || local > 65535 {
		return fmt.Errorf("local port %d is out of range", local)
	}

	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("remote port %d is not listed", remotePort)
	}
	e.pinnedLocal = local
	// Drop the remembered assignment so the new preference is not overruled
	// by where this service happened to land last time.
	m.alloc.Forget(remotePort)

	var events []event.Event
	if e.fwd != nil {
		events = append(events, m.closeLocked(e, "relocating"))
	}
	e.err = ""
	events = append(events, m.applyLocked(e, m.now())...)
	failed := e.err
	m.mu.Unlock()

	if remember {
		m.persist(remotePort)
	}
	m.emit(events)
	if failed != "" {
		return errors.New(failed)
	}
	return nil
}

// persist writes a port's current decisions to the settings store.
func (m *Manager) persist(remotePort int) {
	if m.settings == nil {
		return
	}
	m.mu.Lock()
	e, ok := m.entries[remotePort]
	if !ok {
		m.mu.Unlock()
		return
	}
	saved := PortPrefs{Label: e.label, Mode: string(e.mode), Local: e.pinnedLocal}
	if e.pinned {
		saved.Scheme = string(e.scheme)
	}
	settings := m.settings
	m.mu.Unlock()

	settings.SetPort(remotePort, saved)
}

// SetDialer swaps the transport, used when the SSH link is re-established.
// Passing nil marks the link down and closes every forwarder; the local port
// assignments are remembered so reconnecting restores them.
func (m *Manager) SetDialer(d Dialer) {
	m.mu.Lock()
	m.dialer = d
	var events []event.Event
	if d == nil {
		for _, e := range m.sortedEntriesLocked() {
			if e.fwd != nil {
				events = append(events, m.closeLocked(e, "disconnected"))
			}
			e.missing = 0
		}
	} else {
		now := m.now()
		for _, e := range m.sortedEntriesLocked() {
			events = append(events, m.applyLocked(e, now)...)
		}
	}
	m.mu.Unlock()
	m.emit(events)
}

// Close tears down every tunnel.
func (m *Manager) Close() {
	m.mu.Lock()
	fwds := make([]*forwarder, 0, len(m.entries))
	for _, e := range m.entries {
		if e.fwd != nil {
			fwds = append(fwds, e.fwd)
			e.fwd = nil
		}
	}
	m.mu.Unlock()
	for _, f := range fwds {
		f.Close()
	}
}

// Counts summarizes the current tunnel set.
func (m *Manager) Counts() (active, skipped, failed int) {
	for _, s := range m.States() {
		switch s.Status {
		case StatusActive:
			active++
		case StatusError:
			failed++
		default:
			skipped++
		}
	}
	return
}

// Hidden counts the ports the user has hidden on this host.
//
// It cannot be derived from States, which omits hidden rows by design — so
// without this the header could only report a hidden count while *show hidden*
// was on, which is precisely when the number is least interesting. A count of
// what you cannot currently see is the whole point: it is the reminder that the
// board is shorter than the box.
func (m *Manager) Hidden() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := 0
	for _, e := range m.entries {
		if m.wantLocked(e).skip == SkipHidden {
			n++
		}
	}
	return n
}

func (m *Manager) sortedEntriesLocked() []*entry {
	out := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].svc.Port < out[j].svc.Port })
	return out
}

func (m *Manager) emit(events []event.Event) {
	if m.events == nil {
		return
	}
	// The first scan of a busy box opens a dozen tunnels at once, and a dozen
	// lines arriving in the same instant reads as something going wrong rather
	// than something working. Every scan after that reports one line per
	// change, which is exactly what you want — the difference is that the
	// first is not a change, it is a description of the box.
	if summary, ok := m.summarise(events); ok {
		m.events.Emit(summary)
		return
	}
	for _, e := range events {
		m.events.Emit(e)
	}
}

// summarise folds a first-scan burst into one line, and reports whether it did.
//
// It only ever fires once per Manager, and only for a burst: two ports opening
// together later in the session is news about those two ports and is left
// alone.
func (m *Manager) summarise(events []event.Event) (event.Event, bool) {
	m.mu.Lock()
	first := !m.summarised
	m.mu.Unlock()
	if !first {
		return event.Event{}, false
	}

	var opened, remapped []string
	for _, e := range events {
		if e.Kind != "opened" {
			return event.Event{}, false // a mixed burst is not a first scan
		}
		remote, local := portsOf(e)
		opened = append(opened, remote)
		if remote != local {
			remapped = append(remapped, remote+"→"+local)
		}
	}
	if len(opened) < summariseFrom {
		return event.Event{}, false
	}

	m.mu.Lock()
	m.summarised = true
	m.mu.Unlock()

	text := fmt.Sprintf("forwarding %d ports: %s", len(opened), strings.Join(opened, " "))
	if len(remapped) > 0 {
		// The remaps are the part worth reading twice: a silently different
		// local port is how you spend twenty minutes debugging the wrong
		// service.
		text += fmt.Sprintf("  ·  %d remapped (%s)", len(remapped), strings.Join(remapped, " "))
	}
	text += "  ·  x hides one for good"
	return event.Event{
		Kind: "opened-many", Class: event.Network, Level: event.Info, Text: text,
	}, true
}

// summariseFrom is how many simultaneous opens count as a flood rather than as
// news. Three is a normal dev box waking up; four is a wall of text.
const summariseFrom = 4

// portsOf pulls the remote and local ports out of an opened event's fields.
func portsOf(e event.Event) (remote, local string) {
	for i := 0; i+1 < len(e.Fields); i += 2 {
		key, _ := e.Fields[i].(string)
		value, ok := e.Fields[i+1].(int)
		if !ok {
			continue
		}
		switch key {
		case "remote":
			remote = strconv.Itoa(value)
		case "local":
			local = strconv.Itoa(value)
		}
	}
	return remote, local
}

// openedEvent announces a new tunnel. The ≠ marks a remap: a silently
// different local port is how you spend twenty minutes debugging the wrong
// service, so it is called out in the one line most people will read.
func openedEvent(at time.Time, st State) event.Event {
	arrow := "→"
	if st.Remapped {
		arrow = "≠"
	}
	fields := []any{
		"remote", st.RemotePort,
		"local", st.LocalPort,
		"remapped", st.Remapped,
		"process", st.Cmd,
	}
	if url := st.URL(); url != "" {
		fields = append(fields, "url", url)
	} else if ep := st.Endpoint(); ep != "" {
		fields = append(fields, "endpoint", ep)
	}
	return event.Event{
		Time:   at,
		Kind:   KindOpened,
		Class:  event.Network,
		Level:  event.Info,
		Text:   fmt.Sprintf("remote %d %s %s:%d (%s)", st.RemotePort, arrow, st.LocalAddr, st.LocalPort, st.Cmd),
		Fields: fields,
	}
}

func closedEvent(at time.Time, st State, reason string) event.Event {
	return event.Event{
		Time:   at,
		Kind:   KindClosed,
		Class:  event.Network,
		Level:  event.Info,
		Text:   fmt.Sprintf("remote %d closed on %s:%d (%s)", st.RemotePort, st.LocalAddr, st.LocalPort, reason),
		Fields: []any{"remote", st.RemotePort, "local", st.LocalPort, "reason", reason},
	}
}

func failedEvent(at time.Time, st State, msg string) event.Event {
	return event.Event{
		Time:   at,
		Kind:   KindFailed,
		Class:  event.Network,
		Level:  event.Error,
		Text:   fmt.Sprintf("remote %d not forwarded: %s", st.RemotePort, msg),
		Fields: []any{"remote", st.RemotePort, "error", msg},
	}
}
