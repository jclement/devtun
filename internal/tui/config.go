package tui

import (
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// The Config tab is devtun's own settings, as a tab rather than the popup it
// replaces.
//
// Two things make it more than a longer menu. Every row says where its value
// came from — this host, the global file, or nothing at all — because with two
// levels of configuration a screen showing `auto` without saying which file
// said so is a value nobody can act on. And every edit has a level of its own,
// armed with `g`, so changing something for one box cannot quietly rewrite the
// answer every other box was using.
//
// What a row is remains the services' business wherever it can be: the toggles
// and the per-service settings are discovered by interface, exactly as the
// popup discovered them, so a sixth service gets its rows for free.

// cfgLevel is where a value lives, and where an edit lands.
type cfgLevel int

const (
	levelHost cfgLevel = iota
	levelGlobal
	// levelNone is what neither file said: the value on screen is devtun's own
	// default, and nothing on disk is deciding it.
	levelNone
)

func (l cfgLevel) String() string {
	switch l {
	case levelHost:
		return "host"
	case levelGlobal:
		return "global"
	default:
		return "default"
	}
}

// optInherit is the option that clears a level, so a host can stop having an
// opinion and fall back to the global file — and the global file back to
// devtun's default. It is first in every option list because it is where a
// setting starts out.
const optInherit = "inherit"

// Where a setting can live, in precedence order. bothLevels is written once
// rather than spelled out per row because that order *is* the rule: the host's
// answer, then the global one.
var (
	bothLevels = []cfgLevel{levelHost, levelGlobal}
	globalOnly = []cfgLevel{levelGlobal}
	hostOnly   = []cfgLevel{levelHost}
)

// errNoConfig is what every write says on a --no-config run: the tab still
// lists the settings and still says what devtun is doing, and only saving is
// missing.
var errNoConfig = errors.New("nowhere to record that — no config file")

// sortChoices are the orderings worth reaching without knowing that `s` cycles
// them.
var sortChoices = []string{"port", "recent", "traffic", "process"}

// cfgRow is one line of the tab: a section heading, or a setting. Headings are
// rows rather than a separate structure so scrolling, clicking and rendering
// stay one row to one line; the cursor is what skips them.
type cfgRow struct {
	heading string
	setting *cfgSetting
}

// cfgSetting is one adjustable value.
type cfgSetting struct {
	// key is stable and machine-readable: it names the row in a toast, in the
	// editor, and in a test that does not want to depend on the wording.
	key   string
	title string
	// options are the values ←→ steps through. Empty means the value is text
	// and is edited in the bottom border instead.
	options []string
	// levels are the levels this setting can be written at, in precedence
	// order. A setting with one of them ignores what is armed, and says so.
	levels []cfgLevel
	// value is what devtun would use right now, and where that came from.
	value func() (string, cfgLevel)
	// raw is what one level says on its own, empty when it says nothing.
	raw func(cfgLevel) string
	// set writes at one level. An empty value clears it.
	set  func(cfgLevel, string) error
	help func() string
	// validate refuses a text value before anything is written.
	validate func(string) error
	// after runs once a value is written, for the settings this session can act
	// on rather than leaving to the next connection.
	after func()
	// unusable explains a value this machine cannot honour — a desktop dialog
	// with no program to draw one — and is empty when it can. A warning rather
	// than a refusal: the file may be perfectly right on the machine it is
	// synced to next.
	unusable func() string
}

// writes reports whether the setting can be written at a level.
func (s *cfgSetting) writes(level cfgLevel) bool {
	for _, l := range s.levels {
		if l == level {
			return true
		}
	}
	return false
}

// cfgSection groups rows under a heading.
type cfgSection struct {
	title    string
	settings []*cfgSetting
}

// --- building the rows ------------------------------------------------------

func (m *Model) configSections() []cfgSection {
	return []cfgSection{
		// Approvals first, and the prompt at the top of it: it is the setting
		// people go looking for, and the one they were not finding.
		{title: "Approvals", settings: m.approvalSettings()},
		{title: "Services", settings: m.serviceSettings()},
		{title: "Ports", settings: m.portSettings()},
		{title: "Remote setup", settings: m.remoteSettings()},
		{title: "View", settings: m.viewSettings()},
	}
}

func (m *Model) approvalSettings() []*cfgSetting {
	promptRow := m.storeSetting("prompt", "Approvals appear", "", hostcfg.KeyPrompt, bothLevels, "auto")
	promptRow.options = []string{optInherit, "auto", "tui", "dialog", "deny"}
	promptRow.help = m.promptHelp
	promptRow.unusable = func() string {
		value, _ := promptRow.value()
		if value == string(prompt.BackendDialog) && m.dialogChooser() == "" {
			return "no dialog program here — approvals will appear in this window"
		}
		return ""
	}
	promptRow.after = func() {
		value, _ := promptRow.value()
		m.applyPromptBackend(prompt.Backend(value))
	}
	settings := []*cfgSetting{promptRow}

	// The browser's gate is named here rather than discovered, because it is a
	// two-level setting and service.Setting has no levels — it hands a service
	// one document and asks for a string back. Listing it costs a line and an
	// `if`; leaving it out costs somebody the only place it can be reached.
	if m.hasService("browser") {
		gate := m.storeSetting("gate", "Ask before a site", "browser", "gate", bothLevels, "auto")
		gate.options = []string{optInherit, "ask", "auto"}
		gate.help = func() string {
			return "ask before the remote opens each site · from the next connection"
		}
		settings = append(settings, gate)
	}
	return settings
}

// promptHelp says what this machine can actually do, which is the difference
// between a setting and a promise.
//
// `dialog` on a box with no osascript, zenity, kdialog or yad falls back to
// asking in this window — correct behaviour, and completely invisible from a
// screen that renders the word "dialog" and stops there.
func (m *Model) promptHelp() string {
	// What to install comes first when there is nothing to draw a dialog with.
	// It is the only part of the line somebody can act on, and the help is the
	// first thing to give way on a narrow terminal.
	chooser := m.dialogChooser()
	base := "where an approval appears · dialog uses " + chooser + " here"
	if chooser == "" {
		base = "no dialog program here: install " + strings.Join(prompt.ChooserNames(), " or ") +
			" · otherwise approvals appear in this window"
	}
	// The command line beats both files for this run, so a session started with
	// --prompt is asking somewhere other than what the files say. Saying which
	// is cheaper than letting somebody wonder why the screen disagrees.
	if configured, _ := m.configuredPrompt(); string(m.promptNow) != configured {
		base += " · this run: " + string(m.promptNow)
	}
	return base
}

// configuredPrompt is what the files alone say, resolved the way a session
// resolves it.
func (m *Model) configuredPrompt() (string, cfgLevel) {
	if m.d.store == nil {
		return string(prompt.BackendAuto), levelNone
	}
	if v := m.d.store.Setting(m.d.host, "", hostcfg.KeyPrompt); v != "" {
		return v, levelHost
	}
	if v := m.d.store.Setting("", "", hostcfg.KeyPrompt); v != "" {
		return v, levelGlobal
	}
	return string(prompt.BackendAuto), levelNone
}

// serviceSettings are the toggles and then whatever each service says is
// adjustable, both found by asking the registry rather than by a list here.
func (m *Model) serviceSettings() []*cfgSetting {
	var settings []*cfgSetting
	for _, svc := range m.d.services {
		meta := svc.Meta()
		// The fallback is the service's own answer — on, unless it is one that
		// has to be asked for — which is what the session arrives at when
		// neither file says anything.
		fallback := "on"
		if meta.OptIn {
			fallback = "off"
		}
		row := m.storeSetting(meta.ID, meta.Glyph+" "+meta.Title, hostcfg.SectionServices, meta.ID,
			bothLevels, fallback)
		row.options = []string{optInherit, "on", "off"}
		row.help = func() string { return m.serviceHelp(meta.ID, meta.Short) }
		row.after = m.reloadServices
		settings = append(settings, showAsOnOff(row))
	}

	for _, svc := range m.d.services {
		cfg, ok := svc.(service.Configurable)
		if !ok {
			continue
		}
		title := svc.Meta().Title
		for _, s := range cfg.Settings() {
			settings = append(settings, serviceSetting(svc.Meta().ID+"."+s.Key, s.Title, title, s))
		}
	}
	return settings
}

// portSettings are the two never-forward lists. Both are text: a range is what
// a person means on a box that binds its test servers to port 0, and no list of
// options can express one.
func (m *Model) portSettings() []*cfgSetting {
	here := m.storeSetting("hide.host", "Hidden on "+m.d.host, "tunnels", hostcfg.KeyHide, hostOnly, "")
	here.validate = validPortSpec
	here.help = func() string {
		return "never forwarded on this box, e.g. 5432,32768-60999 · from the next connection"
	}

	everywhere := m.storeSetting("hide.global", "Hidden everywhere", "", hostcfg.KeyHide, globalOnly, "")
	everywhere.validate = validPortSpec
	everywhere.help = func() string {
		return "never forwarded on any box · from the next connection"
	}
	return []*cfgSetting{here, everywhere}
}

// validPortSpec refuses a hide list before it is saved. A list that will not
// parse forwards everything it was written to hide, and it would do so silently
// on the next connection rather than now, in front of the person who typed it.
func validPortSpec(spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	_, err := tunnels.ParsePortSet(spec)
	return err
}

func (m *Model) remoteSettings() []*cfgSetting {
	setup := m.storeSetting("setup", "Shell rc on the box", "", hostcfg.KeySetup, globalOnly, "ask")
	setup.options = []string{optInherit, "ask", "auto", "never"}
	setup.help = func() string {
		return "offer to add devtun's line to the remote shell rc · from the next connection"
	}
	return []*cfgSetting{setup}
}

// viewSettings are the interface's own, which the tunnels service persists for
// this host along with everything else it remembers about it.
func (m *Model) viewSettings() []*cfgSetting {
	sort := serviceSetting("view.sort", "Sort by", "", service.Setting{
		Options: sortChoices,
		Help:    "the order the tunnel table is listed in",
		Get: func() string {
			if m.sortKey == SortAge {
				return "recent"
			}
			return m.sortKey.String()
		},
		Set: func(v string) {
			m.sortKey = sortKeyNamed(v)
			m.savePrefs()
		},
	})
	reverse := serviceSetting("view.reverse", "Reverse", "", service.Setting{
		Help: "read the table from the other end",
		Get:  func() string { return boolWord(m.reverse) },
		Set: func(v string) {
			m.reverse = v == "true"
			m.savePrefs()
		},
	})
	return []*cfgSetting{sort, reverse}
}

// storeSetting builds a row backed by devtun's own configuration files.
//
// It reads each level separately rather than asking for the resolved value: the
// provenance column is the whole point of this tab, and a resolved read cannot
// tell "this host says auto" from "nobody has said anything".
func (m *Model) storeSetting(key, title, section, name string, levels []cfgLevel, fallback string) *cfgSetting {
	at := func(level cfgLevel) string {
		if m.d.store == nil {
			return ""
		}
		switch level {
		case levelHost:
			return m.d.store.Setting(m.d.host, section, name)
		case levelGlobal:
			return m.d.store.Setting("", section, name)
		default:
			return ""
		}
	}
	return &cfgSetting{
		key:    key,
		title:  title,
		levels: levels,
		raw:    at,
		value: func() (string, cfgLevel) {
			for _, level := range levels {
				if v := at(level); v != "" {
					return v, level
				}
			}
			return fallback, levelNone
		},
		set: func(level cfgLevel, value string) error {
			if m.d.store == nil {
				return errNoConfig
			}
			label := m.d.host
			if level == levelGlobal {
				label = ""
			}
			if err := m.d.store.SetSetting(label, section, name, value); err != nil {
				return err
			}
			// Saved now rather than on exit like the port table. This is the
			// screen somebody opens to change a setting and then goes back to
			// work, and a settings screen whose writes are still in memory when
			// the laptop dies has not saved anything.
			return m.d.store.Save()
		},
		help: func() string { return "" },
	}
}

// serviceSetting builds a row a service owns.
//
// service.Setting has no levels — a service is handed one document per host and
// writes back to it — so the row reports `host`, which is where an edit lands.
// It is the one place on this tab where the provenance describes the write
// rather than the read, and the alternative was a blank column that reads as a
// bug.
func serviceSetting(key, title, owner string, s service.Setting) *cfgSetting {
	options := s.Options
	if len(options) == 0 {
		options = []string{"on", "off"}
	}
	row := &cfgSetting{
		key:     key,
		title:   title,
		options: options,
		levels:  hostOnly,
		raw:     func(cfgLevel) string { return s.Get() },
		value:   func() (string, cfgLevel) { return s.Get(), levelHost },
		set: func(_ cfgLevel, value string) error {
			s.Set(value)
			return nil
		},
		help: func() string {
			if owner == "" {
				return s.Help
			}
			return s.Help + " · " + owner
		},
	}
	if len(s.Options) == 0 {
		return showAsOnOff(row)
	}
	return row
}

// showAsOnOff rewrites a row to deal in the words on screen rather than the
// spelling in the file. `true` is a fine thing to find in YAML and a poor thing
// to read in a column headed by a service name.
func showAsOnOff(s *cfgSetting) *cfgSetting {
	raw, value, set := s.raw, s.value, s.set
	s.raw = func(l cfgLevel) string { return onOff(raw(l)) }
	s.value = func() (string, cfgLevel) {
		v, level := value()
		return onOff(v), level
	}
	s.set = func(l cfgLevel, v string) error { return set(l, boolOf(v)) }
	return s
}

func onOff(v string) string {
	switch v {
	case "true":
		return "on"
	case "false":
		return "off"
	default:
		return v
	}
}

func boolOf(v string) string {
	switch v {
	case "on":
		return "true"
	case "off":
		return "false"
	default:
		return v
	}
}

func boolWord(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// hasService reports whether a service is on this session at all, so a setting
// belonging to one that is not running is not offered.
func (m *Model) hasService(id string) bool {
	for _, svc := range m.d.services {
		if svc.Meta().ID == id {
			return true
		}
	}
	return false
}

// serviceHelp is the line beside a service toggle: the reason it cannot run
// here if there is one, since that is what the user has to act on, and
// otherwise what it does plus when a change lands.
func (m *Model) serviceHelp(id, short string) string {
	if detail := m.svcState[id].detail; detail != "" {
		return detail
	}
	return short + " · from the next connection"
}

// dialogChooser names the program this machine would raise a desktop dialog
// with, asked once. DialogBackend looks along PATH and this tab is rebuilt
// twice a second; nothing installs zenity mid-session.
func (m *Model) dialogChooser() string {
	if m.dialogPick == nil {
		pick := prompt.DialogBackend()
		m.dialogPick = &pick
	}
	return *m.dialogPick
}

// reloadConfig rebuilds the rows, dropping the sections a search has emptied.
func (m *Model) reloadConfig() {
	q := strings.ToLower(strings.TrimSpace(m.search[tabConfig]))
	var rows []cfgRow
	for _, section := range m.configSections() {
		var kept []cfgRow
		for _, s := range section.settings {
			if q != "" && !strings.Contains(strings.ToLower(s.key+" "+s.title+" "+s.help()), q) {
				continue
			}
			kept = append(kept, cfgRow{setting: s})
		}
		if len(kept) == 0 {
			continue
		}
		rows = append(rows, cfgRow{heading: section.title})
		rows = append(rows, kept...)
	}
	m.cfgRows = rows

	// A cursor left on a heading by a search or a reordering would highlight a
	// row nothing can be done to.
	if i := m.cursors[tabConfig]; i != noSelection && len(rows) > 0 {
		m.cursors[tabConfig] = m.nextSelectable(min(i, len(rows)-1), 1)
	}
}

// selectedSetting is the setting under the cursor, nil when there is none.
func (m *Model) selectedSetting() *cfgSetting {
	i := m.cursors[tabConfig]
	if i < 0 || i >= len(m.cfgRows) {
		return nil
	}
	return m.cfgRows[i].setting
}

// --- keys -------------------------------------------------------------------

// handleConfigKey takes the keys this tab owns before the global handler sees
// them, and reports whether it took one.
//
// Two of them are borrowed. `g` is "jump to the first row" everywhere else and
// arms the level here, because a settings list is short enough that home does
// the job; ← and → walk the tabs everywhere else and change a value here, which
// is the only pair of keys a person reaches for to change one.
func (m *Model) handleConfigKey(msg tea.KeyPressMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "g":
		return m.armConfigLevel(), true
	case "left", "h":
		return m.stepConfig(-1), true
	case "right", "l", " ", "enter":
		return m.stepConfig(1), true
	}
	return nil, false
}

// armConfigLevel switches which file the next edit is written to.
func (m *Model) armConfigLevel() tea.Cmd {
	if m.cfgLevel == levelHost {
		m.cfgLevel = levelGlobal
		return m.showToast(toastMsg{text: "edits now apply to every host"})
	}
	m.cfgLevel = levelHost
	return m.showToast(toastMsg{text: "edits now apply to " + m.d.host})
}

// editLevel is where an edit to this setting would land: what is armed, or the
// only level the setting has.
func (m *Model) editLevel(s *cfgSetting) cfgLevel {
	if s.writes(m.cfgLevel) {
		return m.cfgLevel
	}
	return s.levels[0]
}

// stepConfig moves the selected setting by delta options, or opens the editor
// for one whose value is text.
//
// Left exists for the same reason it did in the popup: a five-option setting
// you overshot should cost one key to come back to, not four.
func (m *Model) stepConfig(delta int) tea.Cmd {
	s := m.selectedSetting()
	if s == nil {
		return m.needSelection()
	}
	if len(s.options) == 0 {
		return m.openConfigEditor(s)
	}

	level := m.editLevel(s)
	// The options show the armed level's own state, not the value in the
	// column: with nothing set here the cursor starts on `inherit`, so one
	// press to the right is a decision for this level and one press back
	// undoes it.
	current := s.raw(level)
	if current == "" {
		current = optInherit
	}
	at := 0
	for i, option := range s.options {
		if option == current {
			at = i
			break
		}
	}
	next := (at + delta) % len(s.options)
	if next < 0 {
		next += len(s.options)
	}

	value := s.options[next]
	if value == optInherit {
		value = ""
	}
	return m.writeConfig(s, level, value)
}

// writeConfig applies one edit and says what happened to it.
func (m *Model) writeConfig(s *cfgSetting, level cfgLevel, value string) tea.Cmd {
	if err := s.set(level, value); err != nil {
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	if s.after != nil {
		s.after()
	}
	// A setting the tunnels service owns has just been written through the
	// service, so the model's own copy of the presentation settings is the
	// stale one.
	m.syncPrefs()
	m.reload()

	where := "for " + m.d.host
	if level == levelGlobal {
		where = "for every host"
	}
	if value == "" {
		shown, from := s.value()
		return m.showToast(toastMsg{text: s.title + ": " + where + " it now inherits " + shown + " (" + from.String() + ")"})
	}
	if s.unusable != nil {
		if reason := s.unusable(); reason != "" {
			return m.showToast(toastMsg{text: s.title + ": " + reason, bad: true})
		}
	}
	return m.showToast(toastMsg{text: s.title + ": " + value + " " + where})
}

// openConfigEditor starts editing a text-valued setting in the bottom border,
// seeded with what the armed level says rather than with the value on screen: a
// blank box means this level is silent, which is exactly what it is.
func (m *Model) openConfigEditor(s *cfgSetting) tea.Cmd {
	m.editor = editorConfigValue
	m.editorSetting = s.key
	m.input.SetValue(s.raw(m.editLevel(s)))
	return nil
}

// settingNamed finds a row by its key, which is how the inline editor holds on
// to what it is editing: the rows are rebuilt twice a second, so an index would
// be pointing at something else by the time enter was pressed.
func (m *Model) settingNamed(key string) *cfgSetting {
	for _, row := range m.cfgRows {
		if row.setting != nil && row.setting.key == key {
			return row.setting
		}
	}
	return nil
}

// configEditorPrompt names what is being edited and which file it lands in.
func (m *Model) configEditorPrompt() string {
	s := m.settingNamed(m.editorSetting)
	if s == nil {
		return "setting"
	}
	where := m.d.host
	if m.editLevel(s) == levelGlobal {
		where = "every host"
	}
	return s.title + " for " + where
}

// applyConfigValue commits the inline editor, refusing a value that will not
// parse rather than saving it.
func (m *Model) applyConfigValue() tea.Cmd {
	key, value := m.editorSetting, strings.TrimSpace(m.input.Value())
	m.closeEditor()

	setting := m.settingNamed(key)
	if setting == nil {
		return nil
	}
	if setting.validate != nil {
		if err := setting.validate(value); err != nil {
			// Refused, not saved: this is a list whose failure shows up on the
			// next connection as ports that were meant to be hidden and are
			// not, long after anybody would connect the two.
			return m.showToast(toastMsg{text: firstLine(err.Error()), bad: true})
		}
	}
	return m.writeConfig(setting, m.editLevel(setting), value)
}

// applyPromptBackend puts a changed prompt setting into effect now rather than
// at the next connection.
//
// Where an approval appears is the setting somebody changes *because* they are
// missing approvals, and answering that with "reconnect first" is telling them
// to miss one more.
func (m *Model) applyPromptBackend(backend prompt.Backend) {
	m.promptNow = backend
	if m.d.applyPrompt != nil {
		m.d.applyPrompt(backend)
	}
}

// syncPrefs re-reads the settings the tunnels service owns, after something
// other than the model has changed them.
func (m *Model) syncPrefs() {
	m.prefs = m.d.tunnels.ViewPrefs()
	m.sortKey = sortKeyNamed(m.prefs.Sort)
	m.reverse = m.prefs.Reverse
}

// savePrefs pushes the presentation settings back to the tunnels service,
// which persists them for this host.
func (m *Model) savePrefs() {
	m.prefs.Sort = m.sortKey.String()
	m.prefs.Reverse = m.reverse
	m.d.tunnels.SetViewPrefs(m.prefs)
}

// --- rendering --------------------------------------------------------------

func (m *Model) configView() string {
	var lines []string
	end := min(m.offset()+m.listHeight(), len(m.cfgRows))
	for i := m.offset(); i < end; i++ {
		lines = append(lines, m.configLine(m.cfgRows[i], i == m.cursor()))
	}
	empty := "no settings on this session"
	if m.search[tabConfig] != "" {
		empty = "nothing matches " + m.search[tabConfig]
	}
	return m.listView(lines, m.listHeight(), empty)
}

// Column widths for a settings row. The help is what gives way on a narrow
// terminal, so the name, the value and where it came from are written first and
// in that order — those three are the row, and the sentence is the gloss.
const (
	cfgTitleWidth = 20
	cfgValueWidth = 10
	cfgLevelWidth = 8
)

func (m *Model) configLine(r cfgRow, selected bool) string {
	if r.setting == nil {
		return ui.Header.Render(" " + r.heading)
	}
	s := r.setting

	value, level := s.value()
	if value == "" {
		value = "—"
	}
	style := ui.OK
	switch {
	case s.unusable != nil && s.unusable() != "":
		style = ui.Warn
	case level == levelNone:
		style = ui.Muted
	}

	help := s.help()
	// A setting with one level ignores what `g` armed, so it says so rather
	// than appearing to have taken an edit somewhere it did not.
	if len(s.levels) == 1 && !s.writes(m.cfgLevel) {
		help = s.levels[0].String() + " only · " + help
	}

	line := "   " + pad(s.title, cfgTitleWidth) + " " +
		style.Render(pad(value, cfgValueWidth)) + " " +
		ui.Muted.Render(pad(level.String(), cfgLevelWidth)) +
		ui.Muted.Render(help)

	line = clampWidth(line, m.inner())
	if selected {
		if w := ansi.StringWidth(line); w < m.inner() {
			line += strings.Repeat(" ", m.inner()-w)
		}
		return ui.Selected.Reverse(true).Render(ansi.Strip(line))
	}
	return line
}
