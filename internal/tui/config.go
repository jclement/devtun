package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/settings"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// The Config tab is devtun's own settings, as a tab rather than the popup it
// replaces.
//
// What a setting IS lives in internal/settings, because the web board offers
// the same ones and two catalogues would drift. What is left here is the part
// that is genuinely the terminal's: rows, columns, and the keys that walk them.
//
// Two things make it more than a longer menu. Every row says where its value
// came from — this host, the global file, or nothing at all — because with two
// levels of configuration a screen showing `auto` without saying which file
// said so is a value nobody can act on. And every edit has a level of its own,
// armed with `g`, so changing something for one box cannot quietly rewrite the
// answer every other box was using.

// cfgRow is one line of the tab: a section heading, or a setting. Headings are
// rows rather than a separate structure so scrolling, clicking and rendering
// stay one row to one line; the cursor is what skips them.
type cfgRow struct {
	heading string
	setting *settings.Setting
}

// deps assembles what the catalogue needs from this session. The model is the
// only thing that knows all of it, and nothing else in the package should be
// reaching into m.d to build one.
func (m *Model) settingsDeps() settings.Deps {
	return settings.Deps{
		Store:         m.d.store,
		Host:          m.d.host,
		Services:      m.d.services,
		ServiceDetail: func(id string) string { return m.svcState[id].detail },
		PromptNow:     func() prompt.Backend { return m.promptNow },
		ApplyPrompt:   m.applyPromptBackend,
		// The rows are rebuilt after a toggle so the Services tab is not left
		// describing a service by what it was doing a moment ago.
		ReloadServices: m.reloadServices,
		Prefs:          func() tunnels.ViewPrefs { return m.d.tunnels.ViewPrefs() },
		SetPrefs:       m.d.tunnels.SetViewPrefs,
		DialogChooser:  m.dialogChooser,
	}
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
	for _, section := range m.settingsDeps().Catalogue() {
		var kept []cfgRow
		for _, s := range section.Settings {
			if q != "" && !strings.Contains(strings.ToLower(s.Key+" "+s.Title+" "+s.Help()), q) {
				continue
			}
			kept = append(kept, cfgRow{setting: s})
		}
		if len(kept) == 0 {
			continue
		}
		rows = append(rows, cfgRow{heading: section.Title})
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
func (m *Model) selectedSetting() *settings.Setting {
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
	case "right", "l", "space", "enter":
		return m.stepConfig(1), true
	}
	return nil, false
}

// armConfigLevel switches which file the next edit is written to.
func (m *Model) armConfigLevel() tea.Cmd {
	if m.cfgLevel == settings.LevelHost {
		m.cfgLevel = settings.LevelGlobal
		return m.showToast(toastMsg{text: "edits now apply to every host"})
	}
	m.cfgLevel = settings.LevelHost
	return m.showToast(toastMsg{text: "edits now apply to " + m.d.host})
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
	level := s.EditLevel(m.cfgLevel)
	value, ok := settings.Step(s, level, delta)
	if !ok {
		return m.openConfigEditor(s)
	}
	return m.writeConfig(s, level, value)
}

// writeConfig applies one edit and says what happened to it.
func (m *Model) writeConfig(s *settings.Setting, level settings.Level, value string) tea.Cmd {
	result, err := settings.Apply(s, level, value, m.d.host)
	if err != nil {
		return m.showToast(toastMsg{text: firstLine(err.Error()), bad: true})
	}
	// A setting the tunnels service owns has just been written through the
	// service, so the model's own copy of the presentation settings is the
	// stale one.
	m.syncPrefs()
	m.reload()
	return m.showToast(toastMsg{text: result.Text, bad: result.Warn})
}

// openConfigEditor starts editing a text-valued setting in the bottom border,
// seeded with what the armed level says rather than with the value on screen: a
// blank box means this level is silent, which is exactly what it is.
func (m *Model) openConfigEditor(s *settings.Setting) tea.Cmd {
	m.editor = editorConfigValue
	m.editorSetting = s.Key
	m.input.SetValue(s.Raw(s.EditLevel(m.cfgLevel)))
	return nil
}

// settingNamed finds a row by its key, which is how the inline editor holds on
// to what it is editing: the rows are rebuilt twice a second, so an index would
// be pointing at something else by the time enter was pressed.
func (m *Model) settingNamed(key string) *settings.Setting {
	for _, row := range m.cfgRows {
		if row.setting != nil && row.setting.Key == key {
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
	if s.EditLevel(m.cfgLevel) == settings.LevelGlobal {
		where = "every host"
	}
	return s.Title + " for " + where
}

// applyConfigValue commits the inline editor.
func (m *Model) applyConfigValue() tea.Cmd {
	key, value := m.editorSetting, strings.TrimSpace(m.input.Value())
	m.closeEditor()

	setting := m.settingNamed(key)
	if setting == nil {
		return nil
	}
	return m.writeConfig(setting, setting.EditLevel(m.cfgLevel), value)
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

	value, level := s.Value()
	if value == "" {
		value = "—"
	}
	style := ui.OK
	switch {
	case s.Unusable != nil && s.Unusable() != "":
		style = ui.Warn
	case level == settings.LevelNone:
		style = ui.Muted
	}

	help := s.Help()
	// A setting with one level ignores what `g` armed, so it says so rather
	// than appearing to have taken an edit somewhere it did not.
	if len(s.Levels) == 1 && !s.Writes(m.cfgLevel) {
		help = s.Levels[0].String() + " only · " + help
	}

	line := "   " + pad(s.Title, cfgTitleWidth) + " " +
		style.Render(pad(value, cfgValueWidth)) + " " +
		ui.Muted.Render(pad(level.String(), cfgLevelWidth)) +
		ui.Muted.Render(help)

	line = clampWidth(line, m.listWidth())
	if selected {
		if w := ansi.StringWidth(line); w < m.listWidth() {
			line += strings.Repeat(" ", m.listWidth()-w)
		}
		return ui.Selected.Reverse(true).Render(ansi.Strip(line))
	}
	return line
}
