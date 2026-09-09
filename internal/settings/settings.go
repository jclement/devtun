// Package settings is devtun's own configuration, described once.
//
// It exists because there are two surfaces — the terminal and the web board —
// and a setting that is adjustable in one and not the other is a setting the
// person on the wrong surface cannot reach. Describing the catalogue twice
// would be worse than not having it in both places: two lists drift, and the
// way you find out is somebody changing a value on one screen and watching the
// other disagree about what it now is.
//
// So a setting is a value, the levels it can live at, and the functions that
// read and write it — and nothing about how it is drawn. The terminal renders
// rows with provenance columns; the board renders a form. Both ask this
// package what the settings are.
//
// Two properties are the reason this is more than a map of strings. Every
// value says WHERE it came from — this host, the global file, or devtun's own
// default — because with two levels of configuration, a screen showing `auto`
// without saying which file said so is a value nobody can act on. And every
// write names its level, so changing something for one box cannot quietly
// rewrite the answer every other box was using.
package settings

import (
	"errors"
	"strings"

	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/tunnels"
)

// Level is where a value lives, and where an edit lands.
type Level int

const (
	LevelHost Level = iota
	LevelGlobal
	// LevelNone is what neither file said: the value in use is devtun's own
	// default, and nothing on disk is deciding it.
	LevelNone
)

func (l Level) String() string {
	switch l {
	case LevelHost:
		return "host"
	case LevelGlobal:
		return "global"
	default:
		return "default"
	}
}

// OptInherit is the option that clears a level, so a host can stop having an
// opinion and fall back to the global file — and the global file back to
// devtun's default. It is first in every option list because it is where a
// setting starts out.
const OptInherit = "inherit"

// Where a setting can live, in precedence order. BothLevels is written once
// rather than spelled out per row because that order *is* the rule: the host's
// answer, then the global one.
var (
	BothLevels = []Level{LevelHost, LevelGlobal}
	GlobalOnly = []Level{LevelGlobal}
	HostOnly   = []Level{LevelHost}
)

// ErrNoConfig is what every write says on a --no-config run: the surfaces still
// list the settings and still say what devtun is doing, and only saving is
// missing.
var ErrNoConfig = errors.New("nowhere to record that — no config file")

// sortChoices are the orderings worth reaching without knowing that `s` cycles
// them.
var sortChoices = []string{"port", "recent", "traffic", "process"}

// Setting is one adjustable value.
type Setting struct {
	// Key is stable and machine-readable: it names the setting in a toast, in
	// an editor, in an HTTP request, and in a test that does not want to depend
	// on the wording.
	Key   string
	Title string
	// Options are the values a surface steps through. Empty means the value is
	// free text and is typed rather than chosen.
	Options []string
	// Levels are the levels this setting can be written at, in precedence
	// order. A setting with one of them ignores what a surface has armed.
	Levels []Level
	// Value is what devtun would use right now, and where that came from.
	Value func() (string, Level)
	// Raw is what one level says on its own, empty when it says nothing.
	Raw func(Level) string
	// Set writes at one level. An empty value clears it.
	Set  func(Level, string) error
	Help func() string
	// Validate refuses a text value before anything is written.
	Validate func(string) error
	// After runs once a value is written, for the settings this session can act
	// on rather than leaving to the next connection.
	After func()
	// Unusable explains a value this machine cannot honour — a desktop dialog
	// with no program to draw one — and is empty when it can. A warning rather
	// than a refusal: the file may be perfectly right on the machine it is
	// synced to next.
	Unusable func() string
}

// Writes reports whether the setting can be written at a level.
func (s *Setting) Writes(level Level) bool {
	for _, l := range s.Levels {
		if l == level {
			return true
		}
	}
	return false
}

// EditLevel is where an edit lands: the level a surface has armed, or the only
// level this setting has.
func (s *Setting) EditLevel(armed Level) Level {
	if s.Writes(armed) {
		return armed
	}
	return s.Levels[0]
}

// Section groups settings under a heading.
type Section struct {
	Title    string
	Settings []*Setting
}

// Store is the slice of the configuration files a setting needs.
//
// An interface rather than *hostcfg.Store so a test can hand this package a
// map, and so neither surface has to own a real config file to render a
// settings screen.
type Store interface {
	Setting(label, section, key string) string
	SetSetting(label, section, key, value string) error
	Save() error
}

// Deps is what the catalogue needs from a session.
//
// It is a struct of functions rather than an interface because the two callers
// have almost nothing else in common: the terminal holds a Bubble Tea model and
// the board holds an HTTP server, and neither wants to grow methods for the
// other's benefit.
type Deps struct {
	// Store is the configuration files. Nil is a --no-config run: every setting
	// still lists and still reports what devtun is doing, and only writing
	// fails.
	Store Store
	// Host is the label decisions are recorded against.
	Host string
	// Services is the registry, which is what makes the service rows appear
	// without this package knowing any service's name.
	Services []service.Service
	// ServiceDetail is why a service cannot run here, empty when it can. That
	// sentence is the one the user has to act on, so it displaces the help.
	ServiceDetail func(id string) string
	// PromptNow is where approvals are actually appearing this run, which the
	// command line can override without touching either file.
	PromptNow func() string
	// ApplyPrompt puts a changed prompt setting into effect now rather than at
	// the next connection.
	ApplyPrompt func(string)
	// ReloadServices is called after a service is toggled, so the surface's own
	// list of what is running is not left stale.
	ReloadServices func()
	// Prefs and SetPrefs are the tunnel table's presentation, which the tunnels
	// service persists for this host.
	Prefs    func() tunnels.ViewPrefs
	SetPrefs func(tunnels.ViewPrefs)
	// DialogChooser names the program this machine would raise a desktop dialog
	// with, empty when there is none. A function because looking along PATH is
	// worth caching, and the caller is who knows how long a cache may live.
	DialogChooser func() string
}

// Catalogue is every setting, grouped.
func (d Deps) Catalogue() []Section {
	return []Section{
		// Approvals first, and the prompt at the top of it: it is the setting
		// people go looking for, and the one they were not finding.
		{Title: "Approvals", Settings: d.approvalSettings()},
		{Title: "Services", Settings: d.serviceSettings()},
		{Title: "Ports", Settings: d.portSettings()},
		{Title: "Remote setup", Settings: d.remoteSettings()},
		{Title: "View", Settings: d.viewSettings()},
	}
}

// Find returns the setting with this key, nil when there is none. Surfaces hold
// on to a key rather than a pointer between building the catalogue and writing
// to it, because the catalogue is rebuilt often enough that a pointer would be
// aimed at a setting that no longer exists.
func (d Deps) Find(key string) *Setting {
	for _, section := range d.Catalogue() {
		for _, s := range section.Settings {
			if s.Key == key {
				return s
			}
		}
	}
	return nil
}

func (d Deps) approvalSettings() []*Setting {
	promptRow := d.storeSetting("prompt", "Approvals appear", "", hostcfg.KeyPrompt, BothLevels, "auto")
	// all first, because it is the default and the right answer: devtun runs
	// in a window you are not looking at, so asking everywhere is what stops a
	// question becoming a timeout. The rest narrow it deliberately.
	promptRow.Options = []string{OptInherit, "all", "tui", "native", "web", "deny"}
	promptRow.Help = func() string { return d.promptHelp() }
	promptRow.Unusable = func() string {
		value, _ := promptRow.Value()
		surfaces, err := prompt.ParseSurfaces(value)
		if err != nil {
			return "not a place approvals can appear"
		}
		// Only a surface that was NAMED is worth warning about. `all` asking
		// in fewer places than it could is the arrangement working, not a
		// problem to report.
		if value == "all" || value == "auto" {
			return ""
		}
		if surfaces.Has(prompt.SurfaceNative) && d.chooser() == "" {
			return "no dialog program here — nothing will draw that"
		}
		return ""
	}
	promptRow.After = func() {
		if d.ApplyPrompt == nil {
			return
		}
		value, _ := promptRow.Value()
		d.ApplyPrompt(value)
	}
	settings := []*Setting{promptRow}

	// The browser's gate is named here rather than discovered, because it is a
	// two-level setting and service.Setting has no levels — it hands a service
	// one document and asks for a string back. Listing it costs a line and an
	// `if`; leaving it out costs somebody the only place it can be reached.
	if d.hasService("browser") {
		gate := d.storeSetting("gate", "Ask before a site", "browser", "gate", BothLevels, "auto")
		gate.Options = []string{OptInherit, "ask", "auto"}
		gate.Help = func() string {
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
// asking in the terminal — correct behaviour, and completely invisible from a
// screen that renders the word "dialog" and stops there.
func (d Deps) promptHelp() string {
	// What to install comes first when there is nothing to draw a dialog with.
	// It is the only part of the line somebody can act on, and the help is the
	// first thing to give way on a narrow terminal.
	chooser := d.chooser()
	base := "where an approval appears · native uses " + chooser + " here"
	if chooser == "" {
		// Commas rather than " or ": on Linux there are three choosers, and the
		// difference between "zenity or kdialog or yad" and "zenity, kdialog,
		// yad" is six columns — which is the difference between the last name
		// being readable and being the bit the ellipsis eats.
		base = "no dialog program here: install " + strings.Join(prompt.ChooserNames(), ", ") +
			" · otherwise approvals appear in this window"
	}
	// The command line beats both files for this run, so a session started with
	// --prompt is asking somewhere other than what the files say. Saying which
	// is cheaper than letting somebody wonder why the screen disagrees.
	if d.PromptNow != nil {
		if configured, _ := d.ConfiguredPrompt(); d.PromptNow() != configured {
			base += " · this run: " + d.PromptNow()
		}
	}
	return base
}

// ConfiguredPrompt is what the files alone say, resolved the way a session
// resolves it.
func (d Deps) ConfiguredPrompt() (string, Level) {
	if d.Store == nil {
		return "all", LevelNone
	}
	if v := d.Store.Setting(d.Host, "", hostcfg.KeyPrompt); v != "" {
		return v, LevelHost
	}
	if v := d.Store.Setting("", "", hostcfg.KeyPrompt); v != "" {
		return v, LevelGlobal
	}
	return "all", LevelNone
}

// serviceSettings are the toggles and then whatever each service says is
// adjustable, both found by asking the registry rather than by a list here.
func (d Deps) serviceSettings() []*Setting {
	var settings []*Setting
	for _, svc := range d.Services {
		meta := svc.Meta()
		// The fallback is the service's own answer — on, unless it is one that
		// has to be asked for — which is what the session arrives at when
		// neither file says anything.
		fallback := "on"
		if meta.OptIn {
			fallback = "off"
		}
		row := d.storeSetting(meta.ID, meta.Glyph+" "+meta.Title, hostcfg.SectionServices, meta.ID,
			BothLevels, fallback)
		row.Options = []string{OptInherit, "on", "off"}
		row.Help = func() string { return d.serviceHelp(meta.ID, meta.Short) }
		row.After = d.ReloadServices
		settings = append(settings, showAsOnOff(row))
	}

	for _, svc := range d.Services {
		cfg, ok := svc.(service.Configurable)
		if !ok {
			continue
		}
		title := svc.Meta().Title
		for _, s := range cfg.Settings() {
			settings = append(settings, ServiceSetting(svc.Meta().ID+"."+s.Key, s.Title, title, s))
		}
	}
	return settings
}

// portSettings are the two never-forward lists. Both are text: a range is what
// a person means on a box that binds its test servers to port 0, and no list of
// options can express one.
func (d Deps) portSettings() []*Setting {
	here := d.storeSetting("hide.host", "Hidden on "+d.Host, "tunnels", hostcfg.KeyHide, HostOnly, "")
	here.Validate = ValidPortSpec
	here.Help = func() string {
		return "never forwarded on this box, e.g. 5432,32768-60999 · from the next connection"
	}

	everywhere := d.storeSetting("hide.global", "Hidden everywhere", "", hostcfg.KeyHide, GlobalOnly, "")
	everywhere.Validate = ValidPortSpec
	everywhere.Help = func() string {
		return "never forwarded on any box · from the next connection"
	}
	return []*Setting{here, everywhere}
}

// ValidPortSpec refuses a hide list before it is saved. A list that will not
// parse forwards everything it was written to hide, and it would do so silently
// on the next connection rather than now, in front of the person who typed it.
func ValidPortSpec(spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	_, err := tunnels.ParsePortSet(spec)
	return err
}

func (d Deps) remoteSettings() []*Setting {
	setup := d.storeSetting("setup", "Shell rc on the box", "", hostcfg.KeySetup, GlobalOnly, "ask")
	setup.Options = []string{OptInherit, "ask", "auto", "never"}
	setup.Help = func() string {
		return "offer to add devtun's line to the remote shell rc · from the next connection"
	}
	return []*Setting{setup}
}

// viewSettings are the interface's own, which the tunnels service persists for
// this host along with everything else it remembers about it.
//
// They are in the shared catalogue rather than the terminal's own because both
// surfaces list the same table from the same preferences: a sort order changed
// on the board and ignored by the terminal would be the two of them disagreeing
// about a thing they both persist.
func (d Deps) viewSettings() []*Setting {
	if d.Prefs == nil || d.SetPrefs == nil {
		return nil
	}
	sort := ServiceSetting("view.sort", "Sort by", "", service.Setting{
		Options: sortChoices,
		Help:    "the order the tunnel table is listed in",
		Get:     func() string { return d.Prefs().Sort },
		Set: func(v string) {
			p := d.Prefs()
			p.Sort = v
			d.SetPrefs(p)
		},
	})
	reverse := ServiceSetting("view.reverse", "Reverse", "", service.Setting{
		Help: "read the table from the other end",
		Get:  func() string { return boolWord(d.Prefs().Reverse) },
		Set: func(v string) {
			p := d.Prefs()
			p.Reverse = v == "true"
			d.SetPrefs(p)
		},
	})
	return []*Setting{sort, reverse}
}

// storeSetting builds a setting backed by devtun's own configuration files.
//
// It reads each level separately rather than asking for the resolved value: the
// provenance is the whole point of this package, and a resolved read cannot
// tell "this host says auto" from "nobody has said anything".
func (d Deps) storeSetting(key, title, section, name string, levels []Level, fallback string) *Setting {
	at := func(level Level) string {
		if d.Store == nil {
			return ""
		}
		switch level {
		case LevelHost:
			return d.Store.Setting(d.Host, section, name)
		case LevelGlobal:
			return d.Store.Setting("", section, name)
		default:
			return ""
		}
	}
	return &Setting{
		Key:    key,
		Title:  title,
		Levels: levels,
		Raw:    at,
		Value: func() (string, Level) {
			for _, level := range levels {
				if v := at(level); v != "" {
					return v, level
				}
			}
			return fallback, LevelNone
		},
		Set: func(level Level, value string) error {
			if d.Store == nil {
				return ErrNoConfig
			}
			label := d.Host
			if level == LevelGlobal {
				label = ""
			}
			if err := d.Store.SetSetting(label, section, name, value); err != nil {
				return err
			}
			// Saved now rather than on exit like the port table. This is the
			// screen somebody opens to change a setting and then goes back to
			// work, and a settings screen whose writes are still in memory when
			// the laptop dies has not saved anything.
			return d.Store.Save()
		},
		Help: func() string { return "" },
	}
}

// ServiceSetting builds a setting a service owns.
//
// service.Setting has no levels — a service is handed one document per host and
// writes back to it — so it reports `host`, which is where an edit lands. It is
// the one place where the provenance describes the write rather than the read,
// and the alternative was a blank column that reads as a bug.
func ServiceSetting(key, title, owner string, s service.Setting) *Setting {
	options := s.Options
	if len(options) == 0 {
		options = []string{"on", "off"}
	}
	row := &Setting{
		Key:     key,
		Title:   title,
		Options: options,
		Levels:  HostOnly,
		Raw:     func(Level) string { return s.Get() },
		Value:   func() (string, Level) { return s.Get(), LevelHost },
		Set: func(_ Level, value string) error {
			s.Set(value)
			return nil
		},
		Help: func() string {
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

// showAsOnOff rewrites a setting to deal in the words on screen rather than the
// spelling in the file. `true` is a fine thing to find in YAML and a poor thing
// to read in a column headed by a service name.
func showAsOnOff(s *Setting) *Setting {
	raw, value, set := s.Raw, s.Value, s.Set
	s.Raw = func(l Level) string { return onOff(raw(l)) }
	s.Value = func() (string, Level) {
		v, level := value()
		return onOff(v), level
	}
	s.Set = func(l Level, v string) error { return set(l, boolOf(v)) }
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
func (d Deps) hasService(id string) bool {
	for _, svc := range d.Services {
		if svc.Meta().ID == id {
			return true
		}
	}
	return false
}

// serviceHelp is the line beside a service toggle: the reason it cannot run
// here if there is one, since that is what the user has to act on, and
// otherwise what it does plus when a change lands.
func (d Deps) serviceHelp(id, short string) string {
	if d.ServiceDetail != nil {
		if detail := d.ServiceDetail(id); detail != "" {
			return detail
		}
	}
	return short + " · from the next connection"
}

func (d Deps) chooser() string {
	if d.DialogChooser == nil {
		return ""
	}
	return d.DialogChooser()
}
