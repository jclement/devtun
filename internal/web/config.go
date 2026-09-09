package web

import (
	"net/http"
	"strings"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"

	"github.com/jclement/devtun/internal/settings"
	"github.com/jclement/devtun/internal/tunnels"
)

// The board's settings and services.
//
// These were the two things the terminal could do and the board could not, and
// under --web the board is the surface — so a machine with no `op` installed,
// or approvals arriving somewhere nobody is looking, were both invisible to the
// only screen the user had open.
//
// The catalogue itself is not here. It is in internal/settings, which the
// terminal reads too, because a settings list written twice is a settings list
// that disagrees with itself the first time one of them is edited.

// settingView is one row of the settings screen.
type settingView struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Value is what devtun would use right now, and Level says which file
	// decided it — "host", "global", or "default" for devtun's own answer.
	Value string `json:"value"`
	Level string `json:"level"`
	// Raw is what each level says on its own, empty where it says nothing.
	// The board needs both: the value is what is in force, and these are what
	// an edit at that level would be changing.
	Raw map[string]string `json:"raw"`
	// Options are the values to choose between. Empty means free text.
	Options []string `json:"options,omitempty"`
	// Levels are the levels this setting accepts, so the board can refuse an
	// edit at one it does not, rather than writing somewhere it is ignored.
	Levels []string `json:"levels"`
	Help   string   `json:"help,omitempty"`
	// Warn is a value this machine cannot honour — a desktop dialog with no
	// program to draw one. Not an error: the file may be right on the machine
	// it is synced to next.
	Warn string `json:"warn,omitempty"`
}

type sectionView struct {
	Title    string        `json:"title"`
	Settings []settingView `json:"settings"`
}

type configView struct {
	Host     string        `json:"host"`
	Sections []sectionView `json:"sections"`
	// Editable is false on a --no-config run: every setting still lists and
	// still says what devtun is doing, and only saving is missing. The board
	// says so once rather than failing each write in turn.
	Editable bool `json:"editable"`
}

// settingsDeps assembles the catalogue for this session.
func (s *Server) settingsDeps() settings.Deps {
	return settings.Deps{
		Store:         s.opts.Store,
		Host:          s.opts.Host,
		Services:      s.opts.Services,
		ServiceDetail: func(id string) string { return s.serviceState(id).Detail },
		PromptNow:     s.opts.PromptNow,
		ApplyPrompt:   s.opts.ApplyPrompt,
		Prefs:         s.prefs,
		SetPrefs:      s.setPrefs,
		DialogChooser: s.dialogChooser,
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	d := s.settingsDeps()
	view := configView{Host: s.opts.Host, Editable: s.opts.Store != nil}
	for _, section := range d.Catalogue() {
		out := sectionView{Title: section.Title}
		for _, setting := range section.Settings {
			out.Settings = append(out.Settings, s.settingView(setting))
		}
		if len(out.Settings) > 0 {
			view.Sections = append(view.Sections, out)
		}
	}
	writeJSON(w, view)
}

func (s *Server) settingView(setting *settings.Setting) settingView {
	value, level := setting.Value()
	out := settingView{
		Key:     setting.Key,
		Title:   setting.Title,
		Value:   value,
		Level:   level.String(),
		Options: setting.Options,
		Help:    setting.Help(),
		Raw:     map[string]string{},
	}
	for _, l := range setting.Levels {
		out.Levels = append(out.Levels, l.String())
		if raw := setting.Raw(l); raw != "" {
			out.Raw[l.String()] = raw
		}
	}
	if setting.Unusable != nil {
		out.Warn = setting.Unusable()
	}
	return out
}

// handleSetting writes one setting at one level.
//
// The level is named by the caller rather than inferred, for the same reason
// the terminal arms one with `g`: changing something for the box in front of
// you and changing it for every box you ever connect to are different
// decisions, and a screen that picks for you will eventually pick wrong.
func (s *Server) handleSetting(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	d := s.settingsDeps()
	setting := d.Find(key)
	if setting == nil {
		http.Error(w, "no setting called "+key, http.StatusNotFound)
		return
	}

	level, ok := levelNamed(r.URL.Query().Get("level"))
	if !ok {
		http.Error(w, "level must be host or global", http.StatusBadRequest)
		return
	}
	if !setting.Writes(level) {
		// Refused rather than quietly redirected to the level it does accept:
		// a write that lands somewhere other than where it was aimed is worse
		// than one that does not happen.
		http.Error(w, setting.Title+" can only be set for "+setting.Levels[0].String(),
			http.StatusConflict)
		return
	}

	// A step is what a button press means — move to the next option — and is
	// resolved here so the board does not have to know that clearing a level is
	// spelled as the empty string.
	value := r.URL.Query().Get("value")
	if step := r.URL.Query().Get("step"); step != "" {
		delta := 1
		if step == "-1" {
			delta = -1
		}
		stepped, ok := settings.Step(setting, level, delta)
		if !ok {
			http.Error(w, setting.Title+" is typed, not chosen", http.StatusBadRequest)
			return
		}
		value = stepped
	}

	result, err := settings.Apply(setting, level, value, s.opts.Host)
	if err != nil {
		http.Error(w, firstLine(err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"text": result.Text, "warn": result.Warn})
}

// levelNamed reads a level from a request. Only the two writable ones are
// accepted: "default" is where a value came from, never somewhere to put one.
func levelNamed(name string) (settings.Level, bool) {
	switch name {
	case "host":
		return settings.LevelHost, true
	case "global":
		return settings.LevelGlobal, true
	}
	return settings.LevelNone, false
}

// firstLine keeps an error to the sentence a person reads. A port-set parse
// failure can carry the whole spec back with it, and the board has one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// prefs and setPrefs reach the tunnel table's presentation, which the tunnels
// service persists for this host. A session with no tunnels service still has
// a settings screen; it just has no view settings on it.
func (s *Server) prefs() tunnels.ViewPrefs {
	if s.opts.Tunnels == nil {
		return tunnels.ViewPrefs{}
	}
	return s.opts.Tunnels.ViewPrefs()
}

func (s *Server) setPrefs(p tunnels.ViewPrefs) {
	if s.opts.Tunnels != nil {
		s.opts.Tunnels.SetViewPrefs(p)
	}
}

func (s *Server) dialogChooser() string {
	if s.opts.DialogChooser == nil {
		return ""
	}
	return s.opts.DialogChooser()
}

// --- what each service is actually doing ------------------------------------

// The board learns a service's state the same way the interface does: from the
// event bus. There is no other source — `Probe` runs on the session, and its
// answer ("no `op` on this box") reaches everyone as an event and nowhere else.
//
// Without it the board could say a service was off and never why, which is the
// difference between a row and something a person can act on. It was the last
// thing the Services tab had that the board did not.

// svcState is one service's last known state.
type svcState struct {
	Running bool `json:"running"`
	// Detail is the reason it cannot run here, empty when it can.
	Detail string `json:"detail,omitempty"`
}

// watchServices keeps the map current. The returned function stops it.
func (s *Server) watchServices() func() {
	if s.opts.Bus == nil {
		return func() {}
	}
	// The history first, so a board opened ten minutes into a session is not
	// blank until something happens to be said.
	for _, e := range s.opts.Bus.History() {
		s.noteService(e)
	}
	return s.opts.Bus.Subscribe(s.noteService)
}

func (s *Server) noteService(e event.Event) {
	s.svcMu.Lock()
	defer s.svcMu.Unlock()
	if s.svc == nil {
		s.svc = map[string]svcState{}
	}

	if e.Service == "" || e.Service == "session" {
		if e.Kind != "disconnected" && e.Kind != "connect-failed" {
			return
		}
		// The link went away and every instance went with it.
		for id, st := range s.svc {
			st.Running = false
			s.svc[id] = st
		}
		return
	}

	st := s.svc[e.Service]
	switch e.Kind {
	case "started":
		st.Running, st.Detail = true, ""
	case "unavailable", "attach-failed", "disabled":
		st.Running, st.Detail = false, e.Text
	default:
		return
	}
	s.svc[e.Service] = st
}

func (s *Server) serviceState(id string) svcState {
	s.svcMu.Lock()
	defer s.svcMu.Unlock()
	return s.svc[id]
}

// enabledFor reports whether a service is switched on for this host. The
// default is the service's own — on, unless it is one that has to be asked for.
func (s *Server) enabledFor(meta service.Meta) bool {
	store, ok := s.opts.Store.(interface {
		Enabled(label, serviceID string, fallback bool) bool
	})
	if !ok || store == nil {
		return !meta.OptIn
	}
	return store.Enabled(s.opts.Host, meta.ID, !meta.OptIn)
}
