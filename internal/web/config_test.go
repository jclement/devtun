package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/service"
)

// memStore is the two configuration files, as a map.
//
// It keeps ONE map, because the real store does: a service's on/off state and
// the `services:` setting of the same name are the same value read two ways,
// and a stub with two maps would let a test pass while the board's own service
// list disagreed with its settings screen. Which is exactly what it did.
type memStore struct{ values map[string]string }

func newMemStore() *memStore { return &memStore{values: map[string]string{}} }

func (m *memStore) key(label, section, k string) string { return label + "/" + section + "/" + k }

func (m *memStore) Setting(label, section, k string) string {
	return m.values[m.key(label, section, k)]
}

func (m *memStore) SetSetting(label, section, k, value string) error {
	if value == "" {
		delete(m.values, m.key(label, section, k))
		return nil
	}
	m.values[m.key(label, section, k)] = value
	return nil
}

func (m *memStore) Save() error { return nil }

func (m *memStore) Enabled(label, id string, fallback bool) bool {
	// The host's answer, then the global one, then the caller's — the order
	// the real store resolves in.
	for _, at := range []string{label, ""} {
		if v := m.Setting(at, hostcfg.SectionServices, id); v != "" {
			return v == "true"
		}
	}
	return fallback
}

// stubService is a service with nothing behind it, which is all the settings
// screen needs: it reads Meta and never attaches anything.
type stubService struct{ meta service.Meta }

func (s stubService) Meta() service.Meta { return s.meta }

func (s stubService) Probe(context.Context, service.Host) service.Support {
	return service.Support{OK: true}
}

func (s stubService) Attach(context.Context, service.Host) (service.Instance, error) {
	return nil, errors.New("this service does not attach")
}

func configServer(t *testing.T, store *memStore, services ...service.Service) *Server {
	t.Helper()
	return newTestServer(t, Options{
		Host:          "bedev",
		Store:         store,
		Services:      services,
		Bus:           event.NewBus(100),
		PromptNow:     func() string { return "all" },
		DialogChooser: func() string { return "osascript" },
	})
}

func readConfig(t *testing.T, s *Server) configView {
	t.Helper()
	got := ask(t, s, http.MethodGet, "/api/config")
	if got.Code != http.StatusOK {
		t.Fatalf("GET /api/config = %d: %s", got.Code, got.Body)
	}
	var view configView
	if err := json.Unmarshal(got.Body.Bytes(), &view); err != nil {
		t.Fatalf("the settings did not decode: %v", err)
	}
	return view
}

func setting(t *testing.T, view configView, key string) settingView {
	t.Helper()
	for _, section := range view.Sections {
		for _, s := range section.Settings {
			if s.Key == key {
				return s
			}
		}
	}
	t.Fatalf("no setting %q on the board", key)
	return settingView{}
}

// The board offers the settings, which it could not do at all until the
// catalogue stopped being private to the terminal.
func TestTheBoardListsTheSameSettingsTheInterfaceDoes(t *testing.T) {
	view := readConfig(t, configServer(t, newMemStore()))
	if !view.Editable {
		t.Error("a session with a config file says nothing can be saved")
	}
	// Not an exhaustive list — that would be a test of the catalogue, which
	// has its own — but the sections a person goes looking for.
	for _, key := range []string{"prompt", "hide.host", "hide.global", "setup"} {
		if s := setting(t, view, key); s.Title == "" {
			t.Errorf("%q came back with no title", key)
		}
	}
}

// Provenance is the point. A screen that says `auto` without saying which file
// said so is a value nobody can act on.
func TestEverySettingSaysWhichFileDecidedIt(t *testing.T) {
	store := newMemStore()
	s := configServer(t, store)

	if got := setting(t, readConfig(t, s), "prompt"); got.Value != "auto" || got.Level != "default" {
		t.Errorf("with both files silent = %q at %q", got.Value, got.Level)
	}

	_ = store.SetSetting("", "", hostcfg.KeyPrompt, "dialog")
	if got := setting(t, readConfig(t, s), "prompt"); got.Value != "dialog" || got.Level != "global" {
		t.Errorf("with only the global file = %q at %q", got.Value, got.Level)
	}

	// Raw is what each level says alone, which is what the control on the page
	// shows — an empty level means `inherit`, and stepping off it is a decision
	// rather than agreeing with the level below.
	_ = store.SetSetting("bedev", "", hostcfg.KeyPrompt, "tui")
	got := setting(t, readConfig(t, s), "prompt")
	if got.Raw["host"] != "tui" || got.Raw["global"] != "dialog" {
		t.Errorf("the levels came back as %+v", got.Raw)
	}
}

// Writing from the board must land where it was aimed, and nowhere else.
func TestWritingASettingFromTheBoardLandsAtTheNamedLevel(t *testing.T) {
	store := newMemStore()
	s := configServer(t, store)

	if got := ask(t, s, http.MethodPost, "/api/config/prompt?level=host&value=tui"); got.Code != http.StatusOK {
		t.Fatalf("writing a setting = %d: %s", got.Code, got.Body)
	}
	if store.Setting("bedev", "", hostcfg.KeyPrompt) != "tui" {
		t.Error("the value never reached the host file")
	}
	if store.Setting("", "", hostcfg.KeyPrompt) != "" {
		t.Error("an edit for one host reached the global file")
	}

	// And the reply carries the sentence, because that is most of what the
	// person reads: which level it landed on, in words.
	if got := ask(t, s, http.MethodPost, "/api/config/prompt?level=global&value=deny"); got.Code != http.StatusOK {
		t.Fatalf("writing globally = %d", got.Code)
	} else if body := got.Body.String(); !strings.Contains(body, "every host") {
		t.Errorf("a global write reported %q without saying so", body)
	}
}

// A write aimed at a level the setting does not accept is refused rather than
// quietly redirected: a write that lands somewhere other than where it was
// aimed is worse than one that does not happen.
func TestASettingRefusesALevelItDoesNotAccept(t *testing.T) {
	s := configServer(t, newMemStore())

	// The remote-setup line is global only.
	if got := ask(t, s, http.MethodPost, "/api/config/setup?level=host&value=never"); got.Code != http.StatusConflict {
		t.Errorf("a host-level write to a global-only setting = %d, want 409", got.Code)
	}
	// And the per-host hide list is the other way round.
	if got := ask(t, s, http.MethodPost, "/api/config/hide.host?level=global&value=5432"); got.Code != http.StatusConflict {
		t.Errorf("a global write to a host-only setting = %d, want 409", got.Code)
	}
	for _, bad := range []string{"", "default", "nonsense"} {
		path := "/api/config/prompt?level=" + bad + "&value=tui"
		if got := ask(t, s, http.MethodPost, path); got.Code != http.StatusBadRequest {
			t.Errorf("level=%q was accepted: %d", bad, got.Code)
		}
	}
	if got := ask(t, s, http.MethodPost, "/api/config/nope?level=host&value=x"); got.Code != http.StatusNotFound {
		t.Errorf("an unknown setting = %d, want 404", got.Code)
	}
}

// A hide list that will not parse forwards everything it was written to hide,
// silently, on the next connection.
func TestTheBoardRefusesAValueThatWillNotParse(t *testing.T) {
	store := newMemStore()
	s := configServer(t, store)

	got := ask(t, s, http.MethodPost, "/api/config/hide.host?level=host&value=5432,nope")
	if got.Code != http.StatusBadRequest {
		t.Errorf("a malformed hide list = %d, want 400", got.Code)
	}
	if store.Setting("bedev", "tunnels", hostcfg.KeyHide) != "" {
		t.Error("the refused value was written anyway")
	}
}

// Clearing a level is how a host stops having an opinion.
func TestClearingFromTheBoardFallsBackToTheGlobalFile(t *testing.T) {
	store := newMemStore()
	_ = store.SetSetting("", "", hostcfg.KeyPrompt, "dialog")
	_ = store.SetSetting("bedev", "", hostcfg.KeyPrompt, "tui")
	s := configServer(t, store)

	if got := ask(t, s, http.MethodPost, "/api/config/prompt?level=host&value="); got.Code != http.StatusOK {
		t.Fatalf("clearing = %d: %s", got.Code, got.Body)
	}
	if got := setting(t, readConfig(t, s), "prompt"); got.Value != "dialog" || got.Level != "global" {
		t.Errorf("after clearing the host = %q at %q", got.Value, got.Level)
	}
}

// Switching a service on or off from the board goes through the same setting
// the terminal writes — two ways to write one value is how the two surfaces
// started disagreeing in the first place.
func TestSwitchingAServiceFromTheBoardWritesTheSameSetting(t *testing.T) {
	store := newMemStore()
	svc := stubService{meta: service.Meta{ID: "1password", Title: "1Password", Short: "vault reads"}}
	s := configServer(t, store, svc)

	if got := ask(t, s, http.MethodPost, "/api/config/1password?level=host&value=off"); got.Code != http.StatusOK {
		t.Fatalf("switching a service off = %d: %s", got.Code, got.Body)
	}
	// `off` on screen is `false` in the file: the words differ deliberately,
	// and the board must not be writing the ones people read.
	if got := store.Setting("bedev", hostcfg.SectionServices, "1password"); got != "false" {
		t.Errorf("the services section says %q, want false", got)
	}

	// And the board's own service list has to follow it. These are two reads
	// of one value, and a page whose Services section says a service is on
	// while its Settings section says off is worse than either alone.
	if got := stateOf(t, s).Services[0]; got.Enabled {
		t.Error("the service list still shows it switched on after it was switched off")
	}
}

// A service that is switched on and still not running is the case people
// actually hit, and "off" on its own tells them nothing to act on.
func TestTheBoardSaysWhyAServiceIsNotRunning(t *testing.T) {
	bus := event.NewBus(100)
	svc := stubService{meta: service.Meta{ID: "1password", Title: "1Password"}}
	s := newTestServer(t, Options{Host: "bedev", Store: newMemStore(), Services: []service.Service{svc}, Bus: bus})

	stop := s.watchServices()
	defer stop()
	bus.Emit(event.Event{Service: "1password", Kind: "unavailable", Text: "no `op` on the remote box"})

	view := stateOf(t, s)
	if len(view.Services) != 1 {
		t.Fatalf("the board listed %d services", len(view.Services))
	}
	got := view.Services[0]
	if got.Running {
		t.Error("a service reported as unavailable is shown as running")
	}
	if got.Detail != "no `op` on the remote box" {
		t.Errorf("the board says %q, which is not the thing to go and fix", got.Detail)
	}
	if !got.Enabled {
		t.Error("a service nobody switched off is shown as switched off")
	}

	// And when it comes up, the reason goes with it.
	bus.Emit(event.Event{Service: "1password", Kind: "started"})
	if got := stateOf(t, s).Services[0]; !got.Running || got.Detail != "" {
		t.Errorf("after starting: running=%v detail=%q", got.Running, got.Detail)
	}
}

// A --no-config run still lists every setting and still says what devtun is
// doing. The board says so once rather than failing each write in turn.
func TestWithoutAConfigFileTheBoardStillListsSettings(t *testing.T) {
	s := newTestServer(t, Options{Host: "bedev", Bus: event.NewBus(10)})
	view := readConfig(t, s)
	if view.Editable {
		t.Error("a session with no config file says its settings can be saved")
	}
	if len(view.Sections) == 0 {
		t.Fatal("no settings listed at all")
	}
	if got := ask(t, s, http.MethodPost, "/api/config/prompt?level=host&value=tui"); got.Code == http.StatusOK {
		t.Error("a write with nowhere to write to reported success")
	}
}
