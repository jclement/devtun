package settings

import (
	"github.com/jclement/devtun/internal/browser"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/service"
)

// fakeStore is the two configuration files as a map, keyed by the label the
// value was written against — "" being the global file.
type fakeStore struct {
	values map[string]string
	saved  int
	fail   error
}

func newStore() *fakeStore { return &fakeStore{values: map[string]string{}} }

func (f *fakeStore) at(label, section, key string) string {
	return label + "/" + section + "/" + key
}

func (f *fakeStore) Setting(label, section, key string) string {
	return f.values[f.at(label, section, key)]
}

func (f *fakeStore) SetSetting(label, section, key, value string) error {
	if f.fail != nil {
		return f.fail
	}
	if value == "" {
		delete(f.values, f.at(label, section, key))
		return nil
	}
	f.values[f.at(label, section, key)] = value
	return nil
}

func (f *fakeStore) Save() error { f.saved++; return nil }

func deps(store Store) Deps {
	return Deps{Store: store, Host: "bedev", DialogChooser: func() string { return "osascript" }}
}

func find(t *testing.T, d Deps, key string) *Setting {
	t.Helper()
	s := d.Find(key)
	if s == nil {
		t.Fatalf("no setting %q in the catalogue", key)
	}
	return s
}

// The provenance is the point: a screen that says `auto` without saying which
// file said so is a value nobody can act on, and "nothing said anything" has to
// be distinguishable from "the global file said the same as the default".
func TestAValueSaysWhichFileDecidedIt(t *testing.T) {
	store := newStore()
	d := deps(store)

	value, level := find(t, d, "prompt").Value()
	if value != "auto" || level != LevelNone {
		t.Errorf("with both files silent = %q at %v, want auto at default", value, level)
	}

	_ = store.SetSetting("", "", hostcfg.KeyPrompt, "dialog")
	value, level = find(t, d, "prompt").Value()
	if value != "dialog" || level != LevelGlobal {
		t.Errorf("with only the global file = %q at %v, want dialog at global", value, level)
	}

	// The host's answer beats it, and says so — otherwise the two files
	// agreeing and one file deciding look identical on screen.
	_ = store.SetSetting("bedev", "", hostcfg.KeyPrompt, "tui")
	value, level = find(t, d, "prompt").Value()
	if value != "tui" || level != LevelHost {
		t.Errorf("with both files = %q at %v, want tui at host", value, level)
	}
}

// An edit at one level must not touch the other, which is the whole reason a
// level is armed rather than inferred.
func TestAnEditLandsOnlyAtItsOwnLevel(t *testing.T) {
	store := newStore()
	d := deps(store)
	s := find(t, d, "prompt")

	if _, err := Apply(s, LevelHost, "tui", "bedev"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := store.Setting("bedev", "", hostcfg.KeyPrompt); got != "tui" {
		t.Errorf("the host file says %q", got)
	}
	if got := store.Setting("", "", hostcfg.KeyPrompt); got != "" {
		t.Errorf("an edit for one host reached the global file: %q", got)
	}
}

// Clearing a level is how a host stops having an opinion, and the sentence has
// to name what it now inherits — "cleared" on its own leaves the person to go
// and look up what they have just started following.
func TestClearingALevelSaysWhatItNowInherits(t *testing.T) {
	store := newStore()
	_ = store.SetSetting("", "", hostcfg.KeyPrompt, "dialog")
	_ = store.SetSetting("bedev", "", hostcfg.KeyPrompt, "tui")
	d := deps(store)

	result, err := Apply(find(t, d, "prompt"), LevelHost, "", "bedev")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(result.Text, "dialog") || !strings.Contains(result.Text, "global") {
		t.Errorf("clearing said %q — it should name the value and the file it now follows", result.Text)
	}
	if value, level := find(t, d, "prompt").Value(); value != "dialog" || level != LevelGlobal {
		t.Errorf("after clearing the host = %q at %v", value, level)
	}
}

// Stepping starts from what the armed level says ON ITS OWN. Stepping from the
// resolved value instead would make the first press a no-op whenever the level
// below already said the same thing.
func TestSteppingStartsFromTheArmedLevelNotTheValueOnScreen(t *testing.T) {
	store := newStore()
	_ = store.SetSetting("", "", hostcfg.KeyPrompt, "tui")
	d := deps(store)
	s := find(t, d, "prompt")

	// The screen reads "tui (global)"; the host file is silent, so the host
	// starts on inherit and one press forward is a decision for this host.
	value, ok := Step(s, LevelHost, 1)
	if !ok {
		t.Fatal("a setting with options did not step")
	}
	if value != "all" {
		t.Errorf("stepping the silent host level gave %q, want the option after inherit", value)
	}

	// And one press back from there is the way to undo it.
	if _, err := Apply(s, LevelHost, value, "bedev"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	back, _ := Step(s, LevelHost, -1)
	if back != "" {
		t.Errorf("stepping back gave %q, want the empty value that clears the level", back)
	}
}

// A hide list that will not parse forwards everything it was written to hide,
// and it does so silently on the next connection rather than now.
func TestAValueThatWillNotParseIsRefusedRatherThanSaved(t *testing.T) {
	store := newStore()
	d := deps(store)
	s := find(t, d, "hide.host")

	if _, err := Apply(s, LevelHost, "5432,not-a-port", "bedev"); err == nil {
		t.Fatal("a malformed hide list was accepted")
	}
	if got := store.Setting("bedev", "tunnels", hostcfg.KeyHide); got != "" {
		t.Errorf("the refused value was written anyway: %q", got)
	}
	if _, err := Apply(s, LevelHost, "5432,32768-60999", "bedev"); err != nil {
		t.Errorf("a valid hide list was refused: %v", err)
	}
}

// A --no-config run still lists every setting and still reports what devtun is
// doing. Only writing fails, and it says why rather than appearing to work.
func TestWithoutAConfigFileSettingsStillReadAndWritesSayWhy(t *testing.T) {
	d := deps(nil)
	s := find(t, d, "prompt")

	if value, level := s.Value(); value != "auto" || level != LevelNone {
		t.Errorf("with no store = %q at %v", value, level)
	}
	if _, err := Apply(s, LevelHost, "tui", "bedev"); err == nil {
		t.Error("a write with nowhere to write to reported success")
	}
}

// Every write saves immediately. This is the screen somebody opens to change a
// setting and then goes back to work, and a settings screen whose writes are
// still in memory when the laptop dies has not saved anything.
func TestEveryWriteReachesDisk(t *testing.T) {
	store := newStore()
	d := deps(store)
	if _, err := Apply(find(t, d, "prompt"), LevelHost, "tui", "bedev"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if store.saved == 0 {
		t.Error("the value was set but never saved")
	}
}

// A setting that can only be written globally must report that rather than
// silently taking a host-level edit somewhere it did not land.
func TestASettingKnowsWhichLevelsItAccepts(t *testing.T) {
	d := deps(newStore())
	setup := find(t, d, "setup")
	if setup.Writes(LevelHost) {
		t.Error("the remote-setup setting claims to be writable per host")
	}
	if got := setup.EditLevel(LevelHost); got != LevelGlobal {
		t.Errorf("with host armed, a global-only setting edits at %v", got)
	}

	here := find(t, d, "hide.host")
	if here.Writes(LevelGlobal) {
		t.Error("the per-host hide list claims to be writable globally")
	}
}

// A value this machine cannot honour is a warning, not a refusal: the file may
// be right on the machine it is synced to next.
func TestADialogWithNothingToDrawItWarnsButIsStillWritten(t *testing.T) {
	store := newStore()
	d := deps(store)
	d.DialogChooser = func() string { return "" }

	result, err := Apply(d.Find("prompt"), LevelHost, "dialog", "bedev")
	if err != nil {
		t.Fatalf("a value this machine cannot honour was refused: %v", err)
	}
	if !result.Warn {
		t.Error("choosing a dialog with no program to draw one passed without a word")
	}
	if got := store.Setting("bedev", "", hostcfg.KeyPrompt); got != "dialog" {
		t.Errorf("the warned-about value was not written: %q", got)
	}
}

// gatedService is a service with a policy, which is all the catalogue looks for.
type gatedService struct {
	service.Service
	authz.Surface
	id string
}

func (g gatedService) Meta() service.Meta {
	return service.Meta{ID: g.id, Title: g.id, Glyph: "·"}
}

func newGated(id string) gatedService {
	return gatedService{id: id, Surface: authz.NewGate(authz.Config{}, nil).Surface()}
}

// Every broker with a policy gets its own unmatched row, so "only GitHub" for
// SSH does not also refuse every 1Password read nobody wrote a rule for.
func TestEachGatedBrokerHasAnUnmatchedSetting(t *testing.T) {
	store := newStore()
	d := deps(store)
	d.Services = []service.Service{newGated("1password"), newGated("ssh-agent"), stubPlain{}}

	ssh := find(t, d, "unmatched.ssh-agent")
	if v, level := ssh.Value(); v != "ask" || level != LevelNone {
		t.Errorf("default = %q (%s), want ask from devtun's default", v, level)
	}
	if _, err := Apply(ssh, LevelHost, "deny", "bedev"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := store.Setting("bedev", "ssh-agent", "unmatched"); got != "deny" {
		t.Errorf("stored %q under ssh-agent.unmatched, want deny", got)
	}
	if v, _ := find(t, d, "unmatched.1password").Value(); v != "ask" {
		t.Errorf("setting SSH changed 1Password: %q", v)
	}
	if _, err := Apply(ssh, LevelHost, "dney", "bedev"); err == nil {
		t.Error("a value that is neither ask nor deny was accepted")
	}
	if d.Find("unmatched.plain") != nil {
		t.Error("a service with no policy got an unmatched row")
	}
}

// The real store, end to end: the setting writes where the broker reads.
func TestTheUnmatchedSettingIsWhatTheBrokerReads(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	gate := authz.NewGate(authz.Config{}, nil)
	if err := gate.Adopt("bedev", store.Section("bedev", "ssh-agent"), "SSH"); err != nil {
		t.Fatal(err)
	}
	d := deps(store)
	d.Services = []service.Service{gatedService{id: "ssh-agent", Surface: gate.Surface()}}

	if _, err := Apply(find(t, d, "unmatched.ssh-agent"), LevelGlobal, "deny", "bedev"); err != nil {
		t.Fatal(err)
	}
	if u := gate.Unmatched(); u.Action != authz.ActionDeny || u.Level != "global" {
		t.Errorf("the broker reads %+v after the setting was written", u)
	}
}

type stubPlain struct{ service.Service }

func (stubPlain) Meta() service.Meta { return service.Meta{ID: "plain", Title: "plain"} }

// An unmatched edit loosens when the effective policy goes from deny to ask —
// directly, or by clearing a level so an ask is inherited. Tightening, and
// edits that leave deny in force, do not.
func TestLooseningClassifiesUnmatchedEdits(t *testing.T) {
	for _, c := range []struct {
		name          string
		host, global  string
		level         Level
		value         string
		wantLoosening bool
	}{
		{"host deny → ask", "deny", "", LevelHost, "ask", true},
		{"host deny → inherit, global silent", "deny", "", LevelHost, "", true},
		{"host deny → inherit spelled out", "deny", "", LevelHost, OptInherit, true},
		{"host deny → inherit, global deny", "deny", "deny", LevelHost, "", false},
		{"host ask → deny", "ask", "", LevelHost, "deny", false},
		{"host silent → deny", "", "", LevelHost, "deny", false},
		{"host ask over global deny → inherit", "ask", "deny", LevelHost, "", false},
		{"global deny → ask", "", "deny", LevelGlobal, "ask", true},
		{"global deny → inherit", "", "deny", LevelGlobal, "", true},
		// This host keeps its own deny, but every other host inheriting the
		// global deny would be loosened: still a loosening.
		{"global deny → ask under a host deny", "deny", "deny", LevelGlobal, "ask", true},
		{"global ask → deny", "", "ask", LevelGlobal, "deny", false},
		// A value that is neither reads as deny, so replacing it with ask loosens.
		{"host bad value → ask", "dney", "", LevelHost, "ask", true},
		{"host ask → ask", "ask", "", LevelHost, "ask", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := newStore()
			if c.host != "" {
				_ = store.SetSetting("bedev", "ssh-agent", "unmatched", c.host)
			}
			if c.global != "" {
				_ = store.SetSetting("", "ssh-agent", "unmatched", c.global)
			}
			d := deps(store)
			d.Services = []service.Service{newGated("ssh-agent")}
			got := Loosening(find(t, d, "unmatched.ssh-agent"), c.level, c.value)
			if (got != "") != c.wantLoosening {
				t.Errorf("Loosening = %q, want loosening %v", got, c.wantLoosening)
			}
		})
	}
}

// Step is how a surface cycles a value; a step that loosens is classified the
// same as typing the value would be.
func TestAStepThatLoosensIsClassified(t *testing.T) {
	store := newStore()
	_ = store.SetSetting("bedev", "ssh-agent", "unmatched", "deny")
	d := deps(store)
	d.Services = []service.Service{newGated("ssh-agent")}
	row := find(t, d, "unmatched.ssh-agent")
	value, ok := Step(row, LevelHost, 1) // deny → inherit (the options wrap)
	if !ok {
		t.Fatal("unmatched does not step")
	}
	if Loosening(row, LevelHost, value) == "" {
		t.Errorf("stepping deny → %q is not classified as loosening", value)
	}
	if Loosening(find(t, d, "setup"), LevelGlobal, "auto") != "" {
		t.Error("a setting with no Loosens classified an edit")
	}
}

// "Approvals appear" loosens when the effective value goes from asking nowhere
// to asking somewhere: a refusal becomes a question a person can approve.
func TestLooseningClassifiesPromptEdits(t *testing.T) {
	for _, c := range []struct {
		name          string
		host, global  string
		level         Level
		value         string
		wantLoosening bool
	}{
		{"host deny → all", "deny", "", LevelHost, "all", true},
		{"host deny → tui", "deny", "", LevelHost, "tui", true},
		{"host deny → tui,web", "deny", "", LevelHost, "tui,web", true},
		{"host none → native", "none", "", LevelHost, "native", true},
		{"host deny → inherit, default auto asks", "deny", "", LevelHost, "", true},
		{"host deny → inherit, global deny", "deny", "deny", LevelHost, "", false},
		{"host all → deny", "all", "", LevelHost, "deny", false},
		{"host tui → web", "tui", "", LevelHost, "web", false},
		{"host silent → all (auto already asks)", "", "", LevelHost, "all", false},
		{"global deny → all", "", "deny", LevelGlobal, "all", true},
		{"global deny → all under a host deny", "deny", "deny", LevelGlobal, "all", true},
		{"global deny → inherit", "", "deny", LevelGlobal, OptInherit, true},
		{"host unparseable → all", "nowhere", "", LevelHost, "all", true},
		{"host deny → unparseable", "deny", "", LevelHost, "nowhere", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := newStore()
			if c.host != "" {
				_ = store.SetSetting("bedev", "", "prompt", c.host)
			}
			if c.global != "" {
				_ = store.SetSetting("", "", "prompt", c.global)
			}
			got := Loosening(find(t, deps(store), "prompt"), c.level, c.value)
			if (got != "") != c.wantLoosening {
				t.Errorf("Loosening = %q, want loosening %v", got, c.wantLoosening)
			}
		})
	}
}

type browserService struct{ service.Service }

func (browserService) Meta() service.Meta { return service.Meta{ID: "browser", Title: "Browser"} }

// The browser's gate loosens when it stops being ask: anything else opens
// sites without a question.
func TestLooseningClassifiesBrowserGateEdits(t *testing.T) {
	for _, c := range []struct {
		name          string
		host, global  string
		level         Level
		value         string
		wantLoosening bool
	}{
		{"host ask → auto", "ask", "", LevelHost, "auto", true},
		{"host ask → inherit, default auto", "ask", "", LevelHost, "", true},
		{"host ask → inherit, global ask", "ask", "ask", LevelHost, "", false},
		{"host auto → ask", "auto", "", LevelHost, "ask", false},
		{"host silent → auto", "", "", LevelHost, "auto", false},
		{"global ask → auto", "", "ask", LevelGlobal, "auto", true},
		{"global ask → auto under a host ask", "ask", "ask", LevelGlobal, "auto", true},
		{"global auto → ask", "", "auto", LevelGlobal, "ask", false},
		// The browser reads anything but auto as ask (fail closed), so an
		// unknown value does not loosen — and Validate refuses it anyway.
		{"host ask → something else", "ask", "", LevelHost, "sometimes", false},
		{"host ask → AUTO", "ask", "", LevelHost, "AUTO", true},
		{"host ask → ASK", "ask", "", LevelHost, "ASK", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := newStore()
			if c.host != "" {
				_ = store.SetSetting("bedev", "browser", "gate", c.host)
			}
			if c.global != "" {
				_ = store.SetSetting("", "browser", "gate", c.global)
			}
			d := deps(store)
			d.Services = []service.Service{browserService{}}
			got := Loosening(find(t, d, "gate"), c.level, c.value)
			if (got != "") != c.wantLoosening {
				t.Errorf("Loosening = %q, want loosening %v", got, c.wantLoosening)
			}
		})
	}
}

// What Apply writes is the canonical form: "inherit" in any case clears the
// level, and an option is stored in its own spelling. Against the real store,
// so nothing between Apply and the file can turn it back into a literal.
func TestApplyWritesTheCanonicalValue(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	d := deps(store)
	d.Services = []service.Service{browserService{}, newGated("ssh-agent")}
	gate := find(t, d, "gate")

	if _, err := Apply(gate, LevelHost, "ASK", "bedev"); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", "browser", "gate"); got != "ask" {
		t.Errorf("ASK was stored as %q, want ask", got)
	}
	if _, err := Apply(gate, LevelHost, "Inherit", "bedev"); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", "browser", "gate"); got != "" {
		t.Errorf("inherit was stored as %q, want the key cleared", got)
	}
	if _, err := Apply(gate, LevelHost, "sometimes", "bedev"); err == nil {
		t.Error("a gate value that is neither ask nor auto was accepted")
	}
	unmatched := find(t, d, "unmatched.ssh-agent")
	if _, err := Apply(unmatched, LevelHost, "deny", "bedev"); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(unmatched, LevelHost, "INHERIT", "bedev"); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", "ssh-agent", "unmatched"); got != "" {
		t.Errorf("INHERIT was stored as %q, want the key cleared", got)
	}
}

// The classifier and the broker read the same files the same way. Each case
// is set up in real files, with the broker's own Unmatched read before and
// after the edit, and the edit must ask first exactly when the broker goes
// from refusing to asking.
func TestUnmatchedClassificationAgreesWithTheBroker(t *testing.T) {
	for _, c := range []struct {
		name         string
		host, global string // written to the files directly, as an old build might
		edit         string
		wantConfirm  bool
	}{
		// An "inherit" already in the file means inherit: with nothing
		// global that is the default ask, so ask changes nothing.
		{"existing host inherit, no global → ask", "inherit", "", "ask", false},
		// Under a global deny the broker refuses; an explicit ask loosens.
		{"existing host inherit, global deny → ask", "inherit", "deny", "ask", true},
		{"host deny → literal inherit under a global ask", "deny", "ask", "inherit", true},
		{"host deny → literal inherit under a global deny", "deny", "deny", "inherit", false},
		{"host deny → ASK", "deny", "", "ASK", true},
		{"host ask → DENY", "ask", "", "DENY", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := hostcfg.Open(t.TempDir())
			if c.host != "" {
				_ = store.SetSetting("bedev", "ssh-agent", "unmatched", c.host)
			}
			if c.global != "" {
				_ = store.SetSetting("", "ssh-agent", "unmatched", c.global)
			}
			gate := authz.NewGate(authz.Config{}, nil)
			if err := gate.Adopt("bedev", store.Section("bedev", "ssh-agent"), "SSH"); err != nil {
				t.Fatal(err)
			}
			d := deps(store)
			d.Services = []service.Service{gatedService{id: "ssh-agent", Surface: gate.Surface()}}
			row := find(t, d, "unmatched.ssh-agent")

			before := gate.Unmatched().Action
			confirm := Loosening(row, LevelHost, c.edit) != ""
			if _, err := Apply(row, LevelHost, c.edit, "bedev"); err != nil {
				t.Fatal(err)
			}
			after := gate.Unmatched().Action

			brokerLoosened := before == authz.ActionDeny && after != authz.ActionDeny
			if confirm != c.wantConfirm || confirm != brokerLoosened {
				t.Errorf("confirm = %v (want %v); the broker went %s → %s", confirm, c.wantConfirm, before, after)
			}
		})
	}
}

// The gate's classification agrees with what the browser does with the file,
// read through browser.GateAsks and the store's own levels.
func TestGateClassificationAgreesWithTheBrowser(t *testing.T) {
	asks := func(store *hostcfg.Store) bool {
		host, global := store.Setting("bedev", "browser", "gate"), store.Setting("", "browser", "gate")
		switch {
		case !Inherits(host):
			return browser.GateAsks(host)
		case !Inherits(global):
			return browser.GateAsks(global)
		}
		return false
	}
	for _, c := range []struct {
		name         string
		host, global string
		edit         string
		wantConfirm  bool
	}{
		{"host ask → ASK", "ask", "", "ASK", false},
		{"host ask → literal inherit under a global ask", "ask", "ask", "inherit", false},
		{"host ask → literal inherit, global silent", "ask", "", "inherit", true},
		{"host ask → Auto", "ask", "", "Auto", true},
		{"existing host ASK → auto", "ASK", "", "auto", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := hostcfg.Open(t.TempDir())
			if c.host != "" {
				_ = store.SetSetting("bedev", "browser", "gate", c.host)
			}
			if c.global != "" {
				_ = store.SetSetting("", "browser", "gate", c.global)
			}
			d := deps(store)
			d.Services = []service.Service{browserService{}}
			row := find(t, d, "gate")
			before := asks(store)
			confirm := Loosening(row, LevelHost, c.edit) != ""
			if _, err := Apply(row, LevelHost, c.edit, "bedev"); err != nil {
				t.Fatal(err)
			}
			after := asks(store)
			if confirm != c.wantConfirm || confirm != (before && !after) {
				t.Errorf("confirm = %v (want %v); the browser went asks=%v → asks=%v", confirm, c.wantConfirm, before, after)
			}
		})
	}
}
