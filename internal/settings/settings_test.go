package settings

import (
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/hostcfg"
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
	if value != "auto" {
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
