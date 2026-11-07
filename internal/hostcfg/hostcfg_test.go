package hostcfg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type portEntry struct {
	Label string `yaml:"label,omitempty"`
	Mode  string `yaml:"mode,omitempty"`
}

func TestSectionRoundTripsThroughDisk(t *testing.T) {
	dir := t.TempDir()

	store := Open(dir)
	ports := map[int]portEntry{3000: {Label: "frontend"}, 5432: {Mode: "hidden"}}
	if err := store.For("bedev", "tunnels").Set("ports", ports); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reopened := Open(dir)
	var got map[int]portEntry
	found, err := reopened.For("bedev", "tunnels").Get("ports", &got)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("the port table did not survive a save and reopen")
	}
	if got[3000].Label != "frontend" || got[5432].Mode != "hidden" {
		t.Errorf("wrong values back: %+v", got)
	}
}

func TestMissingKeyReportsNotFoundWithoutTouchingTheTarget(t *testing.T) {
	store := Open(t.TempDir())
	got := map[int]portEntry{1: {Label: "untouched"}}

	found, err := store.For("bedev", "tunnels").Get("ports", &got)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Error("want not-found for a key never set")
	}
	if got[1].Label != "untouched" {
		t.Error("a missing key must leave the destination alone")
	}
}

// A rule written once globally should be visible to every host without being
// copied into each file — that is the point of having two layers.
func TestHostReadsFallThroughToGlobal(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)

	if err := store.GlobalFor("1password").Set("rules", []string{"deny op://Private/**"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var got []string
	found, err := store.For("bedev", "1password").Get("rules", &got)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found || len(got) != 1 {
		t.Fatalf("want the global rule visible from the host view, got found=%v %v", found, got)
	}
}

func TestHostValueWinsOverGlobal(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.GlobalFor("tunnels").Set("ports", map[int]portEntry{80: {Label: "global"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{80: {Label: "host"}}); err != nil {
		t.Fatal(err)
	}

	var got map[int]portEntry
	if _, err := store.For("bedev", "tunnels").Get("ports", &got); err != nil {
		t.Fatal(err)
	}
	if got[80].Label != "host" {
		t.Errorf("the host file must win; got %q", got[80].Label)
	}
}

func TestEnabledPrefersHostThenGlobalThenFallback(t *testing.T) {
	store := Open(t.TempDir())

	if !store.Enabled("bedev", "tunnels", true) {
		t.Error("with nothing configured, the fallback should win")
	}

	if err := store.SetSetting("", SectionServices, "tunnels", "false"); err != nil {
		t.Fatal(err)
	}
	if store.Enabled("bedev", "tunnels", true) {
		t.Error("a global default should beat the fallback")
	}

	store.SetEnabled("bedev", "tunnels", true)
	if !store.Enabled("bedev", "tunnels", false) {
		t.Error("the host answer should beat the global default")
	}
}

// Refusing to start because a settings file has a stray tab in it is the wrong
// trade for a tool whose job is to get you connected.
func TestMalformedFileDegradesToEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("\tnot: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts", "bedev.yaml"), []byte("also: [broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := Open(dir)
	if !store.Enabled("bedev", "tunnels", true) {
		t.Error("a malformed file should read as empty, not as a refusal")
	}

	// But it must not read as empty *silently*. A file that was meant to say
	// "never this vault from this box" and instead says nothing has failed
	// open, and a caller about to act on rules has to be able to find out.
	if store.Err() == nil {
		t.Error("a file that would not parse must be reported")
	}
}

func TestErrIsNilForReadableConfiguration(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	store.SetEnabled("bedev", "tunnels", true)
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	if err := Open(dir).Err(); err != nil {
		t.Errorf("a well-formed configuration should report no error, got %v", err)
	}
}

// The host file is only read on first use, so its parse error has to survive
// until somebody asks — not be lost because Err() was called too early.
func TestHostParseErrorSurfacesAfterTheHostIsTouched(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts", "bedev.yaml"), []byte("rules: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := Open(dir)
	_ = store.Enabled("bedev", "1password", true) // this is what loads the file

	if store.Err() == nil {
		t.Error("the host file's parse error was lost")
	}
}

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	store.SetEnabled("bedev", "tunnels", true)
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "hosts", "bedev.yaml"))
	if err != nil {
		t.Fatalf("the host file was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("want mode 0600, got %o", perm)
	}

	// No temporary files should be left behind.
	entries, err := os.ReadDir(filepath.Join(dir, "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("want exactly the host file, got %d entries", len(entries))
	}
}

func TestSaveIsANoOpWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(err) {
		t.Error("saving a clean store should not create files")
	}
}

// A label can arrive as user@host:port, which must not escape the directory.
func TestLabelsAreSanitisedIntoFilenames(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	store.SetEnabled("../../etc/passwd", "tunnels", true)
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "hosts"))
	if err != nil {
		t.Fatalf("nothing was written inside the hosts directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want one file, got %d", len(entries))
	}
	// The exact spelling does not matter; that nothing escapes the directory
	// does. Assert the property rather than the substitution.
	name := entries[0].Name()
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		t.Errorf("sanitised name %q can still traverse", name)
	}
}

func TestMemoryOnlyStoreWorksAndWritesNothing(t *testing.T) {
	store := Open("")
	store.SetEnabled("bedev", "tunnels", true)
	if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{1: {}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Errorf("saving a memory-only store should be a silent no-op, got %v", err)
	}
	if store.Path() != "" {
		t.Error("a memory-only store should report no path")
	}
}

// The fall-through is right for settings and wrong for anything the caller
// writes back: 1Password read the global rules through Get, then "allow always"
// wrote the whole slice into the host file — so deleting a global rule left a
// copy behind, still granting access from a file nobody thought to look in.
func TestGetLocalDoesNotInheritFromGlobal(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.GlobalFor("1password").Set("rules", []string{"deny op://Private/**"}); err != nil {
		t.Fatal(err)
	}

	var viaGet, viaLocal []string
	if found, _ := store.For("bedev", "1password").Get("rules", &viaGet); !found {
		t.Error("Get should still inherit the global rule")
	}
	found, err := store.For("bedev", "1password").GetLocal("rules", &viaLocal)
	if err != nil {
		t.Fatalf("GetLocal: %v", err)
	}
	if found || len(viaLocal) != 0 {
		t.Errorf("GetLocal must not inherit, got found=%v %v", found, viaLocal)
	}

	// A host's own value is still returned.
	if err := store.For("bedev", "1password").Set("rules", []string{"allow op://Work/**"}); err != nil {
		t.Fatal(err)
	}
	viaLocal = nil
	if found, _ := store.For("bedev", "1password").GetLocal("rules", &viaLocal); !found || len(viaLocal) != 1 {
		t.Errorf("GetLocal should return the host's own rules, got %v", viaLocal)
	}
}

// A box that binds services to port 0 gets whatever the kernel hands out, so
// the noisy ports differ every restart and cannot be hidden one at a time. The
// config has to be able to say what a person actually means.
func TestHideAcceptsPortsRangesAndMixtures(t *testing.T) {
	tests := map[string]string{
		"hide: 5432":                         "5432",
		"hide: [5432, 6379]":                 "5432,6379",
		`hide: "32768-60999"`:                "32768-60999",
		`hide: [5432, "32768-60999"]`:        "5432,32768-60999",
		`hide: ["5432,6379", "32768-60999"]`: "5432,6379,32768-60999",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			var g Global
			if err := yaml.Unmarshal([]byte(input), &g); err != nil {
				t.Fatalf("unmarshalling %q: %v", input, err)
			}
			if got := g.Hide.Spec(); got != want {
				t.Errorf("Spec() = %q, want %q", got, want)
			}
		})
	}
}

// A malformed hide list should say so rather than being silently empty: an
// empty hide list forwards everything, which is the wrong direction to fail in.
func TestAMalformedHideListIsReported(t *testing.T) {
	var g Global
	err := yaml.Unmarshal([]byte("hide:\n  key: value\n"), &g)
	if err == nil {
		t.Fatal("a mapping is not a hide list and should be refused")
	}
}

func TestAnAbsentHideListIsEmpty(t *testing.T) {
	var g Global
	if err := yaml.Unmarshal([]byte("setup: ask\n"), &g); err != nil {
		t.Fatal(err)
	}
	if got := g.Hide.Spec(); got != "" {
		t.Errorf("Spec() = %q, want empty", got)
	}
}

// The settings screen has to be able to tell "this host says tui" from "the
// global file says tui", which the resolving readers cannot: Prompt collapses
// both into one answer on purpose.
func TestSettingReadsOneLevelAtATime(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.SetSetting("", "", KeyPrompt, "dialog"); err != nil {
		t.Fatalf("SetSetting global: %v", err)
	}

	if got := store.Setting("bedev", "", KeyPrompt); got != "" {
		t.Errorf("the host reports %q for a setting only the global file has", got)
	}
	if got := store.Setting("", "", KeyPrompt); got != "dialog" {
		t.Errorf("the global file reports %q, want dialog", got)
	}
	if got := store.Prompt("bedev", "auto"); got != "dialog" {
		t.Errorf("resolving reports %q, want the global answer", got)
	}

	// A host's own answer must not touch the global one, or setting one box's
	// preference would quietly change every other box's.
	if err := store.SetSetting("bedev", "", KeyPrompt, "tui"); err != nil {
		t.Fatalf("SetSetting host: %v", err)
	}
	if got := store.Setting("", "", KeyPrompt); got != "dialog" {
		t.Errorf("writing the host rewrote the global setting to %q", got)
	}
	if got := store.Prompt("bedev", "auto"); got != "tui" {
		t.Errorf("resolving reports %q, want the host's answer", got)
	}
}

// Clearing a level has to remove the key, not write a blank one: a host with no
// prompt setting is a host that has stopped having an opinion, and it must fall
// back to the global file rather than pin what it happened to be showing.
func TestClearingAHostSettingFallsBackToGlobal(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if err := store.SetSetting("", "", KeyPrompt, "dialog"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("bedev", "", KeyPrompt, "tui"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("bedev", "", KeyPrompt, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reopened := Open(dir)
	if got := reopened.Setting("bedev", "", KeyPrompt); got != "" {
		t.Errorf("the host file still says %q after being cleared", got)
	}
	if got := reopened.Prompt("bedev", "auto"); got != "dialog" {
		t.Errorf("a cleared host resolves to %q, want the global answer", got)
	}
}

// A service's own section is free-form, so it is reached through the same two
// calls — and a hide list somebody hand-wrote as a sequence has to read back as
// something they can edit and hand in again.
func TestSectionSettingsReadAndClearAtOneLevel(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.For("bedev", "tunnels").Set(KeyHide, []string{"5432", "32768-60999"}); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", "tunnels", KeyHide); got != "5432,32768-60999" {
		t.Errorf("the host's hide list reads as %q", got)
	}
	if got := store.Setting("", "tunnels", KeyHide); got != "" {
		t.Errorf("the global file reports %q for a host's own list", got)
	}

	if err := store.SetSetting("bedev", "tunnels", KeyHide, "6379"); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", "tunnels", KeyHide); got != "6379" {
		t.Errorf("after an edit the list reads as %q", got)
	}
	if err := store.SetSetting("bedev", "tunnels", KeyHide, ""); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", "tunnels", KeyHide); got != "" {
		t.Errorf("a cleared list still reads as %q", got)
	}
}

// Whether a service runs is the same kind of three-answer setting, and absent
// has to stay distinguishable from an explicit off.
func TestServiceStateIsReadableAndClearablePerLevel(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.SetSetting("", SectionServices, "gpg-agent", "true"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("bedev", SectionServices, "gpg-agent", "false"); err != nil {
		t.Fatal(err)
	}

	if got := store.Setting("", SectionServices, "gpg-agent"); got != "true" {
		t.Errorf("the global file reports %q", got)
	}
	if got := store.Setting("bedev", SectionServices, "gpg-agent"); got != "false" {
		t.Errorf("the host file reports %q", got)
	}
	if store.Enabled("bedev", "gpg-agent", true) {
		t.Error("the host's explicit off should win")
	}

	if err := store.SetSetting("bedev", SectionServices, "gpg-agent", ""); err != nil {
		t.Fatal(err)
	}
	if got := store.Setting("bedev", SectionServices, "gpg-agent"); got != "" {
		t.Errorf("a cleared service state reads as %q, want unset", got)
	}
	if !store.Enabled("bedev", "gpg-agent", false) {
		t.Error("with the host cleared the global answer should win")
	}
}

// The host file carries one of the top-level settings and not the others.
// Writing a global-only one to a host would leave a key nothing ever reads.
func TestAGlobalOnlySettingIsRefusedOnAHost(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.SetSetting("bedev", "", KeySetup, "never"); err == nil {
		t.Fatal("a host accepted a global-only setting")
	}
	if err := store.SetSetting("", "", "nonsense", "x"); err == nil {
		t.Fatal("the global file accepted a setting that does not exist")
	}
}

// A decision the interface calls "remembered" has to survive a kill.
//
// Writes used to mark the file dirty and wait for a clean exit, so a `Never`
// deny rule written at ten in the morning was still only in memory at six —
// and a session killed rather than quit lost it. A refusal the user believes
// is protecting them is exactly the thing that must not depend on a tidy
// shutdown.
func TestAWriteIsOnDiskBeforeItIsAcknowledged(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)

	if err := store.Section("bedev", "1password").Set("rules", []map[string]string{
		{"host": "bedev", "subject": "op://Private/**", "action": "deny"},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Read it with a second store that has never seen the first — the same
	// thing a fresh process does after the old one was killed.
	var back []map[string]string
	fresh := Open(dir)
	ok, err := fresh.Section("bedev", "1password").GetLocal("rules", &back)
	if err != nil || !ok {
		t.Fatalf("the rule was not on disk: ok=%v err=%v", ok, err)
	}
	if len(back) != 1 || back[0]["action"] != "deny" {
		t.Errorf("what landed on disk was %+v", back)
	}
}

// Service toggles are the same promise, made by a different screen.
func TestAServiceToggleIsOnDiskImmediately(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	store.SetEnabled("bedev", "gpg-agent", true)

	if !Open(dir).Enabled("bedev", "gpg-agent", false) {
		t.Error("a service switched on was not written before the process could die")
	}
}

// writeFile stands in for a person with an editor.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The bug this package was rewritten for. The store held the host file it read
// at startup and wrote that copy back, whole, on the next change — so a deny
// rule typed in while devtun ran was erased by naming a port, comments and all,
// in a file whose header said it was safe to edit by hand.
func TestAHandEditMadeWhileRunningSurvivesTheNextWrite(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{3000: {Label: "web"}}); err != nil {
		t.Fatal(err)
	}

	path := store.HostPath("bedev")
	edited := readFile(t, path) + `1password:
    # never the root keys, whatever I click
    rules:
        - subject: op://Private/Root Keys/**
          action: deny
`
	writeFile(t, path, edited)

	if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{3000: {Label: "frontend"}}); err != nil {
		t.Fatal(err)
	}

	after := readFile(t, path)
	for _, want := range []string{"op://Private/Root Keys/**", "# never the root keys, whatever I click", "frontend"} {
		if !strings.Contains(after, want) {
			t.Errorf("after devtun's write the file lost %q:\n%s", want, after)
		}
	}
}

// An edit that survives but is not noticed until a restart is half a fix.
func TestAHandEditIsReadWithoutReopening(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	store.LoadHost("bedev")

	writeFile(t, store.HostPath("bedev"), "1password:\n  unmatched: deny\n")
	before := store.Revision()

	var got string
	if ok, err := store.For("bedev", "1password").GetLocal("unmatched", &got); !ok || err != nil || got != "deny" {
		t.Fatalf("the edit was not picked up: ok=%v err=%v got=%q", ok, err, got)
	}
	writeFile(t, store.HostPath("bedev"), "1password:\n  unmatched: ask # changed my mind\n")
	if store.Revision() == before {
		t.Error("an edit on disk did not move the revision, so nothing showing it can know to reload")
	}
}

// Two sessions for different hosts share the global file. Each used to write
// back its own startup copy, so one session's restriction was deleted by the
// other's unrelated preference.
func TestTwoProcessesWritingOneFileKeepBothChanges(t *testing.T) {
	dir := t.TempDir()
	a, b := Open(dir), Open(dir) // both loaded before either writes

	if err := a.GlobalFor("1password").Set("rules", []map[string]string{
		{"subject": "op://Private/**", "action": "deny"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.SetSetting("", "", KeyPrompt, "tui"); err != nil {
		t.Fatal(err)
	}

	fresh := Open(dir)
	var rules []map[string]string
	if ok, _ := fresh.GlobalFor("1password").Get("rules", &rules); !ok || len(rules) != 1 {
		t.Errorf("the deny written by one process was lost to the other's write: %+v", rules)
	}
	if got := fresh.Setting("", "", KeyPrompt); got != "tui" {
		t.Errorf("prompt = %q, want tui", got)
	}
}

// A file that exists but cannot be read is not an empty file. Treating it as
// one is how a deny rule silently stops applying.
func TestAnUnreadableFileIsAnErrorNotAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	// A directory where the host file belongs: unreadable on every platform,
	// and for the root user too, which a chmod would not be.
	if err := os.MkdirAll(filepath.Join(dir, "hosts", "bedev.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	store := Open(dir)
	store.LoadHost("bedev")
	if store.Err() == nil {
		t.Fatal("an unreadable host file was reported as fine")
	}
	if store.HostErr("bedev") == nil {
		t.Fatal("HostErr missed the unreadable host file")
	}
	if err := store.For("bedev", "1password").Set("rules", []string{}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a write over an unreadable file should be refused with ErrUnreadable, got %v", err)
	}
}

// A file broken by a hand edit mid-session is reported, keeps its last good
// contents for presentation, and is never overwritten with them.
func TestAFileBrokenWhileRunningIsReportedAndNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{3000: {Label: "web"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Err(); err != nil {
		t.Fatalf("clean file reported %v", err)
	}

	broken := "tunnels: [unclosed\n# half-typed deny rule\n"
	writeFile(t, store.HostPath("bedev"), broken)

	if store.For("bedev", "tunnels").Err() == nil {
		t.Error("the section did not report its broken file")
	}
	if store.Err() == nil {
		t.Error("the store did not report its broken file")
	}
	var ports map[int]portEntry
	if ok, _ := store.For("bedev", "tunnels").Get("ports", &ports); !ok || ports[3000].Label != "web" {
		t.Errorf("presentation should keep the last good contents, got %+v", ports)
	}
	if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("want ErrUnreadable, got %v", err)
	}
	if got := readFile(t, store.HostPath("bedev")); got != broken {
		t.Errorf("the broken file was overwritten:\n%s", got)
	}

	writeFile(t, store.HostPath("bedev"), "tunnels: {}\n")
	if err := store.Err(); err != nil {
		t.Errorf("a fixed file is still reported: %v", err)
	}
}

// A lock held by a live writer must keep excluding others however old the
// lock file looks. The earlier lock treated any lock older than ten seconds as
// abandoned, so a writer paused that long had its lock stolen and then wrote
// its stale document over the thief's deny.
func TestALiveLockExcludesOtherWritersHoweverOld(t *testing.T) {
	dir := t.TempDir()
	release, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ".devtun.lock")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- Open(dir).SetSetting("", "", KeyPrompt, "tui") }()
	select {
	case err := <-done:
		t.Fatalf("a write went ahead while another writer held the lock (err=%v)", err)
	case <-time.After(150 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("the write failed once the lock was free: %v", err)
	}
}

// A writer that cannot get the lock in time gives up rather than writing.
func TestAWriterThatCannotGetTheLockGivesUp(t *testing.T) {
	dir := t.TempDir()
	saved := lockWait
	lockWait = 50 * time.Millisecond
	t.Cleanup(func() { lockWait = saved })
	release, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := Open(dir).SetSetting("", "", KeyPrompt, "tui"); err == nil {
		t.Fatal("a write succeeded without the lock")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(err) {
		t.Error("the file was written anyway")
	}
}

// A person saving the file between devtun's read and its write must not be
// overwritten. The edit callback is the barrier: it runs after the read and
// before the write, which is exactly where an editor's save would land.
func TestAHandEditDuringATransactionIsKept(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if err := store.For("bedev", "1password").Set("unmatched", "ask"); err != nil {
		t.Fatal(err)
	}
	path := store.HostPath("bedev")

	var once bool
	err := store.For("bedev", "tunnels").EditNode("ports", func(*yaml.Node) (*yaml.Node, error) {
		if !once {
			once = true
			edited := strings.Replace(readFile(t, path), "unmatched: ask", "unmatched: deny # tightened by hand", 1)
			writeFile(t, path, edited)
		}
		n, err := toNode(map[int]portEntry{3000: {Label: "web"}})
		return &n, err
	})
	if err != nil {
		t.Fatalf("EditNode: %v", err)
	}
	after := readFile(t, path)
	if !strings.Contains(after, "unmatched: deny") || !strings.Contains(after, "web") {
		t.Errorf("want the hand edit and devtun's change both:\n%s", after)
	}
}

// A file that changes on every attempt is a conflict, not a stale write.
func TestAFileThatKeepsChangingIsAConflict(t *testing.T) {
	dir := t.TempDir()
	store := Open(dir)
	if err := store.For("bedev", "1password").Set("unmatched", "ask"); err != nil {
		t.Fatal(err)
	}
	path := store.HostPath("bedev")
	n := 0
	err := store.For("bedev", "tunnels").EditNode("ports", func(*yaml.Node) (*yaml.Node, error) {
		n++
		writeFile(t, path, "1password:\n  unmatched: deny\n# edit "+strings.Repeat("x", n)+"\n")
		return scalarNode("x"), nil
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if strings.Contains(readFile(t, path), "tunnels") {
		t.Error("devtun's change was written over a file that kept changing")
	}
}

// Ambiguous YAML must not be read as whichever half a tree walk happens to
// see. Each of these, read naively, drops a deny.
func TestAmbiguousYAMLIsRefusedNotGuessed(t *testing.T) {
	cases := map[string]string{
		"duplicate section": "1password:\n  rules: [{subject: '**', action: deny}]\n1password:\n  rules: [{subject: '**', action: allow}]\n",
		"duplicate key":     "1password:\n  rules: [{subject: '**', action: deny}]\n  rules: [{subject: '**', action: allow}]\n",
		"alias":             "policy: &p\n  rules: [{subject: '**', action: deny}]\n1password: *p\n",
		"merge key":         "policy: &p\n  rules: [{subject: '**', action: deny}]\n1password:\n  <<: *p\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store := Open(dir)
			writeFile(t, store.HostPath("bedev"), content)
			if store.HostErr("bedev") == nil {
				t.Error("the file was accepted")
			}
			if err := store.For("bedev", "1password").Err(); err == nil {
				t.Error("the section did not report its file")
			}
			if err := store.For("bedev", "tunnels").Set("ports", map[int]portEntry{}); !errors.Is(err, ErrUnreadable) {
				t.Errorf("a write was not refused: %v", err)
			}
			if got := readFile(t, store.HostPath("bedev")); got != content {
				t.Errorf("the file was rewritten:\n%s", got)
			}
		})
	}
}

// A service section that is there but is not a map is unreadable policy, not
// absent policy — and an edit must not replace it.
func TestASectionOfTheWrongShapeIsAnError(t *testing.T) {
	store := Open(t.TempDir())
	writeFile(t, store.HostPath("bedev"), "1password: wrong\n")
	var rules []map[string]string
	if _, err := store.For("bedev", "1password").GetLocal("rules", &rules); err == nil {
		t.Error("GetLocal read a scalar section as empty")
	}
	if _, err := store.For("bedev", "1password").Get("rules", &rules); err == nil {
		t.Error("Get read a scalar section as empty")
	}
	if err := store.For("bedev", "1password").Set("rules", []string{}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("an edit replaced a scalar section: %v", err)
	}
	// A blank section is null and means nothing is set.
	writeFile(t, store.HostPath("bedev"), "1password:\n")
	if _, err := store.For("bedev", "1password").GetLocal("rules", &rules); err != nil {
		t.Errorf("a blank section should read as empty: %v", err)
	}
}

func TestGetGlobalIgnoresTheHostFile(t *testing.T) {
	store := Open(t.TempDir())
	if err := store.GlobalFor("1password").Set("unmatched", "deny"); err != nil {
		t.Fatal(err)
	}
	if err := store.For("bedev", "1password").Set("unmatched", "ask"); err != nil {
		t.Fatal(err)
	}
	var global string
	if ok, err := store.For("bedev", "1password").GetGlobal("unmatched", &global); !ok || err != nil || global != "deny" {
		t.Errorf("GetGlobal = %q ok=%v err=%v", global, ok, err)
	}
}
