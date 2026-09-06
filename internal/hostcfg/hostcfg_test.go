package hostcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	no := false
	store.global.Services = map[string]ServiceState{"tunnels": {Enabled: &no}}
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
