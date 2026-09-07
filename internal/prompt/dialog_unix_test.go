//go:build linux || freebsd || openbsd || netbsd || dragonfly

package prompt

import (
	"os"
	"strings"
	"testing"
)

// zenity prints the row's columns joined by a separator, and yad appends a
// trailing one. Either way the answer is the first column, and a label that
// arrived with decoration attached would match nothing and fail closed.
func TestZenityTakesTheFirstColumn(t *testing.T) {
	fakeProgram(t, "devtun-fake-zenity", `printf 'Yes, once|\n'`)
	got, err := zenityChooser{bin: "devtun-fake-zenity"}.ask(t.Context(), "t", "p", []string{"Yes, once"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if got != "Yes, once" {
		t.Errorf("answer = %q", got)
	}
}

// The labels are passed as rows, in the menu's order, so the first is the one
// under the cursor — the narrowest answer, which is the point of that order.
func TestZenityPassesTheLabelsAsRows(t *testing.T) {
	fakeProgram(t, "devtun-fake-args", `for a in "$@"; do echo "$a"; done | tail -n 2 | head -n 1`)
	got, err := zenityChooser{bin: "devtun-fake-args"}.ask(t.Context(), "t", "p", []string{"first", "second"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if got != "first" {
		t.Errorf("the labels are not the trailing arguments, in order: got %q", got)
	}
}

// kdialog prints the tag, not the text. The tags are indices, so a label
// containing anything at all — a vault path, a quote — cannot be mistaken for
// one.
func TestKdialogMapsTheTagBackToTheLabel(t *testing.T) {
	fakeProgram(t, "kdialog", `echo 1`)
	got, err := kdialogChooser{}.ask(t.Context(), "t", "p", []string{"Yes, once", "Yes, this session"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if got != "Yes, this session" {
		t.Errorf("tag 1 mapped to %q", got)
	}
}

// A tag we did not offer is not an answer, and must not be turned into one.
func TestKdialogRejectsATagItWasNotOffered(t *testing.T) {
	fakeProgram(t, "kdialog", `echo 9`)
	got, err := kdialogChooser{}.ask(t.Context(), "t", "p", []string{"Yes, once"})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if got == "Yes, once" {
		t.Error("an out-of-range tag was mapped to a real answer")
	}
}

// A box reached over SSH has the programs installed and no screen to draw on.
// Checking first is what keeps the terminal prompt instant there.
func TestUnixChoosersNeedADisplay(t *testing.T) {
	old := lookPath
	t.Cleanup(func() { lookPath = old })
	lookPath = func(string) (string, error) { return "/usr/bin/anything", nil }

	os.Unsetenv("WAYLAND_DISPLAY")
	t.Setenv("DISPLAY", "")
	if pickChooser() != nil {
		t.Error("a chooser was picked with no display")
	}
	t.Setenv("DISPLAY", ":0")
	if pickChooser() == nil {
		t.Error("no chooser was picked with a display and every program installed")
	}
}

// The first pick is zenity, which is the one most likely to be installed and to
// look like the rest of the desktop.
func TestZenityIsPreferred(t *testing.T) {
	names := chooserNames()
	if len(names) == 0 || names[0] != "zenity" {
		t.Errorf("chooser order = %v, want zenity first", names)
	}
	if !strings.Contains(strings.Join(names, ","), "kdialog") {
		t.Errorf("kdialog is not among the choosers: %v", names)
	}
}
