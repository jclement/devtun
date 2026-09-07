package prompt

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeChooser stands in for a dialog program, so the shared half of the dialog
// — what it asks for, what it does with the answer — is testable on any
// machine, including one with no desktop at all.
type fakeChooser struct {
	answer string
	err    error

	title  string
	prompt string
	labels []string
}

func (f *fakeChooser) name() string    { return "fake" }
func (f *fakeChooser) available() bool { return true }

func (f *fakeChooser) ask(_ context.Context, title, prompt string, labels []string) (string, error) {
	f.title, f.prompt, f.labels = title, prompt, labels
	return f.answer, f.err
}

func testRequest() Request {
	return Request{Host: "bedev", Subject: "op://Personal/Docker/PAT", TTL: 5 * time.Minute}
}

func TestDialogMapsTheAnswerBackToAChoice(t *testing.T) {
	labels, choices := dialogOptions(testRequest())
	for i, label := range labels {
		fake := &fakeChooser{answer: label}
		got, err := (&Dialog{chooser: fake}).Ask(t.Context(), testRequest())
		if err != nil {
			t.Fatalf("%q: %v", label, err)
		}
		if got != choices[i] {
			t.Errorf("%q gave %v, want %v", label, got, choices[i])
		}
	}
}

// Every way of dismissing the dialog is a refusal, and so is an answer that is
// not one of the options — a garbled reply is not consent.
func TestDialogFailsClosed(t *testing.T) {
	for _, answer := range []string{denySentinel, "", "   ", "Yes, obviously"} {
		got, _ := (&Dialog{chooser: &fakeChooser{answer: answer}}).Ask(t.Context(), testRequest())
		if got != ChoiceDeny {
			t.Errorf("answer %q gave %v, want deny", answer, got)
		}
	}
}

// A dialog that cannot be drawn must not become a refusal when there is a
// terminal that could have asked. It also must not become an approval.
func TestDialogFallsBackWhenItCannotBeShown(t *testing.T) {
	asked := false
	fallback := PrompterFunc(func(context.Context, Request) (Choice, error) {
		asked = true
		return ChoiceAllowOnce, nil
	})

	d := &Dialog{chooser: &fakeChooser{err: errors.New("no display")}, fallback: fallback}
	got, err := d.Ask(t.Context(), testRequest())
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if !asked || got != ChoiceAllowOnce {
		t.Errorf("the fallback was not asked (asked=%v, choice=%v)", asked, got)
	}

	// With nowhere to fall back to, the failure is reported rather than
	// swallowed as a denial nobody made.
	if _, err := (&Dialog{chooser: &fakeChooser{err: errors.New("no display")}}).Ask(t.Context(), testRequest()); err == nil {
		t.Error("a dialog that could not be shown reported success")
	}
}

// A cancelled prompt is an answer, not a failure: falling back would ask the
// same question again in the terminal, and "no" would become "no, then maybe".
func TestACancelledDialogIsNotAFallback(t *testing.T) {
	asked := false
	fallback := PrompterFunc(func(context.Context, Request) (Choice, error) {
		asked = true
		return ChoiceAllowOnce, nil
	})
	got, err := (&Dialog{chooser: &fakeChooser{answer: denySentinel}, fallback: fallback}).Ask(t.Context(), testRequest())
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if asked {
		t.Error("cancelling the dialog re-asked in the terminal")
	}
	if got != ChoiceDeny {
		t.Errorf("cancelling gave %v, want deny", got)
	}
}

// The window says what is being asked for. A dialog titled 1Password while
// asking about an SSH key is worse than one with no title.
func TestDialogTitleFollowsTheSubject(t *testing.T) {
	if got := dialogTitle(Request{}); !strings.Contains(got, "1Password") {
		t.Errorf("a secret request is titled %q", got)
	}
	if got := dialogTitle(Request{Noun: "key"}); !strings.Contains(got, "SSH agent") {
		t.Errorf("a signature request is titled %q", got)
	}
}

// --- the helper programs ---------------------------------------------------

// fakeProgram writes a shell script that behaves like a dialog helper, and puts
// it on PATH under the given name. It is how the exec half of a chooser is
// tested without a desktop.
func fakeProgram(t *testing.T, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake helpers are shell scripts")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("writing the fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

// A helper that exits 1 having printed nothing has been cancelled, which is how
// zenity, kdialog and yad all say "the person clicked Deny".
func TestRunChooserReadsACancelAsARefusal(t *testing.T) {
	fakeProgram(t, "devtun-fake-cancel", "exit 1")
	got, err := runChooser(t.Context(), "devtun-fake-cancel")
	if err != nil {
		t.Fatalf("runChooser: %v", err)
	}
	if got != denySentinel {
		t.Errorf("a cancelled helper gave %q, want the deny sentinel", got)
	}
}

// Any other failure is a helper that could not run, which is a different thing
// and has to reach the fallback.
func TestRunChooserReportsAHelperThatCouldNotRun(t *testing.T) {
	fakeProgram(t, "devtun-fake-broken", "echo 'cannot open display' >&2; exit 3")
	if _, err := runChooser(t.Context(), "devtun-fake-broken"); err == nil {
		t.Error("a helper that failed reported success")
	}
	if _, err := runChooser(t.Context(), "devtun-fake-absent-entirely"); err == nil {
		t.Error("a helper that does not exist reported success")
	}
}

func TestRunChooserTrimsTheAnswer(t *testing.T) {
	fakeProgram(t, "devtun-fake-answer", `printf 'Yes, once\n'`)
	got, err := runChooser(t.Context(), "devtun-fake-answer")
	if err != nil {
		t.Fatalf("runChooser: %v", err)
	}
	if got != "Yes, once" {
		t.Errorf("answer = %q", got)
	}
}

// lookPath is indirected so availability can be tested without installing
// anything. This proves the indirection is the one the choosers use.
func TestHaveProgramUsesTheLookPathSeam(t *testing.T) {
	old := lookPath
	t.Cleanup(func() { lookPath = old })

	lookPath = func(name string) (string, error) {
		if name == "zenity" {
			return "/usr/bin/zenity", nil
		}
		return "", exec.ErrNotFound
	}
	if !haveProgram("zenity") {
		t.Error("zenity was reported missing")
	}
	if haveProgram("kdialog") {
		t.Error("kdialog was reported present")
	}
}

// Every platform must offer at least a name to put in the "install one of
// these" error, or that error tells the user nothing.
func TestChooserNamesAreNeverEmpty(t *testing.T) {
	if len(ChooserNames()) == 0 {
		t.Fatal("chooserNames returned nothing")
	}
	for _, name := range ChooserNames() {
		if strings.TrimSpace(name) == "" {
			t.Error("a chooser has no name")
		}
	}
}
