package session

import (
	"context"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/service"
)

// fakeRemote answers the setup code's shell probes from a script.
type fakeRemote struct {
	replies []string
	scripts []string
	err     error
}

func (f *fakeRemote) Output(_ context.Context, script string) (string, error) {
	f.scripts = append(f.scripts, script)
	if f.err != nil {
		return "", f.err
	}
	if len(f.replies) == 0 {
		return "", nil
	}
	reply := f.replies[0]
	f.replies = f.replies[1:]
	return reply, nil
}

func TestPlanRCPerShell(t *testing.T) {
	tests := []struct {
		shell    string
		wantFile string
		wantLine string
	}{
		{"/bin/zsh", "/home/jsc/.zshrc", `export PATH="/home/jsc/.devtun/bin:$PATH"`},
		{"/bin/bash", "/home/jsc/.bashrc", `export PATH="/home/jsc/.devtun/bin:$PATH"`},
		{"/usr/bin/fish", "/home/jsc/.config/fish/config.fish", "fish_add_path /home/jsc/.devtun/bin"},
	}
	for _, tc := range tests {
		t.Run(tc.shell, func(t *testing.T) {
			plan := planRC(service.Facts{Home: "/home/jsc", Shell: tc.shell}, "/home/jsc/.devtun/bin")
			if plan.File != tc.wantFile {
				t.Errorf("want file %q, got %q", tc.wantFile, plan.File)
			}
			if len(plan.Lines) != 1 || plan.Lines[0] != tc.wantLine {
				t.Errorf("want line %q, got %v", tc.wantLine, plan.Lines)
			}
			if !plan.Writable {
				t.Error("a recognised shell should be writable")
			}
		})
	}
}

// bash reads .bashrc, not .bash_profile, for the interactive non-login shell
// that `ssh host` and anything herdr starts actually get.
func TestBashTargetsBashrcNotProfile(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/bash"}, "/home/jsc/.devtun/bin")
	if strings.Contains(plan.File, "profile") {
		t.Errorf("bash should get .bashrc, got %q", plan.File)
	}
}

// fish is not POSIX and `export` is a syntax error in it. Getting this wrong
// means an error on every single prompt, so it is worth its own test.
func TestFishNeverEmitsExport(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/usr/bin/fish"}, "/home/jsc/.devtun/bin")
	for _, line := range plan.Lines {
		if strings.HasPrefix(line, "export ") {
			t.Errorf("fish must not be given POSIX export syntax: %q", line)
		}
	}
}

// Guessing the file for an unknown shell is how you append bash syntax to a
// csh rc. Advice, not an edit.
func TestUnknownShellGetsAdviceNotAnEdit(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/tcsh"}, "/home/jsc/.devtun/bin")
	if plan.Writable {
		t.Error("an unrecognised shell must not be edited")
	}
	if plan.File != "" {
		t.Errorf("no file should be chosen, got %q", plan.File)
	}
	if len(plan.Lines) == 0 {
		t.Error("the user should still be told what to add")
	}
	if plan.Why == "" {
		t.Error("the refusal should explain itself")
	}
}

func TestBlockIsDelimitedByMarkers(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/zsh"}, "/home/jsc/.devtun/bin")
	if !strings.HasPrefix(plan.Block, setupMarkerStart) || !strings.HasSuffix(plan.Block, setupMarkerEnd) {
		t.Errorf("the managed block must be delimited so it can be found and removed:\n%s", plan.Block)
	}
}

// A dotfile managed by chezmoi, stow or a bare git repo is normally a symlink,
// and an append to it is either refused or silently reverted on the next apply.
func TestSymlinkedRCIsRefused(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/zsh"}, "/home/jsc/.devtun/bin")
	remote := &fakeRemote{replies: []string{"symlink\n"}}

	plan = checkWritable(context.Background(), remote, plan)

	if plan.Writable {
		t.Fatal("a symlinked rc must not be edited")
	}
	if !strings.Contains(plan.Why, "dotfiles") {
		t.Errorf("the reason should mention why: %q", plan.Why)
	}
}

func TestUnwritableRCIsRefused(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/zsh"}, "/home/jsc/.devtun/bin")
	plan = checkWritable(context.Background(), &fakeRemote{replies: []string{"readonly\n"}}, plan)
	if plan.Writable {
		t.Error("an unwritable rc must not be edited")
	}
}

func TestWritableRCIsAccepted(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/zsh"}, "/home/jsc/.devtun/bin")
	plan = checkWritable(context.Background(), &fakeRemote{replies: []string{"ok\n"}}, plan)
	if !plan.Writable {
		t.Errorf("an ordinary rc should be writable, got %q", plan.Why)
	}
}

func TestApplyRefusesWhenNotWritable(t *testing.T) {
	plan := RCPlan{File: "/home/jsc/.zshrc", Writable: false, Why: "it is a symlink"}
	err := applyRC(context.Background(), &fakeRemote{}, plan)
	if err == nil {
		t.Fatal("applying an unwritable plan should fail")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the error should carry the reason, got %v", err)
	}
}

// The edit must be idempotent: connecting fifty times leaves one block, which
// is what the markers are for.
func TestApplyStripsAnyPreviousBlockBeforeAppending(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/zsh"}, "/home/jsc/.devtun/bin")
	plan.Writable = true
	remote := &fakeRemote{replies: []string{""}}

	if err := applyRC(context.Background(), remote, plan); err != nil {
		t.Fatalf("applyRC: %v", err)
	}
	if len(remote.scripts) != 1 {
		t.Fatalf("want one script, got %d", len(remote.scripts))
	}
	script := remote.scripts[0]
	if !strings.Contains(script, "awk") {
		t.Error("the script should filter out a previous block rather than blindly appending")
	}
	for _, marker := range []string{setupMarkerStart, setupMarkerEnd} {
		if !strings.Contains(script, marker) {
			t.Errorf("the script should reference the %q marker", marker)
		}
	}
	// Rename rather than truncate-in-place: a shell rc truncated by a closing
	// lid greets the user with a broken login on a box they may not have
	// another way into.
	if !strings.Contains(script, "mv ") {
		t.Error("the edit should be written to a temporary file and renamed")
	}
}

func TestParseSetupMode(t *testing.T) {
	for _, in := range []string{"ask", "auto", "never"} {
		if got, err := ParseSetupMode(in); err != nil || string(got) != in {
			t.Errorf("ParseSetupMode(%q) = %q, %v", in, got, err)
		}
	}
	if got, _ := ParseSetupMode(""); got != SetupAsk {
		t.Errorf("an empty mode should default to ask, got %q", got)
	}
	if _, err := ParseSetupMode("yolo"); err == nil {
		t.Error("an unknown mode should be rejected")
	}
}

func TestShellQuoteHandlesQuotes(t *testing.T) {
	got := shellQuote(`it's`)
	if got != `'it'\''s'` {
		t.Errorf("unexpected quoting: %s", got)
	}
}

// A user should ever see one devtun block in their rc, not one per service.
// The SSH agent service will be the first to need this, since `ssh` finds its
// agent through SSH_AUTH_SOCK and there is no binary to shadow.
func TestAdvisorLinesJoinTheSameBlock(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/zsh"}, "/home/jsc/.devtun/bin")
	plan.Lines = append(plan.Lines, `export SSH_AUTH_SOCK="/run/user/1000/devtun-agent.sock"`)

	plan = rebuildBlock(plan)

	if strings.Count(plan.Block, setupMarkerStart) != 1 {
		t.Errorf("want exactly one opening marker:\n%s", plan.Block)
	}
	if !strings.Contains(plan.Block, "SSH_AUTH_SOCK") {
		t.Errorf("the added line is not inside the block:\n%s", plan.Block)
	}
	// The marker must still be the last line, or the block cannot be found and
	// replaced next time.
	if !strings.HasSuffix(plan.Block, setupMarkerEnd) {
		t.Errorf("the closing marker must stay last:\n%s", plan.Block)
	}
}

func TestRebuildBlockLeavesAnUnwritablePlanAlone(t *testing.T) {
	plan := planRC(service.Facts{Home: "/home/jsc", Shell: "/bin/tcsh"}, "/home/jsc/.devtun/bin")
	if got := rebuildBlock(plan); got.Block != "" {
		t.Errorf("a plan with no file should have no block, got %q", got.Block)
	}
}

// A line the shell already exports is not missing, and printing it anyway is
// how a setup notice becomes noise people scroll past.
func TestAlreadySetRecognisesAnExistingExport(t *testing.T) {
	facts := service.Facts{Env: map[string]string{
		"SSH_AUTH_SOCK": "/run/user/1000/devtun-agent.sock",
	}}

	if !alreadySet(facts, `export SSH_AUTH_SOCK="/run/user/1000/devtun-agent.sock"`) {
		t.Error("an exact match should count as already set")
	}
	// A different value is somebody else's agent, or a stale path from a
	// previous run. Accepting it silently leaves a service that cannot work and
	// no line saying why.
	if alreadySet(facts, `export SSH_AUTH_SOCK="/tmp/other-agent.sock"`) {
		t.Error("a different value must not count as already set")
	}
	if alreadySet(service.Facts{}, `export SSH_AUTH_SOCK="/x"`) {
		t.Error("an unset variable is not already set")
	}
}

// A value containing a variable cannot be compared without expanding it, so
// devtun must not pretend it can.
func TestUnexpandableExportIsNeverConsideredSet(t *testing.T) {
	facts := service.Facts{Env: map[string]string{"PATH": "/home/jsc/.devtun/bin:/usr/bin"}}

	if alreadySet(facts, `export PATH="$HOME/.devtun/bin:$PATH"`) {
		t.Error("a value with a variable in it cannot be compared")
	}
	if _, _, ok := parseExport("fish_add_path /home/jsc/.devtun/bin"); ok {
		t.Error("only the export form devtun generates should parse")
	}
}
