package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/doctor"
)

// stubTool writes a fake command and puts it first on PATH.
func stubTool(t *testing.T, name, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stubs are shell scripts")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func find(t *testing.T, section *doctor.Section, name string) doctor.Check {
	t.Helper()
	for _, c := range section.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, section.Checks)
	return doctor.Check{}
}

// An op that is installed and configured but *not signed in* is the case that
// matters, and the one this check used to miss.
//
// It ran `op account list`, which reads a file on disk and succeeds with no
// session at all — so doctor reported a cheerful tick on a machine where every
// request from the remote came back "account is not signed in". That is exactly
// the failure the check exists to find, passed over by the check itself. The
// three states have three different fixes and have to be told apart.
func TestDoctorTellsSignedInFromMerelyConfigured(t *testing.T) {
	// Configured, not signed in: `whoami` fails, `account list` succeeds.
	section := &doctor.Section{}
	stubTool(t, "op", `case "$1" in
	--version) echo 2.30.0;;
	whoami) echo "[ERROR] account is not signed in" >&2; exit 1;;
	account) echo "URL EMAIL"; echo "example.1password.com a@b.c";;
	esac`)
	doctorOnePassword(t.Context(), section, upFlags{})

	got := find(t, section, "1password")
	if got.Status != doctor.StatusWarn || !strings.Contains(got.Detail, "not signed in") {
		t.Errorf("a configured-but-unauthenticated op reported %+v", got)
	}
	if !strings.Contains(got.Fix, "signin") && !strings.Contains(got.Fix, "Integrate") {
		t.Errorf("the fix does not say how to sign in: %q", got.Fix)
	}

	// No accounts at all: a different problem with a different fix.
	section = &doctor.Section{}
	stubTool(t, "op", `case "$1" in
	--version) echo 2.30.0;;
	whoami) exit 1;;
	account) exit 1;;
	esac`)
	doctorOnePassword(t.Context(), section, upFlags{})
	if got := find(t, section, "1password"); !strings.Contains(got.Fix, "account add") {
		t.Errorf("an op with no accounts was not told to add one: %+v", got)
	}

	// Signed in.
	section = &doctor.Section{}
	stubTool(t, "op", `case "$1" in
	--version) echo 2.30.0;;
	whoami) echo "URL:   https://example.1password.com"; echo "Email: a@b.c";;
	esac`)
	doctorOnePassword(t.Context(), section, upFlags{})
	got = find(t, section, "1password")
	if got.Status != doctor.StatusOK {
		t.Errorf("a signed-in op reported %+v", got)
	}
	if !strings.Contains(got.Detail, "a@b.c") {
		t.Errorf("the check does not say which account answered: %q", got.Detail)
	}
}

func TestDoctorReportsAMissingOp(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	section := &doctor.Section{}
	doctorOnePassword(t.Context(), section, upFlags{})

	got := find(t, section, "1password")
	if got.Status != doctor.StatusWarn || !strings.Contains(got.Fix, "1password-cli") {
		t.Errorf("check = %+v", got)
	}
}

// The three agent answers are different problems with different fixes, and
// telling them apart is most of why this check exists: no agent, an agent that
// is not there any more, and an agent holding nothing.
func TestDoctorDistinguishesTheAgentFailures(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	section := &doctor.Section{}
	doctorAgent(section, upFlags{})
	if got := find(t, section, "ssh-agent"); got.Status != doctor.StatusWarn ||
		!strings.Contains(got.Detail, "not set") {
		t.Errorf("with no agent: %+v", got)
	}

	section = &doctor.Section{}
	doctorAgent(section, upFlags{authSock: filepath.Join(t.TempDir(), "gone.sock")})
	if got := find(t, section, "ssh-agent"); got.Status != doctor.StatusFail ||
		!strings.Contains(got.Fix, "stale") {
		t.Errorf("with a dead socket: %+v", got)
	}

	section = &doctor.Section{}
	doctorAgent(section, upFlags{noAgent: true})
	if got := find(t, section, "ssh-agent"); got.Status != doctor.StatusOff {
		t.Errorf("with --no-agent: %+v", got)
	}
}

// A request nobody hears is a request that times out, and a timeout reads as a
// refusal nobody made — so whether this machine can make a sound is worth
// reporting before the fact rather than after.
func TestDoctorReportsWhetherAnApprovalWillBeHeard(t *testing.T) {
	section := &doctor.Section{}
	doctorAlert(section)

	got := find(t, section, "alert")
	switch got.Status {
	case doctor.StatusOK:
		if !strings.Contains(got.Detail, "plays a sound") {
			t.Errorf("a machine that can play says %q", got.Detail)
		}
	case doctor.StatusWarn:
		// A headless box is a legitimate answer, but it has to say what to do.
		if !strings.Contains(got.Fix, "bell") {
			t.Errorf("a silent machine was not told what to do about it: %q", got.Fix)
		}
	default:
		t.Errorf("the alert check reported %q, which is neither", got.Status)
	}
}
