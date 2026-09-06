package session

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type scriptedRunner struct {
	out string
	err error
}

func (s scriptedRunner) Output(context.Context, string) (string, error) { return s.out, s.err }

const goodProbe = `@@DEVTUN-BASICS
/home/jsc
/run/user/1000
/bin/zsh
jsc
bedev
Linux
x86_64
@@DEVTUN-SHELL
PATH	/home/jsc/.local/bin:/usr/bin:/bin
op	/home/jsc/.local/bin/op
ss	/usr/bin/ss
git	/usr/bin/git
@@DEVTUN-END
`

func TestParseFacts(t *testing.T) {
	facts := parseFacts(goodProbe)

	if facts.Home != "/home/jsc" || facts.RuntimeDir != "/run/user/1000" {
		t.Errorf("wrong directories: %+v", facts)
	}
	if facts.User != "jsc" || facts.Hostname != "bedev" || facts.Shell != "/bin/zsh" {
		t.Errorf("wrong identity: %+v", facts)
	}
	if facts.OS != "linux" || facts.Arch != "amd64" {
		t.Errorf("want linux/amd64, got %s/%s", facts.OS, facts.Arch)
	}
	if !facts.Has("op") || !facts.Has("ss") {
		t.Errorf("tools not discovered: %v", facts.Tools)
	}
	if facts.Has("docker") {
		t.Error("a tool that reported nothing must not count as present")
	}
	if !strings.Contains(facts.LoginPath, ".local/bin") {
		t.Errorf("want the login PATH, got %q", facts.LoginPath)
	}
}

// An interactive shell prints whatever it likes — a motd, a version-manager
// banner, a prompt escape. None of it is ours, and none of it may be parsed.
func TestNoiseOutsideTheMarkersIsIgnored(t *testing.T) {
	noisy := "Welcome to Ubuntu 24.04!\nLast login: Tue\n" + goodProbe + "\nnvm: v20 in use\n"

	facts := parseFacts(noisy)

	if facts.Home != "/home/jsc" {
		t.Errorf("noise broke the parse: %+v", facts)
	}
	if facts.Tools["nvm"] != "" {
		t.Error("text outside the markers must not become a fact")
	}
}

// The login shell is asked before the interactive one and either counts, so a
// tool found by only one of them is still found.
func TestFirstAnswerWinsAcrossBothShells(t *testing.T) {
	both := `@@DEVTUN-BASICS
/home/jsc

/bin/bash
jsc
bedev
Linux
aarch64
@@DEVTUN-SHELL
PATH	/usr/bin
op	
PATH	/home/jsc/.local/bin:/usr/bin
op	/home/jsc/.local/bin/op
@@DEVTUN-END
`
	facts := parseFacts(both)

	if facts.LoginPath != "/usr/bin" {
		t.Errorf("the first non-empty PATH should win, got %q", facts.LoginPath)
	}
	if facts.Tools["op"] != "/home/jsc/.local/bin/op" {
		t.Errorf("a tool found only by the interactive shell should still count, got %q", facts.Tools["op"])
	}
	if facts.Arch != "arm64" {
		t.Errorf("want arm64, got %q", facts.Arch)
	}
}

// A short or truncated answer must not index out of range.
func TestTruncatedProbeDoesNotPanic(t *testing.T) {
	facts := parseFacts("@@DEVTUN-BASICS\n/home/jsc\n")
	if facts.Home != "/home/jsc" {
		t.Errorf("want the home we did get, got %q", facts.Home)
	}
	if facts.Arch != "" {
		t.Errorf("missing fields should stay empty, got %q", facts.Arch)
	}
}

func TestProbeFactsRejectsAHomelessHost(t *testing.T) {
	_, err := probeFacts(context.Background(), scriptedRunner{out: "@@DEVTUN-BASICS\n\n@@DEVTUN-END\n"})
	if err == nil {
		t.Fatal("a host reporting no home should be an error")
	}
}

func TestProbeFactsWrapsTransportErrors(t *testing.T) {
	want := errors.New("connection reset")
	_, err := probeFacts(context.Background(), scriptedRunner{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("want the transport error wrapped, got %v", err)
	}
}

// Getting this wrong uploads a perfectly good binary that then fails with
// "cannot execute binary file".
func TestArchNormalisation(t *testing.T) {
	cases := map[string]string{
		"x86_64": "amd64", "amd64": "amd64",
		"aarch64": "arm64", "arm64": "arm64",
		"armv7l": "arm", "i686": "386", "riscv64": "riscv64",
	}
	for in, want := range cases {
		if got := normalizeArch(in); got != want {
			t.Errorf("normalizeArch(%q) = %q, want %q", in, got, want)
		}
	}
}

// The probe must stay POSIX: dash, busybox ash and ksh all have to run it.
func TestScriptIsPOSIX(t *testing.T) {
	script := factsScript()
	for _, bashism := range []string{"[[", "local ", "declare ", "$'"} {
		if strings.Contains(script, bashism) {
			t.Errorf("the probe script contains a bashism: %q", bashism)
		}
	}
	// The inner probe is embedded in a single-quoted argument, so it must not
	// contain a single quote of its own.
	start := strings.Index(script, "-lc '")
	end := strings.Index(script[start+5:], "'")
	if start < 0 || end < 0 {
		t.Fatal("could not find the embedded inner probe")
	}
	if strings.Contains(script[start+5:start+5+end], `'`) {
		t.Error("the inner probe must contain no single quotes")
	}
}

func TestEveryProbedToolAppearsInTheScript(t *testing.T) {
	script := factsScript()
	for _, tool := range probedTools {
		if !strings.Contains(script, "command -v "+tool) {
			t.Errorf("the script never looks for %q", tool)
		}
	}
}
