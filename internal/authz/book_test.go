package authz

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
)

// These run the gate against real config files, because the promises they
// check — a hand edit is seen and never erased — are promises about files.

func adoptedGate(t *testing.T, store *hostcfg.Store, prompter prompt.Prompter) *Gate {
	t.Helper()
	gate := NewGate(Config{}, prompter)
	if err := gate.Adopt("bedev", store.Section("bedev", "1password"), "1Password"); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	return gate
}

func writeHostFile(t *testing.T, store *hostcfg.Store, content string) {
	t.Helper()
	path := store.HostPath("bedev")
	if err := os.MkdirAll(strings.TrimSuffix(path, "/bedev.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const handWritten = `# my rules
1password:
    rules:
        # the deploy key, for CI
        - subject: op://Work/Deploy/**
          action: allow
        # and never the root keys
        - subject: op://Private/Root/**
          action: deny
`

func TestRulesTypedWhileRunningApplyAtOnceAndSurviveDevtunsWrites(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	gate := adoptedGate(t, store, allowAlways{})

	// Typed in while devtun runs.
	writeHostFile(t, store, handWritten)
	if got := gate.Decide("bedev", "op://Private/Root/key"); got.Action != ActionDeny || got.By.Source != SourceHost {
		t.Fatalf("a deny typed into the host file did not apply without a restart: %+v", got)
	}

	// devtun writes: an "always" answer lands in remembered…
	gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "op://Docs/readme"})
	// …and the hand-written list, comments and all, is still there.
	data, _ := os.ReadFile(store.HostPath("bedev"))
	for _, want := range []string{"# the deploy key, for CI", "# and never the root keys", "op://Private/Root/**", "remembered:", "op://Docs/readme"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("after devtun's write the file is missing %q:\n%s", want, data)
		}
	}
}

func TestRemovingOneHandWrittenRuleKeepsTheOthersAsWritten(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	writeHostFile(t, store, handWritten)
	gate := adoptedGate(t, store, nil)

	var deployID string
	for _, r := range gate.Rules() {
		if r.Subject == "op://Work/Deploy/**" {
			deployID = r.ID
		}
	}
	if err := gate.RemoveRule(deployID); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	data, _ := os.ReadFile(store.HostPath("bedev"))
	if strings.Contains(string(data), "op://Work/Deploy/**") {
		t.Errorf("the removed rule is still in the file:\n%s", data)
	}
	if !strings.Contains(string(data), "# and never the root keys") {
		t.Errorf("the untouched rule lost its comment:\n%s", data)
	}
}

// Two devtun processes, one host file. Each must see the other's rule rather
// than writing back a list that is missing it.
func TestTwoProcessesRememberingRulesKeepBoth(t *testing.T) {
	dir := t.TempDir()
	a := adoptedGate(t, hostcfg.Open(dir), nil)
	b := adoptedGate(t, hostcfg.Open(dir), nil)

	if _, err := a.AddRule(Rule{Host: "bedev", Subject: "op://A/**", Action: ActionDeny}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddRule(Rule{Host: "bedev", Subject: "op://B/**", Action: ActionAllow}); err != nil {
		t.Fatal(err)
	}
	fresh := adoptedGate(t, hostcfg.Open(dir), nil)
	if got := len(fresh.Rules()); got != 2 {
		t.Errorf("want both processes' rules, got %+v", fresh.Rules())
	}
	if got := a.Decide("bedev", "op://B/x"); got.Action != ActionAllow {
		t.Errorf("process a did not see process b's rule: %v", got.Action)
	}
}

// A host file broken mid-session refuses everything until it is fixed, and is
// never overwritten.
func TestABrokenHostFileFailsClosedUntilFixed(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	writeHostFile(t, store, handWritten)
	gate := adoptedGate(t, store, allowAlways{})
	if got := gate.Decide("bedev", "op://Work/Deploy/key"); got.Action != ActionAllow {
		t.Fatalf("precondition: %v", got.Action)
	}

	broken := handWritten + "  - subject: [unclosed\n"
	writeHostFile(t, store, broken)
	if got := gate.Decide("bedev", "op://Work/Deploy/key"); got.Action != ActionDeny || got.By.Kind != ByUnreadable {
		t.Errorf("a broken file should refuse everything, got %+v", got)
	}
	if gate.PolicyErr() == nil {
		t.Error("PolicyErr should say why")
	}
	if _, err := gate.AddRule(Rule{Subject: "op://x", Action: ActionDeny}); err == nil {
		t.Error("a write over a broken file was accepted")
	}
	if asked := gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "op://Q/x"}); asked.Allowed {
		t.Error("a broken policy file let a prompt answer through")
	}
	data, _ := os.ReadFile(store.HostPath("bedev"))
	if string(data) != broken {
		t.Errorf("the broken file was overwritten:\n%s", data)
	}

	writeHostFile(t, store, handWritten)
	if got := gate.Decide("bedev", "op://Work/Deploy/key"); got.Action != ActionAllow {
		t.Errorf("after fixing the file: %v", got.Action)
	}
}

func TestGlobalRulesAndUnmatchedAreReadLiveFromTheGlobalFile(t *testing.T) {
	dir := t.TempDir()
	store := hostcfg.Open(dir)
	gate := adoptedGate(t, store, nil)

	if err := store.GlobalFor("1password").Set("rules", []Rule{{Subject: "op://Private/**", Action: ActionDeny}}); err != nil {
		t.Fatal(err)
	}
	if err := store.GlobalFor("1password").Set("unmatched", "deny"); err != nil {
		t.Fatal(err)
	}
	if got := gate.Decide("bedev", "op://Private/x"); got.By.Source != SourceGlobal {
		t.Errorf("global rule not read live: %+v", got)
	}
	if u := gate.Unmatched(); u.Action != ActionDeny || u.Level != "global" {
		t.Errorf("Unmatched() = %+v", u)
	}
	if err := store.For("bedev", "1password").Set("unmatched", "ask"); err != nil {
		t.Fatal(err)
	}
	if u := gate.Unmatched(); u.Action != ActionAsk || u.Level != "host" {
		t.Errorf("the host's answer should win: %+v", u)
	}
	id := gate.Rules()[0].ID
	if err := gate.RemoveRule(id); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RemoveRule(global) = %v", err)
	}
}
