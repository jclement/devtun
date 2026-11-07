package authz

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/hostcfg"
)

// Each case is a host or global file that, read naively, dropped a deny while
// a competing allow kept allowing. Every one must refuse instead.
func TestPolicyThatCannotBeReadExactlyRefusesEverything(t *testing.T) {
	allowAll := "1password:\n  rules: [{subject: '**', action: allow}]\n"
	cases := []struct {
		name, global, host string
	}{
		{"duplicate section", "", "1password:\n  rules: [{subject: '**', action: deny}]\n1password:\n  rules: [{subject: '**', action: allow}]\n"},
		{"duplicate key", "", "1password:\n  rules: [{subject: '**', action: deny}]\n  rules: [{subject: '**', action: allow}]\n"},
		{"alias", allowAll, "policy: &p\n  rules: [{subject: '**', action: deny}]\n1password: *p\n"},
		{"merge key", allowAll, "policy: &p\n  rules: [{subject: '**', action: deny}]\n1password:\n  <<: *p\n"},
		{"scalar section", allowAll, "1password: wrong\n"},
		{"misspelt action", "", "1password:\n  rules:\n    - {subject: '**', action: denyy}\n    - {subject: '**', action: allow}\n"},
		{"missing action", "", "1password:\n  rules:\n    - {subject: '**'}\n    - {subject: '**', action: allow}\n"},
		{"missing subject", "", "1password:\n  rules:\n    - {action: deny}\n    - {subject: '**', action: allow}\n"},
		{"unknown field", "", "1password:\n  rules:\n    - {subjet: '**', action: deny}\n    - {subject: '**', action: allow}\n"},
		{"bad remembered rule", "", "1password:\n  rules: [{subject: '**', action: allow}]\n  remembered: [{subject: '**', action: nope}]\n"},
		{"bad global rule", "1password:\n  rules:\n    - {subject: '**', action: dney}\n    - {subject: '**', action: allow}\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			store := hostcfg.Open(dir)
			gate := NewGate(Config{}, nil)
			// Adopt refuses outright when a file is already broken; attach
			// to clean files and break them after, which is the harder case —
			// the policy changing under a running session.
			if err := gate.Adopt("bedev", store.Section("bedev", "1password"), "1Password"); err != nil {
				t.Fatalf("Adopt on clean files: %v", err)
			}
			if c.global != "" {
				mustWrite(t, filepath.Join(dir, "config.yaml"), c.global)
			}
			if c.host != "" {
				mustWrite(t, store.HostPath("bedev"), c.host)
			}
			got := gate.Decide("bedev", "op://V/I/F")
			if got.Action != ActionDeny || got.By.Kind != ByUnreadable {
				t.Errorf("got %+v, want deny ByUnreadable", got)
			}
			if !errors.Is(gate.PolicyErr(), ErrUnreadable) {
				t.Errorf("PolicyErr() = %v", gate.PolicyErr())
			}
			if _, err := gate.AddRule(Rule{Subject: "op://y", Action: ActionDeny}); !errors.Is(err, ErrUnreadable) {
				t.Errorf("AddRule over unreadable policy = %v, want ErrUnreadable", err)
			}
			if c.host != "" {
				if _, err := gate.AddRule(Rule{Subject: "op://x", Action: ActionDeny}); err == nil {
					t.Error("a write over an unreadable file was accepted")
				}
				data, _ := os.ReadFile(store.HostPath("bedev"))
				if string(data) != c.host {
					t.Errorf("the file was rewritten:\n%s", data)
				}
			}
		})
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A blank host override inherits; it does not reset a global deny to ask.
func TestAnEmptyUnmatchedOverrideInherits(t *testing.T) {
	for name, value := range map[string]string{"empty": "''", "null": "null", "blank": "", "whitespace": "'   '"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			store := hostcfg.Open(dir)
			mustWrite(t, filepath.Join(dir, "config.yaml"), "1password:\n  unmatched: deny\n")
			mustWrite(t, store.HostPath("bedev"), "1password:\n  unmatched: "+value+"\n")
			gate := NewGate(Config{}, nil)
			if err := gate.Adopt("bedev", store.Section("bedev", "1password"), "1Password"); err != nil {
				t.Fatal(err)
			}
			if u := gate.Unmatched(); u.Action != ActionDeny || u.Level != "global" {
				t.Errorf("Unmatched() = %+v, want the global deny inherited", u)
			}
			if got := gate.Decide("bedev", "op://V/I/F"); got.Action != ActionDeny {
				t.Errorf("got %v, want deny", got.Action)
			}
		})
	}
}

// Updating a rule into an exact copy of another must return the edited one's
// ID, not the first match's.
func TestUpdatingIntoADuplicateReturnsTheEditedRulesID(t *testing.T) {
	store := newTestStore(t)
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	withHostRules(store, nil,
		Rule{Subject: "x", Action: ActionAllow, Added: at},
		Rule{Subject: "y", Action: ActionAllow, Added: at})
	second := store.Rules()[1].ID

	x := "x"
	updated, err := store.UpdateRule(second, RuleEdit{Subject: &x})
	if err != nil {
		t.Fatal(err)
	}
	rules := store.Rules()
	if rules[0].ID == rules[1].ID {
		t.Fatalf("identical rules share an ID: %+v", rules)
	}
	if updated.ID != rules[1].ID {
		t.Errorf("UpdateRule returned %s, but the edited rule (second) is %s; the first is %s",
			updated.ID, rules[1].ID, rules[0].ID)
	}
	if _, err := store.SetRuleAction(updated.ID, ActionDeny); err != nil {
		t.Fatal(err)
	}
	if got := store.Rules(); got[0].Action != ActionAllow || got[1].Action != ActionDeny {
		t.Errorf("acting on the returned ID changed the wrong rule: %+v", got)
	}
}

// Extra separators and odd field counts behave predictably: SplitN keeps any
// further separator inside the last field, so the key boundary cannot move.
func TestSSHMatchingWithStraySeparators(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		{"* → github.com", slashedKey + " → github.com → evil", false},
		{"* → **", slashedKey + " → github.com → evil", true},
		{slashedKey + " → *", "other → " + slashedKey + " → github.com", false},
		{"* → github.com", "no-separator", false},
		{"no-separator", "no-separator", true},
		{"*", slashedKey + " → github.com", true}, // no separator: whole-subject, crosses everything
		{"* → * → *", slashedKey + " → github.com", false},
	}
	for _, c := range cases {
		if got := sshSchema.Match(c.pattern, c.subject); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}
