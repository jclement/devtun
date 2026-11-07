package authz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// sshSchema is the agent's, restated here so authz can test per-field matching
// without importing the broker.
var sshSchema = Schema{
	Noun: "signature",
	Fields: []Field{
		{Name: "key", Label: "key"},
		{Name: "destination", Label: "destination"},
	},
	Separator: " → ",
}

// A fingerprint with a slash in it — about half of all SHA256 fingerprints are.
const slashedKey = "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZ/DTMczCvj3tD2s"

func TestVerdictSaysWhatDecided(t *testing.T) {
	store := newTestStore(t, Rule{Subject: "op://Private/**", Action: ActionDeny})
	withHostRules(store, nil, Rule{Host: "bedev", Subject: "op://Work/**", Action: ActionAllow})

	byRule := store.Decide("bedev", "op://Private/root")
	if byRule.By.Kind != ByRule || byRule.By.Source != SourceGlobal || byRule.By.RuleID != store.Rules()[0].ID {
		t.Errorf("a global deny decided, got By = %+v", byRule.By)
	}
	if !strings.Contains(byRule.Reason, `"op://Private/**"`) || !strings.Contains(byRule.Reason, "every host") {
		t.Errorf("reason %q should quote the rule and spell out an empty host", byRule.Reason)
	}

	store.GrantSession("bedev", "op://Docs/readme")
	byGrant := store.Decide("bedev", "op://Docs/readme")
	if byGrant.By.Kind != ByGrant || byGrant.By.GrantID != store.Grants()[0].ID {
		t.Errorf("a grant decided, got By = %+v", byGrant.By)
	}

	none := store.Decide("bedev", "op://Elsewhere/x")
	if none.By.Kind != ByUnmatched || none.By.Unmatched != ActionAsk {
		t.Errorf("nothing matched, got By = %+v", none.By)
	}

	fields := byRule.By.Fields()
	if len(fields) != 6 || fields[0] != "by" || fields[2] != "rule" || fields[4] != "source" {
		t.Errorf("event fields = %v", fields)
	}
}

// Explain lists every match in evaluation order and marks which one decided,
// so the screen can say "this allow never wins" with evidence.
func TestExplainListsEveryMatchAndTheDecider(t *testing.T) {
	store := newTestStore(t, Rule{Subject: "op://Private/**", Action: ActionAllow})
	withHostRules(store, []Rule{{Subject: "op://Private/Root/**", Action: ActionDeny}})
	store.GrantSession("bedev", "op://Private/Root/key")

	ex := store.Explain("bedev", "op://Private/Root/key")
	if ex.Verdict.Action != ActionDeny {
		t.Fatalf("verdict = %+v, want deny", ex.Verdict)
	}
	if len(ex.Matches) != 3 {
		t.Fatalf("want deny rule, allow rule, allow grant; got %+v", ex.Matches)
	}
	first, second, third := ex.Matches[0], ex.Matches[1], ex.Matches[2]
	if first.Rule == nil || first.Rule.Action != ActionDeny || !first.Decided || first.Outranked {
		t.Errorf("the deny should come first and decide: %+v", first)
	}
	if second.Rule == nil || second.Rule.Source != SourceGlobal || !second.Outranked {
		t.Errorf("the global allow should be listed as outranked: %+v", second)
	}
	if third.Grant == nil || !third.Outranked {
		t.Errorf("the grant should be listed as outranked: %+v", third)
	}
	if ex.Verdict.By.RuleID != first.Rule.ID {
		t.Errorf("verdict and explanation disagree about the decider")
	}
}

// The README's own example: allow GitHub, and nothing else. With deny beating
// allow it cannot be written as an allow plus a deny-everything — that denies
// GitHub too — so it is written as an allow plus `unmatched: deny`.
func TestUnmatchedDenyMakesAnAllowlist(t *testing.T) {
	store := NewStore(Config{Schema: sshSchema})
	book := withHostRules(store, nil, Rule{Subject: "** → github.com", Action: ActionAllow})
	book.loaded.Unmatched, book.loaded.UnmatchedLevel = "deny", "host"

	if got := store.Decide("bedev", slashedKey+" → github.com"); got.Action != ActionAllow {
		t.Errorf("github.com should be allowed, got %+v", got)
	}
	got := store.Decide("bedev", slashedKey+" → gitlab.com")
	if got.Action != ActionDeny || got.By.Kind != ByUnmatched || got.By.Unmatched != ActionDeny {
		t.Errorf("everything else should be refused by the unmatched policy, got %+v", got)
	}
	if u := store.Unmatched(); u.Action != ActionDeny || u.Level != "host" {
		t.Errorf("Unmatched() = %+v", u)
	}

	// And the old way, kept as a test so nobody writes it into the README again.
	wrong := NewStore(Config{Schema: sshSchema})
	withHostRules(wrong, nil,
		Rule{Subject: "** → github.com", Action: ActionAllow},
		Rule{Subject: "** → **", Action: ActionDeny})
	if got := wrong.Decide("bedev", slashedKey+" → github.com"); got.Action != ActionDeny {
		t.Errorf("deny beats allow, so allow+deny-all denies GitHub too; got %v", got.Action)
	}
}

// unmatched only applies when nothing matches: it never loosens a deny and
// never overrides an allow.
func TestUnmatchedNeverOverridesAMatch(t *testing.T) {
	store := newTestStore(t)
	book := withHostRules(store, []Rule{
		{Subject: "op://Work/**", Action: ActionAllow},
		{Subject: "op://Work/Root/**", Action: ActionDeny},
	})
	for _, policy := range []string{"ask", "deny"} {
		book.loaded.Unmatched = policy
		book.revision++
		if got := store.Decide("bedev", "op://Work/ci"); got.Action != ActionAllow {
			t.Errorf("unmatched=%s: an allow rule should still allow, got %v", policy, got.Action)
		}
		if got := store.Decide("bedev", "op://Work/Root/key"); got.Action != ActionDeny {
			t.Errorf("unmatched=%s: a deny rule should still deny, got %v", policy, got.Action)
		}
	}
}

// A typo in the setting that makes an allowlist must not open it.
func TestAnUnreadableUnmatchedValueFailsClosed(t *testing.T) {
	store := newTestStore(t)
	book := withHostRules(store, nil)
	book.loaded.Unmatched, book.loaded.UnmatchedLevel = "dney", "global"

	u := store.Unmatched()
	if u.Action != ActionDeny || u.Err == nil {
		t.Errorf("Unmatched() = %+v, want deny with an error", u)
	}
	if got := store.Decide("bedev", "op://x/y/z"); got.Action != ActionDeny {
		t.Errorf("got %v, want deny", got.Action)
	}
}

// brokenBook is a rule file that cannot be read.
type brokenBook struct{ memoryBook }

func (*brokenBook) Load() (Loaded, error) {
	return Loaded{}, errors.New("hosts/bedev.yaml: yaml: line 3: did not find expected key")
}

// A policy file broken by a hand edit mid-session must not read as an empty
// policy. It might be the file holding the deny that matters.
func TestAnUnreadablePolicyRefusesEverything(t *testing.T) {
	store := newTestStore(t, Rule{Subject: "op://Work/**", Action: ActionAllow})
	store.GrantSession("bedev", "op://Docs/x")
	store.AdoptBook(&brokenBook{})

	for _, subject := range []string{"op://Work/ci", "op://Docs/x", "op://Other/y"} {
		got := store.Decide("bedev", subject)
		if got.Action != ActionDeny || got.By.Kind != ByUnreadable {
			t.Errorf("%s: got %+v, want deny ByUnreadable", subject, got)
		}
	}
	if err := store.PolicyErr(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("PolicyErr() = %v, want ErrUnreadable", err)
	}
}

// RevokeGrant used to find the first grant with a matching host and subject —
// which, once a five-minute grant had lapsed and been granted again, was the
// lapsed one. The revoke "succeeded" and the live grant carried on.
func TestRevokeGrantNeverHitsAnExpiredDuplicate(t *testing.T) {
	store := newTestStore(t)
	store.GrantTemporary("bedev", "op://V/I/F", time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	store.GrantSession("bedev", "op://V/I/F")

	live := store.Grants()
	if len(live) != 1 {
		t.Fatalf("want one live grant, got %+v", live)
	}
	if store.RevokeGrant("g1") {
		t.Error("revoking the lapsed grant's ID reported success")
	}
	if !store.RevokeGrant(live[0].ID) {
		t.Fatal("the live grant was not found")
	}
	if got := store.Decide("bedev", "op://V/I/F"); got.Action != ActionAsk {
		t.Errorf("the live grant survived its revoke: %v", got.Action)
	}
}

func TestAddGrantFromTheForm(t *testing.T) {
	store := newTestStore(t)
	g, err := store.AddGrant(GrantSpec{Host: "bedev", Subject: "op://Work/**", Action: ActionAllow, TTL: time.Minute})
	if err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if g.ID == "" || g.Expires.IsZero() {
		t.Errorf("grant = %+v", g)
	}
	if got := store.Decide("bedev", "op://Work/ci"); got.Action != ActionAllow || got.By.GrantID != g.ID {
		t.Errorf("verdict = %+v", got)
	}
	if _, err := store.AddGrant(GrantSpec{Host: "bedev", Subject: "x", Action: ActionAsk}); err == nil {
		t.Error("a grant that asks was accepted")
	}
	before := store.Revision()
	store.RevokeGrant(g.ID)
	if store.Revision() == before {
		t.Error("revoking a grant did not move the revision")
	}
}

// `*` stopped at the `/` in about half of all key fingerprints, so `* →
// github.com` — the rule the agent's own documentation recommended — silently
// failed for those keys. Per-field matching without a path separator fixes it.
func TestSSHSubjectsMatchFieldByField(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"* → github.com", true},
		{"** → github.com", true},
		{"** → **", true},
		{"**", true},
		{slashedKey + " → *", true},
		{"ssh-ed25519 *", true},
		{"ssh-rsa * → github.com", false},
		{"* → gitlab.com", false},
		{"* → *.com", true},
	}
	for _, c := range cases {
		if got := sshSchema.Match(c.pattern, slashedKey+" → github.com"); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
	if !Match("op://Personal/*", "op://Personal/Docker") || Match("op://Personal/*", "op://Personal/Docker/PAT") {
		t.Error("the default schema must keep `*` stopping at `/` for op:// references")
	}
}

func TestSchemaSplitsAndJoins(t *testing.T) {
	parts := sshSchema.Split(slashedKey + " → github.com")
	if len(parts) != 2 || parts[0] != slashedKey || parts[1] != "github.com" {
		t.Errorf("Split = %q", parts)
	}
	if got := sshSchema.Split("**"); len(got) != 2 || got[0] != "**" || got[1] != "**" {
		t.Errorf("a bare ** should read as any key to anywhere, got %q", got)
	}
	if got := sshSchema.Join([]string{"*", "github.com"}); got != "* → github.com" {
		t.Errorf("Join = %q", got)
	}
	if got := DefaultSchema.Split("op://a/b/c"); len(got) != 1 {
		t.Errorf("a single-field schema splits into one part, got %q", got)
	}
	if s := NewStore(Config{}).Schema(); len(s.Fields) != 1 || !s.PathLike {
		t.Errorf("zero schema should default to one path-like field: %+v", s)
	}
}
