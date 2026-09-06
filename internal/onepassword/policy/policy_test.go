package policy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T, rules ...Rule) *Store {
	t.Helper()
	return NewStore(Config{
		DefaultTTL:    5 * time.Minute,
		PromptTimeout: time.Minute,
		Rules:         rules,
	})
}

// recordingSaver stands in for the host's config document. What matters is
// whether it was written to at all, so every call is kept.
type recordingSaver struct {
	saved [][]Rule
	err   error
}

func (r *recordingSaver) SaveRules(rules []Rule) error {
	r.saved = append(r.saved, rules)
	return r.err
}

func (r *recordingSaver) last() []Rule {
	if len(r.saved) == 0 {
		return nil
	}
	return r.saved[len(r.saved)-1]
}

func TestDecideAsksWhenNothingMatches(t *testing.T) {
	store := newTestStore(t)
	if verdict := store.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAsk {
		t.Fatalf("action = %q, want ask", verdict.Action)
	}
}

func TestDecideAllowsFromRule(t *testing.T) {
	store := newTestStore(t, Rule{Host: "devbox", Subject: "op://Personal/**", Action: ActionAllow})
	if verdict := store.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAllow {
		t.Fatalf("action = %q, want allow", verdict.Action)
	}
	if verdict := store.Decide("other", "op://Personal/Docker/PAT"); verdict.Action != ActionAsk {
		t.Fatalf("a rule for devbox must not cover other, got %q", verdict.Action)
	}
}

// A deny rule has to beat an allow rule regardless of the order they appear in,
// otherwise a blocklist entry could be defeated by an earlier allow.
func TestDenyBeatsAllowRegardlessOfOrder(t *testing.T) {
	store := newTestStore(t,
		Rule{Host: "**", Subject: "op://Personal/**", Action: ActionAllow},
		Rule{Host: "**", Subject: "op://Personal/Root/**", Action: ActionDeny},
	)
	if verdict := store.Decide("devbox", "op://Personal/Root/key"); verdict.Action != ActionDeny {
		t.Fatalf("action = %q, want deny", verdict.Action)
	}
}

// Rules arrive from two places, and a deny in either set has to beat an allow
// in the other — otherwise "always allow" on a prompt would quietly defeat a
// global block, or a global allow would defeat a block written for one host.
func TestDenyBeatsAllowAcrossBothRuleSets(t *testing.T) {
	globalDeny := newTestStore(t, Rule{Host: "**", Subject: "op://Personal/Root/**", Action: ActionDeny})
	globalDeny.AdoptHostRules([]Rule{{Host: "devbox", Subject: "op://Personal/**", Action: ActionAllow}}, nil)
	if verdict := globalDeny.Decide("devbox", "op://Personal/Root/key"); verdict.Action != ActionDeny {
		t.Errorf("a per-host allow defeated a global deny: action = %q", verdict.Action)
	}

	globalAllow := newTestStore(t, Rule{Host: "**", Subject: "op://Personal/**", Action: ActionAllow})
	globalAllow.AdoptHostRules([]Rule{{Host: "devbox", Subject: "op://Personal/Root/**", Action: ActionDeny}}, nil)
	if verdict := globalAllow.Decide("devbox", "op://Personal/Root/key"); verdict.Action != ActionDeny {
		t.Errorf("a global allow defeated a per-host deny: action = %q", verdict.Action)
	}
	if verdict := globalAllow.Decide("devbox", "op://Personal/Other/key"); verdict.Action != ActionAllow {
		t.Errorf("the global allow should still cover everything else, got %q", verdict.Action)
	}
}

// And it has to beat a live grant too, so that clicking "always" on a prompt
// cannot quietly override a rule someone wrote to block something.
func TestDenyBeatsTemporaryGrant(t *testing.T) {
	store := newTestStore(t, Rule{Host: "devbox", Subject: "op://Personal/Root/**", Action: ActionDeny})
	store.GrantTemporary("devbox", HostWildcard, time.Hour)

	if verdict := store.Decide("devbox", "op://Personal/Root/key"); verdict.Action != ActionDeny {
		t.Fatalf("action = %q, want deny", verdict.Action)
	}
	if verdict := store.Decide("devbox", "op://Personal/Other/key"); verdict.Action != ActionAllow {
		t.Fatalf("the host grant should still cover everything else, got %q", verdict.Action)
	}
}

func TestGrantsExpire(t *testing.T) {
	store := newTestStore(t)
	store.GrantTemporary("devbox", "op://Personal/Docker/PAT", 20*time.Millisecond)

	if verdict := store.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAllow {
		t.Fatalf("fresh grant: action = %q, want allow", verdict.Action)
	}
	time.Sleep(40 * time.Millisecond)
	if verdict := store.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAsk {
		t.Fatalf("expired grant: action = %q, want ask", verdict.Action)
	}
}

func TestForgetGrants(t *testing.T) {
	store := newTestStore(t)
	store.GrantTemporary("devbox", HostWildcard, time.Hour)
	if got := store.ForgetGrants(); got != 1 {
		t.Fatalf("ForgetGrants() = %d, want 1", got)
	}
	if verdict := store.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAsk {
		t.Fatalf("action = %q, want ask after forgetting", verdict.Action)
	}
}

// "Always" has to outlive the process, which here means it reaches the saver
// and comes back through AdoptHostRules on the next run.
func TestGrantPermanentIsPersistedAndReloads(t *testing.T) {
	saver := &recordingSaver{}
	store := newTestStore(t)
	store.AdoptHostRules(nil, saver)

	if err := store.GrantPermanent("devbox", "op://Personal/Docker/PAT", "approved in a test"); err != nil {
		t.Fatalf("GrantPermanent: %v", err)
	}
	if len(saver.saved) != 1 {
		t.Fatalf("the rule was saved %d times, want 1", len(saver.saved))
	}

	reloaded := newTestStore(t)
	reloaded.AdoptHostRules(saver.last(), saver)
	if verdict := reloaded.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAllow {
		t.Fatalf("after reload: action = %q, want allow", verdict.Action)
	}
	if got := len(reloaded.Rules()); got != 1 {
		t.Fatalf("reloaded %d rules, want 1", got)
	}
}

// A save that fails is reported rather than swallowed: the caller decides what
// to do about it, and being asked again is the worst case.
func TestGrantPermanentReportsASaveFailure(t *testing.T) {
	saver := &recordingSaver{err: errors.New("disk full")}
	store := newTestStore(t)
	store.AdoptHostRules(nil, saver)

	if err := store.GrantPermanent("devbox", "op://V/I/F", ""); err == nil {
		t.Fatal("GrantPermanent = nil, want the saver's error")
	}
	if verdict := store.Decide("devbox", "op://V/I/F"); verdict.Action != ActionAllow {
		t.Errorf("action = %q; the user said yes, so the rule still applies in this process", verdict.Action)
	}
}

func TestRevoke(t *testing.T) {
	saver := &recordingSaver{}
	store := newTestStore(t)
	store.AdoptHostRules(nil, saver)

	for _, subject := range []string{"op://A/one/f", "op://A/two/f"} {
		if err := store.GrantPermanent("devbox", subject, ""); err != nil {
			t.Fatalf("GrantPermanent: %v", err)
		}
	}
	if err := store.Revoke(0); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	rules := store.Rules()
	if len(rules) != 1 || rules[0].Subject != "op://A/two/f" {
		t.Fatalf("rules after revoke = %+v", rules)
	}
	if got := len(saver.last()); got != 1 {
		t.Errorf("the saver was left holding %d rules, want 1", got)
	}
	if err := store.Revoke(5); err == nil {
		t.Error("revoking a missing index should fail")
	}
}

func TestZeroConfigUsesDefaults(t *testing.T) {
	store := NewStore(Config{})
	if got := store.Config().DefaultTTL; got != 5*time.Minute {
		t.Errorf("DefaultTTL = %s, want 5m", got)
	}
	if got := store.Config().PromptTimeout; got != 2*time.Minute {
		t.Errorf("PromptTimeout = %s, want 2m", got)
	}
}

func TestSessionGrantsDoNotExpire(t *testing.T) {
	store := newTestStore(t)
	store.GrantSession("devbox", "op://Personal/Docker/PAT")

	verdict := store.Decide("devbox", "op://Personal/Docker/PAT")
	if verdict.Action != ActionAllow {
		t.Fatalf("action = %q, want allow", verdict.Action)
	}
	if !verdict.Until.IsZero() {
		t.Errorf("Until = %v, want the zero time: a session grant has no expiry of its own", verdict.Until)
	}
	if !strings.Contains(verdict.Reason, "session") {
		t.Errorf("reason = %q, want it to say the grant is session-scoped", verdict.Reason)
	}
}

// A session grant lives in the process, not on disk, so quitting revokes it —
// which is the whole difference between it and an "always" rule.
func TestSessionGrantsAreNotPersisted(t *testing.T) {
	saver := &recordingSaver{}
	store := newTestStore(t)
	store.AdoptHostRules(nil, saver)
	store.GrantSession("devbox", "op://Personal/Docker/PAT")

	if len(saver.saved) != 0 {
		t.Errorf("a session grant wrote %d rule sets, want none", len(saver.saved))
	}
	if got := store.ForgetGrants(); got != 1 {
		t.Errorf("ForgetGrants() = %d, want 1", got)
	}
}

// A TTL grant reports when it lapses, so anything derived from it — a cached
// secret — can be bounded by the same moment.
func TestTemporaryGrantsReportTheirExpiry(t *testing.T) {
	store := newTestStore(t)
	store.GrantTemporary("devbox", "op://V/I/F", time.Minute)

	verdict := store.Decide("devbox", "op://V/I/F")
	if verdict.Until.IsZero() {
		t.Fatal("Until is zero; a temporary grant must report when it lapses")
	}
	if remaining := time.Until(verdict.Until); remaining > time.Minute || remaining < 50*time.Second {
		t.Errorf("Until is %s away, want about a minute", remaining)
	}
}

func TestAccountsFor(t *testing.T) {
	accounts := Accounts{
		Default: "personal.1password.com",
		ByVault: map[string]string{"Barreleye": "work.1password.com"},
	}
	tests := map[string]string{
		"op://Barreleye/CI/token": "work.1password.com",
		"op://Private/Docker/PAT": "personal.1password.com",
		"op://Barreleye/CI":       "work.1password.com",
		"op vault list":           "personal.1password.com",
		"op://?/Docker/PAT":       "personal.1password.com",
	}
	for subject, want := range tests {
		if got := accounts.For(subject); got != want {
			t.Errorf("For(%q) = %q, want %q", subject, got, want)
		}
	}
}

// With one account signed in there is nothing to route, and passing --account
// unnecessarily would just be another way to get it wrong.
func TestAccountsForWithNothingConfigured(t *testing.T) {
	if got := (Accounts{}).For("op://V/I/F"); got != "" {
		t.Errorf("For() = %q, want empty so op picks", got)
	}
}

// A live "allow anything from bedev for 5 minutes" is the most consequential
// state in the process. Until it could be listed, the only thing anyone could
// do about it was drop every grant at once.
func TestGrantsAreListableAndRevocable(t *testing.T) {
	store := NewStore(Config{})
	store.GrantTemporary("bedev", "op://Personal/Docker/PAT", time.Minute)
	store.GrantTemporary("bedev", HostWildcard, time.Minute)
	store.GrantSession("other", "op://Work/Key")

	grants := store.Grants()
	if len(grants) != 3 {
		t.Fatalf("want 3 live grants, got %d: %+v", len(grants), grants)
	}

	var hostWide, session int
	for _, g := range grants {
		if g.HostWide {
			hostWide++
		}
		if g.Expires.IsZero() {
			session++
		}
	}
	if hostWide != 1 {
		t.Errorf("a host-wide grant should be marked as such, got %d", hostWide)
	}
	if session != 1 {
		t.Errorf("a session grant has no expiry, got %d with none", session)
	}

	if !store.RevokeGrant("bedev", HostWildcard) {
		t.Fatal("revoking a listed grant should find it")
	}
	if len(store.Grants()) != 2 {
		t.Errorf("the revoked grant is still listed: %+v", store.Grants())
	}
	if store.RevokeGrant("bedev", "never granted") {
		t.Error("revoking something that was never granted should report so")
	}

	// And revoking must actually close the door, not merely hide the row.
	if decision := store.Decide("bedev", "op://Anything/At/All"); decision.Action == ActionAllow {
		t.Error("the host-wide grant still allows after being revoked")
	}
}

// A lapsed grant is not live state and must not be shown as though it were.
func TestExpiredGrantsAreNotListed(t *testing.T) {
	store := NewStore(Config{})
	store.GrantTemporary("bedev", "op://Personal/Docker/PAT", time.Nanosecond)
	time.Sleep(2 * time.Millisecond)

	if got := store.Grants(); len(got) != 0 {
		t.Errorf("an expired grant should not be listed: %+v", got)
	}
}
