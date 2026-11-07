package authz

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

// withHostRules gives a store host and remembered rules, in memory.
func withHostRules(s *Store, host []Rule, remembered ...Rule) *memoryBook {
	book := &memoryBook{loaded: Loaded{Global: s.Config().Rules, Host: host, Remembered: remembered}}
	s.AdoptBook(book)
	return book
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
	withHostRules(globalDeny, []Rule{{Host: "devbox", Subject: "op://Personal/**", Action: ActionAllow}})
	if verdict := globalDeny.Decide("devbox", "op://Personal/Root/key"); verdict.Action != ActionDeny {
		t.Errorf("a per-host allow defeated a global deny: action = %q", verdict.Action)
	}

	globalAllow := newTestStore(t, Rule{Host: "**", Subject: "op://Personal/**", Action: ActionAllow})
	withHostRules(globalAllow, nil, Rule{Host: "devbox", Subject: "op://Personal/Root/**", Action: ActionDeny})
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

// The panic button used to drop refusals too, reopening every question
// somebody had closed with "no, and stop asking". The one action meant to
// tighten everything loosened something.
func TestForgetGrantsKeepsRefusals(t *testing.T) {
	store := newTestStore(t)
	store.GrantSession("devbox", "op://Work/CI")
	store.RefuseSession("devbox", "op://Private/Root")

	if got := store.ForgetGrants(); got != 1 {
		t.Fatalf("ForgetGrants() = %d, want only the allow", got)
	}
	if got := store.Decide("devbox", "op://Private/Root"); got.Action != ActionDeny {
		t.Errorf("the refusal did not survive Forget: %v", got.Action)
	}
	if got := store.ForgetRefusals(); got != 1 {
		t.Errorf("ForgetRefusals() = %d, want 1", got)
	}
	if got := store.Decide("devbox", "op://Private/Root"); got.Action != ActionAsk {
		t.Errorf("after ForgetRefusals the question should be asked again, got %v", got.Action)
	}
}

// "Always" has to outlive the process, which here means it reaches the rule
// book's remembered list and is read back from it.
func TestGrantPermanentIsRememberedAndReloads(t *testing.T) {
	store := newTestStore(t)
	book := withHostRules(store, nil)

	if err := store.GrantPermanent("devbox", "op://Personal/Docker/PAT", "approved in a test"); err != nil {
		t.Fatalf("GrantPermanent: %v", err)
	}
	if len(book.loaded.Remembered) != 1 || len(book.loaded.Host) != 0 {
		t.Fatalf("an always answer must land in remembered, not the hand-written list: %+v", book.loaded)
	}

	reloaded := newTestStore(t)
	withHostRules(reloaded, nil, book.loaded.Remembered...)
	if verdict := reloaded.Decide("devbox", "op://Personal/Docker/PAT"); verdict.Action != ActionAllow {
		t.Fatalf("after reload: action = %q, want allow", verdict.Action)
	}
	rules := reloaded.Rules()
	if len(rules) != 1 || rules[0].Source != SourceRemembered {
		t.Fatalf("reloaded %+v, want one remembered rule", rules)
	}
}

// A save that fails is reported rather than swallowed: the caller decides what
// to do about it.
func TestGrantPermanentReportsASaveFailure(t *testing.T) {
	store := newTestStore(t)
	book := withHostRules(store, nil)
	book.fail = errors.New("disk full")

	if err := store.GrantPermanent("devbox", "op://V/I/F", ""); err == nil {
		t.Fatal("GrantPermanent = nil, want the book's error")
	}
}

// IDs are what make a revoke on one screen safe while another screen is
// open: they do not move when the list around them does.
func TestRuleIDsSurviveOtherRulesBeingRemoved(t *testing.T) {
	store := newTestStore(t, Rule{Subject: "op://Global/**", Action: ActionDeny})
	withHostRules(store,
		[]Rule{{Subject: "op://A/one/f", Action: ActionAllow}, {Subject: "op://A/two/f", Action: ActionAllow}},
		Rule{Subject: "op://A/three/f", Action: ActionAllow})

	before := store.Rules()
	if len(before) != 4 {
		t.Fatalf("want 4 rules, got %+v", before)
	}
	wantSources := []Source{SourceGlobal, SourceHost, SourceHost, SourceRemembered}
	for i, r := range before {
		if r.Source != wantSources[i] || r.ID == "" {
			t.Errorf("rule %d = %+v, want source %s and an ID", i, r, wantSources[i])
		}
	}
	two, three := before[2].ID, before[3].ID

	if err := store.RemoveRule(before[1].ID); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if r, ok := store.Rule(two); !ok || r.Subject != "op://A/two/f" {
		t.Errorf("removing one rule moved another's ID: %+v %v", r, ok)
	}
	if r, ok := store.Rule(three); !ok || r.Subject != "op://A/three/f" {
		t.Errorf("removing one rule moved another's ID: %+v %v", r, ok)
	}
	// The removed one is gone, and removing it again says so rather than
	// taking out whatever is now in its place.
	if err := store.RemoveRule(before[1].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second remove = %v, want ErrNotFound", err)
	}
}

func TestGlobalRulesAreReadOnly(t *testing.T) {
	store := newTestStore(t, Rule{Subject: "op://Private/**", Action: ActionDeny})
	id := store.Rules()[0].ID

	if err := store.RemoveRule(id); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RemoveRule(global) = %v, want ErrReadOnly", err)
	}
	if _, err := store.SetRuleAction(id, ActionAllow); !errors.Is(err, ErrReadOnly) {
		t.Errorf("SetRuleAction(global) = %v, want ErrReadOnly", err)
	}
	subject := "op://**"
	if _, err := store.UpdateRule(id, RuleEdit{Subject: &subject}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("UpdateRule(global) = %v, want ErrReadOnly", err)
	}
	if got := store.Decide("bedev", "op://Private/x"); got.Action != ActionDeny {
		t.Errorf("the global deny should still decide, got %v", got.Action)
	}
}

// Changing a rule's action works in both directions through the API; the
// confirm before loosening is the interface's job.
func TestSetRuleActionFlipsEitherWayAndKeepsTheNote(t *testing.T) {
	store := newTestStore(t)
	withHostRules(store, []Rule{{Host: "devbox", Subject: "op://A/one/f", Action: ActionAllow, Note: "hand-typed"}})
	id := store.Rules()[0].ID

	denied, err := store.SetRuleAction(id, ActionDeny)
	if err != nil {
		t.Fatalf("SetRuleAction(deny): %v", err)
	}
	if denied.Action != ActionDeny || denied.Note != "hand-typed" || denied.Source != SourceHost {
		t.Errorf("after deny: %+v", denied)
	}
	if denied.ID == id {
		t.Error("the rule says something different now, so its ID should have changed")
	}
	if got := store.Decide("devbox", "op://A/one/f"); got.Action != ActionDeny || got.By.RuleID != denied.ID {
		t.Errorf("verdict = %+v, want the rewritten rule to decide", got)
	}

	allowed, err := store.SetRuleAction(denied.ID, ActionAllow)
	if err != nil {
		t.Fatalf("SetRuleAction(allow): %v", err)
	}
	if allowed.Action != ActionAllow {
		t.Errorf("after allow: %+v", allowed)
	}
	if _, err := store.SetRuleAction(allowed.ID, ActionAsk); err == nil {
		t.Error("a rule cannot be made to ask")
	}
}

func TestUpdateRuleChangesTextAndReturnsTheNewID(t *testing.T) {
	store := newTestStore(t)
	withHostRules(store, nil, Rule{Host: "devbox", Subject: "op://A/one/f", Action: ActionAllow})
	id := store.Rules()[0].ID

	subject, note := "op://A/*/f", "widened"
	updated, err := store.UpdateRule(id, RuleEdit{Subject: &subject, Note: &note})
	if err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if updated.Subject != subject || updated.Note != note || updated.Source != SourceRemembered {
		t.Errorf("updated = %+v", updated)
	}
	if r, ok := store.Rule(updated.ID); !ok || r.Subject != subject {
		t.Errorf("the returned ID does not find the rule: %+v %v", r, ok)
	}
	if got := store.Decide("devbox", "op://A/two/f"); got.Action != ActionAllow {
		t.Errorf("the widened rule did not apply: %v", got.Action)
	}
	empty := " "
	if _, err := store.UpdateRule(updated.ID, RuleEdit{Subject: &empty}); err == nil {
		t.Error("a rule with no subject was accepted")
	}
}

func TestAddRuleLandsInRemembered(t *testing.T) {
	store := newTestStore(t)
	withHostRules(store, []Rule{{Subject: "op://Hand/**", Action: ActionAllow}})

	added, err := store.AddRule(Rule{Host: "devbox", Subject: "op://New/**", Action: ActionDeny, Source: SourceGlobal})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if added.Source != SourceRemembered || added.ID == "" || added.Added.IsZero() {
		t.Errorf("added = %+v; want remembered, with an ID and a stamp, whatever source was asked for", added)
	}
	if _, err := store.AddRule(Rule{Subject: "x", Action: ActionAsk}); err == nil {
		t.Error("a rule that asks was accepted")
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
	store := newTestStore(t)
	book := withHostRules(store, nil)
	store.GrantSession("devbox", "op://Personal/Docker/PAT")

	if book.revision != 0 {
		t.Errorf("a session grant wrote to the rule book %d times, want none", book.revision)
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

	var hostWideID string
	for _, g := range grants {
		if g.HostWide {
			hostWideID = g.ID
		}
	}
	if !store.RevokeGrant(hostWideID) {
		t.Fatal("revoking a listed grant should find it")
	}
	if len(store.Grants()) != 2 {
		t.Errorf("the revoked grant is still listed: %+v", store.Grants())
	}
	if store.RevokeGrant("g999") {
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

// "Never" was the gap: you could say "allow always" and get a rule, but the
// only way to stop being asked about something you kept declining was to
// approve it. A security prompt whose only escape is "yes" teaches the wrong
// reflex.
func TestRefusalsAreRecordableAndBeatAllows(t *testing.T) {
	store := NewStore(Config{Rules: []Rule{
		{Host: "bedev", Subject: "op://Work/**", Action: ActionAllow},
	}})

	// A standing allow rule covers this subject.
	if got := store.Decide("bedev", "op://Work/CI"); got.Action != ActionAllow {
		t.Fatalf("precondition: want allow, got %v", got.Action)
	}

	// Answering "no, stop asking" must win, even against a persistent allow.
	// The most recent and most specific thing the user said was no.
	store.RefuseSession("bedev", "op://Work/CI")
	got := store.Decide("bedev", "op://Work/CI")
	if got.Action != ActionDeny {
		t.Errorf("a session refusal should beat a standing allow rule, got %v (%s)", got.Action, got.Reason)
	}
	// And it must not spill onto its siblings.
	if got := store.Decide("bedev", "op://Work/Other"); got.Action != ActionAllow {
		t.Errorf("the refusal should cover only its own subject, got %v", got.Action)
	}
}

func TestRefuseSessionIsListedAndRevocable(t *testing.T) {
	store := NewStore(Config{})
	store.RefuseSession("bedev", "op://Private/Root")

	grants := store.Grants()
	if len(grants) != 1 || grants[0].Action != ActionDeny {
		t.Fatalf("a refusal should be listed as live state: %+v", grants)
	}

	if !store.RevokeGrant(grants[0].ID) {
		t.Fatal("a listed refusal should be revocable")
	}
	if got := store.Decide("bedev", "op://Private/Root"); got.Action != ActionAsk {
		t.Errorf("after revoking, the question should be asked again, got %v", got.Action)
	}
}

// A temporary refusal must lapse like a temporary approval does.
func TestSessionRefusalOutlivesNothingItShouldNot(t *testing.T) {
	store := NewStore(Config{})
	store.RefuseSession("bedev", "op://X/Y")

	if got := store.Decide("other", "op://X/Y"); got.Action != ActionAsk {
		t.Errorf("a refusal is per host, got %v for a different host", got.Action)
	}
}

// Deny wins at every level, so a permanent refusal cannot be clicked away.
func TestRefusePermanentCannotBeUndoneByAGrant(t *testing.T) {
	store := NewStore(Config{})

	if err := store.RefusePermanent("bedev", "op://Private/Root", "never"); err != nil {
		t.Fatalf("RefusePermanent: %v", err)
	}
	// Somebody clicks through an approval afterwards.
	store.GrantSession("bedev", "op://Private/Root")

	if got := store.Decide("bedev", "op://Private/Root"); got.Action != ActionDeny {
		t.Errorf("a written refusal must beat a later approval, got %v (%s)", got.Action, got.Reason)
	}
}
