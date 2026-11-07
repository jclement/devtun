package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/sshagent"
)

// policyService is a service that is also a broker's policy, which is how
// the settings catalogue finds the brokers it lists under Policy.
type policyService struct {
	stubService
	*stubSecrets
}

const edKey = "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZ/DTMczCvj3tD2s"

// sourcedFixture has a rule from each source, an SSH broker with the README's
// old allow-plus-deny-everything, and an op deny that outranks an allow.
func sourcedFixture(t *testing.T) (*Model, *stubSecrets, *stubSecrets) {
	t.Helper()
	op := &stubSecrets{
		live: []authz.Grant{{Host: "bedev", Subject: "op://Personal/AWS/root", Action: authz.ActionDeny}},
		rules: []authz.Rule{
			{Host: "bedev", Subject: "op://Work/CI/token", Action: authz.ActionAllow, Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "op://Work/Stripe/key", Action: authz.ActionDeny, Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "op://Private/Notes/pin", Action: authz.ActionAllow, Source: authz.SourceHost},
		},
		global: []authz.Rule{{Host: "**", Subject: "op://Private/**", Action: authz.ActionDeny}},
	}
	schema := sshagent.Schema
	ssh := &stubSecrets{
		schema: &schema,
		rules: []authz.Rule{
			{Host: "bedev", Subject: edKey + " → github.com", Action: authz.ActionAllow, Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "** → **", Action: authz.ActionDeny, Source: authz.SourceHost},
		},
	}
	all, _ := prompt.ParseSurfaces("all")
	m := newTestModel(t, deps{
		secrets:       []accessSource{{id: "1password", title: "1Password", ctrl: op}, {id: "ssh-agent", title: "SSH Agent", ctrl: ssh}},
		promptBackend: all,
	})
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	send(m, "3")
	return m, op, ssh
}

func TestAccessGroupsRulesByWhoWroteThem(t *testing.T) {
	m, _, _ := sourcedFixture(t)
	view := bodyLines(m)
	order := []string{"LIVE", "WRITTEN BY DEVTUN", "YOU WROTE", "ALL HOSTS"}
	at := -1
	for _, h := range order {
		i := strings.Index(view, h)
		if i < 0 || i < at {
			t.Fatalf("heading %q missing or out of order:\n%s", h, view)
		}
		at = i
	}
	for _, want := range []string{"always", "never", "stop-ask"} {
		if !strings.Contains(view, want) {
			t.Errorf("KIND %q is not shown:\n%s", want, view)
		}
	}
}

// A hand-written host rule may be edited from the interface; a global one may
// not.
func TestYouWroteRulesAreEditableAndGlobalOnesAreNot(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	selectSubject(m, "op://Private/Notes/pin")
	if why := m.revokeBlocked(); why != "" {
		t.Errorf("a host-file rule cannot be revoked: %q", why)
	}
	selectSubject(m, "op://Private/**")
	send(m, "r")
	if len(op.revoked) != 0 {
		t.Error("a global rule was revoked")
	}
}

// The README's old example: an allow for github.com under a deny for
// everything. The allow never wins, and the screen now says so.
func TestAnAllowUnderADenyIsMarkedOutranked(t *testing.T) {
	m, _, _ := sourcedFixture(t)
	selectSubject(m, edKey+" → github.com")
	r, _ := m.selectedAccess()
	if !r.outranked || !r.exact {
		t.Fatalf("the github.com allow is not marked outranked: %+v", r)
	}
	if !strings.Contains(bodyLines(m), "⚠") {
		t.Errorf("no ⚠ in the list:\n%s", bodyLines(m))
	}
	send(m, "enter")
	view := plainView(m)
	if !strings.Contains(view, "never wins") || !strings.Contains(view, "any key → anywhere") {
		t.Errorf("the detail does not say what beats it:\n%s", view)
	}

	// The host-file pin under the global op://Private/** deny is outranked too.
	send(m, "esc")
	selectSubject(m, "op://Private/Notes/pin")
	if r, _ := m.selectedAccess(); !r.outranked {
		t.Error("an allow under a global deny is not marked")
	}
	// An allow nothing denies is not.
	selectSubject(m, "op://Work/CI/token")
	if r, _ := m.selectedAccess(); r.outranked {
		t.Error("an allow nothing denies is marked outranked")
	}
}

func TestADenysDetailSaysWhatItBeats(t *testing.T) {
	m, _, _ := sourcedFixture(t)
	selectSubject(m, "** → **")
	send(m, "enter")
	if !strings.Contains(plainView(m), "It beats:") {
		t.Errorf("a catch-all deny's detail lists nothing it beats:\n%s", plainView(m))
	}
}

func TestTheFallbackLineShowsEachBrokersUnmatchedPolicy(t *testing.T) {
	m, _, ssh := sourcedFixture(t)
	ssh.unmatched = &authz.UnmatchedPolicy{Action: authz.ActionDeny, Level: "host"}
	line := plainView(m)
	if !strings.Contains(line, "op: ask") || !strings.Contains(line, "key: deny") {
		t.Errorf("the fallback line does not show per-broker policy:\n%s", line)
	}

	ssh.policyErr = errors.New("hosts/bedev.yaml: yaml: line 4: did not find expected key")
	if view := plainView(m); !strings.Contains(view, "key refuses everything") || !strings.Contains(view, "line 4") {
		t.Errorf("an unreadable policy file is not shown:\n%s", view)
	}
}

func TestActivityExplainsARefusalAndJumpsToTheRule(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	global := op.global[0]
	m.Update(eventMsg(event.Event{
		Time: testNow, Service: "1password", Kind: "denied", Class: event.Security,
		Text:   "refused bedev op://Private/Root/ssh — denied by rule",
		Fields: []any{"subject", "op://Private/Root/ssh", "why", "denied by rule", "by", "rule", "rule", global.ID, "source", "global"},
	}))
	send(m, "2")
	send(m, "up")
	send(m, "enter")
	view := plainView(m)
	for _, want := range []string{"refused by a rule", "you wrote it · all hosts", "op://Private/**"} {
		if !strings.Contains(view, want) {
			t.Errorf("the why is missing %q:\n%s", want, view)
		}
	}
	send(m, "o")
	if m.tab != tabAccess {
		t.Fatalf("o left us on %v", m.tab)
	}
	if r, ok := m.selectedAccess(); !ok || r.rule.ID != global.ID {
		t.Errorf("o selected %+v, want the deciding rule", r)
	}
}

func TestActivityExplainsATimeoutAndAnUnmatchedDeny(t *testing.T) {
	m, _, _ := sourcedFixture(t)
	m.Update(eventMsg(event.Event{Time: testNow, Service: "1password", Kind: "denied", Class: event.Security,
		Text: "refused", Fields: []any{"subject", "op://A/B/c", "by", "timeout"}}))
	send(m, "2")
	send(m, "up")
	send(m, "enter")
	if !strings.Contains(plainView(m), "counts as No") {
		t.Errorf("a timeout is not explained:\n%s", plainView(m))
	}
	send(m, "esc")
	m.Update(eventMsg(event.Event{Time: testNow, Service: "ssh-agent", Kind: "denied", Class: event.Security,
		Text: "refused", Fields: []any{"subject", edKey + " → gitlab.com", "by", "unmatched", "unmatched", "deny"}}))
	send(m, "G")
	send(m, "enter")
	if !strings.Contains(plainView(m), "unmatched\" is deny") {
		t.Errorf("an unmatched deny is not explained:\n%s", plainView(m))
	}
}

func TestTheTestBoxShowsTheStoresAnswer(t *testing.T) {
	m, _, _ := sourcedFixture(t)
	send(m, "t")
	if m.test == nil {
		t.Fatal("t did not open the test box")
	}
	typeIn(m, "op://Private/Root/gpg")
	view := plainView(m)
	if !strings.Contains(view, "DENY") || !strings.Contains(view, "op://Private/**") {
		t.Errorf("the test box does not show the deny and what decided:\n%s", view)
	}
	m.test.fields.values[0].SetValue("op://Somewhere/Else/x")
	if !strings.Contains(plainView(m), "would ASK") {
		t.Errorf("an unmatched subject does not say ask:\n%s", plainView(m))
	}
	send(m, "esc")
	if m.test != nil {
		t.Error("esc did not close the test box")
	}
}

// A new allow asks before it is written; a deny does not, because it only
// tightens.
func TestTheNewRuleFormConfirmsAnAllowAndNotADeny(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	m.cursors[tabAccess] = noSelection
	send(m, "n")
	if m.form == nil {
		t.Fatal("n did not open the form")
	}
	typeIn(m, "op://Shared/Dev/**")
	send(m, "enter")
	if m.confirm == nil || len(op.addedRules) != 0 {
		t.Fatal("saving an allow did not ask first")
	}
	if !strings.Contains(plainView(m), "without being asked") {
		t.Errorf("the confirm does not say what it opens:\n%s", plainView(m))
	}
	send(m, "y")
	if len(op.addedRules) != 1 || op.addedRules[0].Subject != "op://Shared/Dev/**" || op.addedRules[0].Host != "bedev" {
		t.Fatalf("the rule written was %+v", op.addedRules)
	}

	send(m, "n")
	m.form.fields.values[0].SetValue("op://Private/Keys/x")
	m.form.effect = authz.ActionDeny
	send(m, "enter")
	if m.confirm != nil || len(op.addedRules) != 2 {
		t.Error("a deny should be saved without a confirm")
	}
}

func TestTheFormMakesGrantsForSessionAndMinutes(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	m.cursors[tabAccess] = noSelection
	send(m, "n")
	m.form.fields.values[0].SetValue("op://Shared/Dev/token")
	m.form.lasts = lastsMinutes
	send(m, "enter")
	send(m, "y")
	if len(op.addedGrants) != 1 || op.addedGrants[0].TTL != formGrantTTL || op.addedGrants[0].Action != authz.ActionAllow {
		t.Errorf("the grant made was %+v", op.addedGrants)
	}
}

// w on a rule devtun wrote edits it in place; ctrl+t widens the last part of
// the pattern one step, and widening an allow asks.
func TestWidenEditsARuleInPlaceAfterAConfirm(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	selectSubject(m, "op://Work/CI/token")
	send(m, "w")
	if m.form == nil || m.form.editing == "" {
		t.Fatal("w on a remembered rule did not open an edit")
	}
	send(m, "ctrl+t")
	if got := m.form.fields.subject(m); got != "op://Work/CI/*" {
		t.Fatalf("ctrl+t widened to %q", got)
	}
	send(m, "ctrl+t")
	if got := m.form.fields.subject(m); got != "op://Work/CI/**" {
		t.Fatalf("a second ctrl+t widened to %q", got)
	}
	send(m, "enter")
	if m.confirm == nil || !strings.Contains(m.confirm.title, "Widen") {
		t.Fatal("widening an allow did not ask")
	}
	send(m, "y")
	if len(op.updated) != 1 || *op.updated[0].Subject != "op://Work/CI/**" {
		t.Errorf("the update was %+v", op.updated)
	}
}

// A global rule is not yours to edit here, so w writes a new rule beside it.
func TestWidenOnAGlobalRuleWritesANewOne(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	selectSubject(m, "op://Private/**")
	send(m, "w")
	if m.form == nil || m.form.editing != "" {
		t.Fatal("w on a global rule should open a new rule")
	}
	send(m, "enter") // a deny: saved straight away
	if len(op.addedRules) != 1 || len(op.updated) != 0 {
		t.Errorf("added %+v, updated %+v", op.addedRules, op.updated)
	}
}

// SSH subjects are two fields, so "any key to github.com" is a field set to
// ** rather than a glob to get right.
func TestTheFormShowsSSHAsKeyAndDestination(t *testing.T) {
	m, _, ssh := sourcedFixture(t)
	selectSubject(m, edKey+" → github.com")
	send(m, "w")
	if len(m.form.fields.values) != 2 {
		t.Fatalf("the ssh form has %d fields", len(m.form.fields.values))
	}
	m.form.focus = 1 // the key
	send(m, "ctrl+t")
	if got := m.form.fields.subject(m); got != "** → github.com" {
		t.Errorf("widening the key gave %q", got)
	}
	_ = ssh
}

// w in the approval opens the form on the request without answering it; a
// rule that covers the request answers it, and esc goes back to the question.
func TestWidenFromTheApprovalAnswersWhatTheRuleCovers(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	reply := make(chan prompt.Choice, 1)
	ask := func() {
		m.Update(approvalMsg{
			request: prompt.Request{Host: "bedev", Subject: "op://Shared/Dev/token"},
			options: prompt.MenuFor(prompt.Request{Host: "bedev", Subject: "op://Shared/Dev/token", TTL: time.Minute}),
			reply:   reply,
		})
	}
	ask()
	send(m, "w")
	if m.form == nil || m.approval != nil {
		t.Fatal("w did not hand the approval to the form")
	}
	send(m, "esc")
	if m.approval == nil {
		t.Fatal("cancelling the form did not go back to the approval")
	}

	send(m, "w")
	send(m, "ctrl+t") // op://Shared/Dev/*
	send(m, "enter")
	send(m, "y")
	if len(op.addedRules) != 1 {
		t.Fatalf("no rule was written: %+v", op.addedRules)
	}
	select {
	case got := <-reply:
		if got != prompt.ChoiceAllowOnce {
			t.Errorf("the covered request was answered %v", got)
		}
	default:
		t.Error("the covered request was left waiting")
	}
}

func TestConfigListsEachBrokersUnmatchedPolicy(t *testing.T) {
	op := &stubSecrets{}
	services := []service.Service{policyService{stubService{meta: service.Meta{ID: "1password", Title: "1Password", Glyph: "❖"}}, op}}
	m := newTestModel(t, deps{services: services, secrets: oneSource(op), store: newTestStore(t)})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	send(m, "5")
	if !strings.Contains(bodyLines(m), "unmatched") {
		t.Errorf("the Config tab has no unmatched policy row:\n%s", bodyLines(m))
	}
}
