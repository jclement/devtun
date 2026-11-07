package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/ui"
)

// The board's Access tab: everything the interface's Access tab can do, as
// endpoints.
//
// None of the policy is here. What matches, what wins, and what a rule would
// decide are all asked of the broker through authz.Policy, which is the same
// surface the terminal drives — a second copy of the matching rules in a web
// handler, or worse in the page's JavaScript, is a second answer to "would
// this be allowed?" that will one day disagree with the first.
//
// What is here is the one thing the store leaves to whoever has a person in
// front of them: the confirm before loosening. The page asks first; these
// handlers refuse a loosening change that does not say it was confirmed. That
// is not a security boundary — the page that asks is the page that sends
// confirm=1 — but it means a page bug that skipped the dialog fails loudly
// instead of quietly opening something, and it makes "which changes loosen"
// a list written down here and tested, rather than a habit of the page.

// confirmParam is how a request says the person saw the loosen-confirm.
const confirmParam = "confirm"

// maxGrantTTL bounds a grant made from the board. A day is longer than any
// working session; anything meant to outlast that is a rule, which is written
// down where it can be read.
const maxGrantTTL = 24 * time.Hour

// policyView is one gated service, as the Access tab needs to know it: what
// its subjects are made of, and what happens when nothing matches.
type policyView struct {
	Source string     `json:"source"`
	Title  string     `json:"title"`
	Glyph  string     `json:"glyph,omitempty"`
	Short  string     `json:"short"`
	Noun   string     `json:"noun"`
	Schema schemaView `json:"schema"`
	// Unmatched is the effective "when nothing matches" for this service.
	Unmatched unmatchedView `json:"unmatched"`
	// PolicyErr is set while a policy file cannot be read: every request on
	// this service is being refused until it is fixed, which the page shows
	// above everything else.
	PolicyErr string `json:"policyErr,omitempty"`
}

type schemaView struct {
	Fields    []fieldView `json:"fields"`
	Separator string      `json:"separator,omitempty"`
	// PathLike says `*` stops at `/` here, which is what decides how the
	// form widens a field one step.
	PathLike bool `json:"pathLike,omitempty"`
}

type fieldView struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Help  string `json:"help,omitempty"`
	// Glob says what a wildcard means in this field, from the schema rather
	// than from the page: `*` is one path segment in an op:// reference and
	// any run of characters in an SSH destination, and a hint that said the
	// former about the latter taught people the wrong rule.
	Glob string `json:"glob"`
}

// globHelp describes the wildcards of one schema's fields.
func globHelp(schema authz.Schema) string {
	if schema.PathLike {
		return "* is one /-separated segment, ** is everything below"
	}
	return "* matches anything within this field"
}

type unmatchedView struct {
	Action string `json:"action"`
	Level  string `json:"level"`
	Err    string `json:"err,omitempty"`
}

// matchView is one rule or grant inside an explanation.
type matchView struct {
	Kind      string `json:"kind"` // "rule" or "grant"
	Source    string `json:"source"`
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	Host      string `json:"host"`
	Subject   string `json:"subject"`
	Action    string `json:"action"`
	Note      string `json:"note,omitempty"`
	HostWide  bool   `json:"hostWide,omitempty"`
	Decided   bool   `json:"decided"`
	Outranked bool   `json:"outranked"`
}

type deciderView struct {
	Kind      string `json:"kind"`
	RuleID    string `json:"ruleId,omitempty"`
	Source    string `json:"source,omitempty"`
	GrantID   string `json:"grantId,omitempty"`
	Unmatched string `json:"unmatched,omitempty"`
}

type verdictView struct {
	Action string      `json:"action"`
	Reason string      `json:"reason"`
	By     deciderView `json:"by"`
}

// explainView is the answer to "what would decide this?". Self, BeatenBy and
// Beats are filled in when the question was asked about one rule or grant:
// the detail view's "what overrides this" and "what this overrides".
type explainView struct {
	Verdict   verdictView   `json:"verdict"`
	Matches   []matchView   `json:"matches"`
	Unmatched unmatchedView `json:"unmatched"`
	Self      *matchView    `json:"self,omitempty"`
	BeatenBy  []matchView   `json:"beatenBy,omitempty"`
	Beats     []matchView   `json:"beats,omitempty"`
}

// accessState fills the Access half of a snapshot: every rule and grant, with
// what the page needs to draw them, and one policy row per gated service.
func (s *Server) accessState(payload *statePayload) {
	var revision []string
	for _, gated := range s.brokers() {
		id, broker := gated.id, gated.broker
		schema := broker.Schema()
		payload.Policies = append(payload.Policies, s.policyView(id, broker))
		revision = append(revision, id+":"+strconv.FormatUint(broker.Revision(), 10))

		for _, rule := range broker.Rules() {
			view := ruleView{
				Source: id, ID: rule.ID, Origin: string(rule.Source), Host: rule.Host,
				Subject: rule.Subject, Parts: schema.Split(rule.Subject), Action: string(rule.Action),
				Note: rule.Note, Global: rule.Source == authz.SourceGlobal, Editable: rule.Editable(),
			}
			if !rule.Added.IsZero() {
				view.Added = rule.Added.Format(time.RFC3339)
			}
			if rule.Action == authz.ActionAllow {
				view.Outranked = s.outranked(broker, rule.Host, rule.Subject, func(m authz.Matched) bool {
					return m.Rule != nil && m.Rule.ID == rule.ID
				})
			}
			payload.Rules = append(payload.Rules, view)
		}
		for _, grant := range broker.Grants() {
			view := grantView{
				Source: id, ID: grant.ID, Host: grant.Host, Subject: grant.Subject,
				Parts: schema.Split(grant.Subject), Action: string(grant.Action), HostWide: grant.HostWide,
			}
			if !grant.Expires.IsZero() {
				view.Expires = grant.Expires.Format(time.RFC3339)
			}
			if !grant.Created.IsZero() {
				view.Created = grant.Created.Format(time.RFC3339)
			}
			if grant.Action == authz.ActionAllow {
				view.Outranked = s.outranked(broker, grant.Host, grant.Subject, func(m authz.Matched) bool {
					return m.Grant != nil && m.Grant.ID == grant.ID
				})
			}
			payload.Grants = append(payload.Grants, view)
		}
	}
	payload.Revision = strings.Join(revision, ",")
}

// outranked reports whether an allow loses to a deny for the request its own
// pattern describes — the pattern asked about as if it were a request. That is
// the case the ⚠ marker exists for: "allow * → github.com" under "deny ** → **"
// never wins, and nothing on screen used to say so.
//
// An allow grant beneath an allow rule is also "outranked" in the store's
// sense, but harmlessly — the request is allowed either way — so only a deny
// deciding counts here.
func (s *Server) outranked(broker Broker, host, subject string, self func(authz.Matched) bool) bool {
	x := broker.Explain(s.explainHost(host), subject)
	if x.Verdict.Action != authz.ActionDeny {
		return false
	}
	for _, m := range x.Matches {
		if self(m) {
			return m.Outranked
		}
	}
	return false
}

// explainHost is the host to ask about for a rule's own pattern. A rule for
// every host, or for a glob of them, is asked about as this session's host:
// that is the host the person looking at the board is connected to.
func (s *Server) explainHost(host string) string {
	if host == "" || strings.ContainsAny(host, "*?[") {
		return s.opts.Host
	}
	return host
}

func (s *Server) policyView(id string, broker Broker) policyView {
	schema := broker.Schema()
	view := policyView{Source: id, Short: ui.ShortService(id), Noun: schema.Noun, Title: id}
	for _, svc := range s.opts.Services {
		if meta := svc.Meta(); meta.ID == id {
			view.Title, view.Glyph = meta.Title, meta.Glyph
		}
	}
	view.Schema.Separator, view.Schema.PathLike = schema.Separator, schema.PathLike
	for _, f := range schema.Fields {
		view.Schema.Fields = append(view.Schema.Fields, fieldView{
			Name: f.Name, Label: f.Label, Help: f.Help, Glob: globHelp(schema),
		})
	}
	view.Unmatched = unmatchedOf(broker.Unmatched())
	if err := broker.PolicyErr(); err != nil {
		view.PolicyErr = firstLine(err.Error())
	}
	return view
}

func unmatchedOf(u authz.UnmatchedPolicy) unmatchedView {
	view := unmatchedView{Action: string(u.Action), Level: u.Level}
	if u.Err != nil {
		view.Err = u.Err.Error()
	}
	return view
}

func matchOf(source string, m authz.Matched) matchView {
	view := matchView{Source: source, Decided: m.Decided, Outranked: m.Outranked}
	switch {
	case m.Rule != nil:
		view.Kind, view.ID, view.Origin = "rule", m.Rule.ID, string(m.Rule.Source)
		view.Host, view.Subject, view.Action, view.Note = m.Rule.Host, m.Rule.Subject, string(m.Rule.Action), m.Rule.Note
	case m.Grant != nil:
		view.Kind, view.ID, view.Origin = "grant", m.Grant.ID, "live"
		view.Host, view.Subject, view.Action, view.HostWide = m.Grant.Host, m.Grant.Subject, string(m.Grant.Action), m.Grant.HostWide
	}
	return view
}

// handleExplain answers "what would decide this?", for one of three
// questions: a request (host and subject), a rule (rule=id) or a grant
// (grant=id). It never reads a secret and never makes a signature — it is the
// same lookup a request gets, stopping short of acting on it.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	source := r.URL.Query().Get("source")
	q := r.URL.Query()

	var host, subject string
	var isSelf func(authz.Matched) bool
	var self *matchView
	switch {
	case q.Has("rule"):
		rule, found := broker.Rule(q.Get("rule"))
		if !found {
			http.Error(w, "that rule has changed or gone since this page loaded — reload", http.StatusNotFound)
			return
		}
		host, subject = s.explainHost(rule.Host), rule.Subject
		id := rule.ID
		isSelf = func(m authz.Matched) bool { return m.Rule != nil && m.Rule.ID == id }
		v := matchOf(source, authz.Matched{Rule: &rule})
		self = &v
	case q.Has("grant"):
		id := q.Get("grant")
		var found *authz.Grant
		for _, g := range broker.Grants() {
			if g.ID == id {
				grant := g
				found = &grant
			}
		}
		if found == nil {
			http.Error(w, "that grant has lapsed or been revoked", http.StatusNotFound)
			return
		}
		host, subject = found.Host, found.Subject
		isSelf = func(m authz.Matched) bool { return m.Grant != nil && m.Grant.ID == id }
		v := matchOf(source, authz.Matched{Grant: found})
		self = &v
	default:
		host, subject = strings.TrimSpace(q.Get("host")), strings.TrimSpace(q.Get("subject"))
		if subject == "" {
			http.Error(w, "say what is being asked for: subject is empty", http.StatusBadRequest)
			return
		}
		if host == "" {
			host = s.opts.Host
		}
	}

	x := broker.Explain(host, subject)
	view := explainView{
		Verdict: verdictView{
			Action: string(x.Verdict.Action), Reason: x.Verdict.Reason,
			By: deciderView{
				Kind: string(x.Verdict.By.Kind), RuleID: x.Verdict.By.RuleID, Source: string(x.Verdict.By.Source),
				GrantID: x.Verdict.By.GrantID, Unmatched: string(x.Verdict.By.Unmatched),
			},
		},
		Unmatched: unmatchedOf(x.Unmatched),
		Matches:   []matchView{},
		Self:      self,
	}
	var selfMatch *authz.Matched
	for i, m := range x.Matches {
		view.Matches = append(view.Matches, matchOf(source, m))
		if isSelf != nil && isSelf(m) {
			selfMatch = &x.Matches[i]
		}
	}
	if selfMatch != nil {
		view.Self.Decided, view.Self.Outranked = selfMatch.Decided, selfMatch.Outranked
		selfAction := view.Self.Action
		for _, m := range x.Matches {
			if isSelf(m) {
				continue
			}
			mv := matchOf(source, m)
			switch {
			// What beats it: a deny over an allow. A rule over a grant of the
			// same sense is outranked too, but changes nothing, so it is not
			// listed as something to worry about.
			case selfMatch.Outranked && selfAction == string(authz.ActionAllow) && mv.Action == string(authz.ActionDeny):
				view.BeatenBy = append(view.BeatenBy, mv)
			case selfMatch.Decided && m.Outranked:
				view.Beats = append(view.Beats, mv)
			}
		}
	}
	writeJSON(w, view)
}

// --- rules -------------------------------------------------------------------

// needConfirm refuses a loosening change that does not say it was confirmed.
func needConfirm(w http.ResponseWriter, r *http.Request, what string) bool {
	if r.URL.Query().Get(confirmParam) == "1" {
		return true
	}
	http.Error(w, what+" lets more through — the board asks before doing that (confirm=1)",
		http.StatusPreconditionRequired)
	return false
}

// actionParam reads allow or deny, and nothing else: "ask" is what happens
// when no rule matches, not something a rule can say.
func actionParam(w http.ResponseWriter, r *http.Request) (authz.Action, bool) {
	switch a := authz.Action(r.URL.Query().Get("action")); a {
	case authz.ActionAllow, authz.ActionDeny:
		return a, true
	}
	http.Error(w, "action must be allow or deny", http.StatusBadRequest)
	return "", false
}

// ruleParam finds the rule a request names, refusing a global one: that came
// out of the file the user keeps for every host, and the board does not edit
// it. Refused here, before the store is asked, so that the refusal is the same
// sentence whichever action was attempted.
func ruleParam(w http.ResponseWriter, r *http.Request, broker Broker) (authz.Rule, bool) {
	rule, found := broker.Rule(r.URL.Query().Get("id"))
	if !found {
		ruleError(w, authz.ErrNotFound)
		return authz.Rule{}, false
	}
	if !rule.Editable() {
		ruleError(w, authz.ErrReadOnly)
		return authz.Rule{}, false
	}
	return rule, true
}

// handleAddRule writes a new rule, into devtun's own `remembered:` list.
// An allow loosens and has to be confirmed; a deny only ever tightens.
func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	action, ok := actionParam(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	subject := strings.TrimSpace(q.Get("subject"))
	if subject == "" {
		http.Error(w, "a rule has to match something: subject is empty", http.StatusBadRequest)
		return
	}
	if action == authz.ActionAllow && !needConfirm(w, r, "a new allow") {
		return
	}
	rule, err := broker.AddRule(authz.Rule{
		Host: strings.TrimSpace(q.Get("host")), Subject: subject, Action: action, Note: strings.TrimSpace(q.Get("note")),
	})
	if err != nil {
		ruleError(w, err)
		return
	}
	writeJSON(w, map[string]string{"id": rule.ID, "text": fmt.Sprintf("%s %s — written to this host's file", rule.Action, rule.Subject)})
}

// handleRemoveRule deletes a host or remembered rule. Removing an allow only
// tightens; removing a deny lets through whatever it was refusing, so that one
// asks first — the one-key loosening the old board allowed.
func (s *Server) handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	rule, ok := ruleParam(w, r, broker)
	if !ok {
		return
	}
	if rule.Action == authz.ActionDeny && !needConfirm(w, r, "removing a deny") {
		return
	}
	if err := broker.RemoveRule(rule.ID); err != nil {
		ruleError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleRuleAction turns a rule into an allow or a deny. Towards deny is one
// click; towards allow is the accident deny-beats-allow exists to prevent,
// and it is confirmed. A rule that already says the wanted thing is left as
// it is and reported as done, because it is.
func (s *Server) handleRuleAction(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	action, ok := actionParam(w, r)
	if !ok {
		return
	}
	rule, ok := ruleParam(w, r, broker)
	if !ok {
		return
	}
	if rule.Action == action {
		writeJSON(w, map[string]string{"id": rule.ID})
		return
	}
	if action == authz.ActionAllow && !needConfirm(w, r, "turning a deny into an allow") {
		return
	}
	updated, err := broker.SetRuleAction(rule.ID, action)
	if err != nil {
		ruleError(w, err)
		return
	}
	writeJSON(w, map[string]string{"id": updated.ID})
}

// handleUpdateRule changes what a rule matches, where it applies, or its note.
//
// Any change to the host or the subject is confirmed, whichever way the rule
// points: a wider allow lets more through, and so does a narrower deny, and
// telling wider from narrower for two globs is a question with no reliable
// answer. A note on its own changes nothing a request sees.
func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	rule, ok := ruleParam(w, r, broker)
	if !ok {
		return
	}
	q := r.URL.Query()
	var edit authz.RuleEdit
	changesMatch := false
	if q.Has("host") {
		host := strings.TrimSpace(q.Get("host"))
		edit.Host = &host
		changesMatch = changesMatch || host != rule.Host
	}
	if q.Has("subject") {
		subject := strings.TrimSpace(q.Get("subject"))
		if subject == "" {
			http.Error(w, "a rule has to match something: subject is empty", http.StatusBadRequest)
			return
		}
		edit.Subject = &subject
		changesMatch = changesMatch || subject != rule.Subject
	}
	if q.Has("note") {
		note := strings.TrimSpace(q.Get("note"))
		edit.Note = &note
	}
	if changesMatch && !needConfirm(w, r, "changing what a rule matches") {
		return
	}
	updated, err := broker.UpdateRule(rule.ID, edit)
	if err != nil {
		ruleError(w, err)
		return
	}
	// The ID follows the content, so the page needs the new one to keep the
	// rule selected.
	writeJSON(w, map[string]string{"id": updated.ID})
}

// ruleError maps the store's typed errors onto statuses a page can act on.
func ruleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authz.ErrReadOnly):
		http.Error(w, "that rule is in your config file (config.yaml), which applies to every host — edit it there", http.StatusForbidden)
	case errors.Is(err, authz.ErrNotFound):
		http.Error(w, "that rule has changed since this page loaded — reload", http.StatusConflict)
	case errors.Is(err, authz.ErrUnreadable):
		http.Error(w, "the policy file could not be read, so nothing was written: "+firstLine(err.Error()), http.StatusConflict)
	default:
		http.Error(w, firstLine(err.Error()), http.StatusConflict)
	}
}

// --- grants ------------------------------------------------------------------

// handleAddGrant opens a live grant without a prompt — the form's "lasts 5m /
// this session". An allow is confirmed; a deny is a "stop asking" refusal and
// only tightens.
func (s *Server) handleAddGrant(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	action, ok := actionParam(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	host, subject := strings.TrimSpace(q.Get("host")), strings.TrimSpace(q.Get("subject"))
	if host == "" || strings.ContainsAny(host, "*?[") {
		http.Error(w, "a grant is for one host — name it, or write a rule for every host instead", http.StatusBadRequest)
		return
	}
	if subject == "" {
		http.Error(w, "a grant has to cover something: subject is empty", http.StatusBadRequest)
		return
	}
	seconds, err := strconv.Atoi(q.Get("ttl"))
	ttl := time.Duration(seconds) * time.Second
	if err != nil || seconds < 0 || ttl > maxGrantTTL {
		http.Error(w, "ttl is seconds, 0 for this session, at most a day — anything longer is a rule", http.StatusBadRequest)
		return
	}
	if action == authz.ActionAllow && !needConfirm(w, r, "a new grant") {
		return
	}
	grant, err := broker.AddGrant(authz.GrantSpec{Host: host, Subject: subject, Action: action, TTL: ttl})
	if err != nil {
		ruleError(w, err)
		return
	}
	writeJSON(w, map[string]string{"id": grant.ID})
}

// handleRevokeGrant takes back one live grant by its ID. Revoking an allow
// only tightens; revoking a "stop asking" refusal means the next request is
// asked about — or let through by an allow beneath it — so that one asks.
func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("id")
	for _, g := range broker.Grants() {
		if g.ID == id && g.Action == authz.ActionDeny && !needConfirm(w, r, "removing a refusal") {
			return
		}
	}
	if !broker.RevokeGrant(id) {
		http.Error(w, "that grant has already lapsed", http.StatusConflict)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleForget drops every live allow grant and every cached secret value,
// across every broker. Refusals stay: dropping "No, and stop asking" would let
// an allow underneath win again, which is the opposite of what somebody
// reaching for this wants. The counts come back so the page can say what went,
// "nothing" included.
func (s *Server) handleForget(w http.ResponseWriter, _ *http.Request) {
	grants, cached := s.forgetAll()
	writeJSON(w, map[string]int{"grants": grants, "cached": cached})
}

// forgetAll sweeps the brokers and reports what it took, in the same two
// numbers the interface shows.
func (s *Server) forgetAll() (grants, cached int) {
	for _, gated := range s.brokers() {
		switch b := gated.broker.(type) {
		case Forgetter:
			g, c := b.Forget()
			grants, cached = grants+g, cached+c
		case cachelessForgetter:
			grants += b.Forget()
		default:
			grants += b.ForgetGrants()
		}
	}
	return grants, cached
}

// handleForgetRefusals drops every live refusal, in every broker. It is a
// separate action from forgetting grants because it loosens, and it is
// confirmed.
func (s *Server) handleForgetRefusals(w http.ResponseWriter, r *http.Request) {
	if !needConfirm(w, r, "forgetting refusals") {
		return
	}
	n := 0
	for _, gated := range s.brokers() {
		n += gated.broker.ForgetRefusals()
	}
	writeJSON(w, map[string]int{"refusals": n})
}
