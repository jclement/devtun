// Package authz decides whether a remote host may have a particular secret,
// signature or site.
//
// There are two layers. Persistent *rules* are the ones the user can read, edit
// and audit; they are what "always allow" writes. Temporary *grants* live only
// in the running process and expire, which is what "allow for five minutes"
// creates. Everything not covered by either falls through to the broker's
// *unmatched* policy: ask a human (the default), or refuse.
//
// Rules come from three places — the global config, the host file's own
// `rules:`, and the `remembered:` list devtun writes beside it — and the store
// treats them as one list. That matters because deny always beats allow, and it
// has to beat it across every list or a global block could be undone by a
// per-host approval. A persistent deny also beats a live grant, so a rule added
// to block something cannot be undone by clicking through a prompt.
package authz

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Action is the outcome of matching a request against the policy.
type Action string

const (
	// ActionAllow runs the command without asking.
	ActionAllow Action = "allow"
	// ActionDeny refuses without asking.
	ActionDeny Action = "deny"
	// ActionAsk defers to the human.
	ActionAsk Action = "ask"
)

// HostWildcard is the subject pattern a host-wide grant uses.
const HostWildcard = "**"

const (
	defaultTTL           = 5 * time.Minute
	defaultPromptTimeout = 2 * time.Minute
)

// Config is everything the store and the guard need to know that does not
// change while the process runs. It is passed in rather than read from a file,
// because where these settings live is the caller's business.
type Config struct {
	// DefaultTTL is how long a "for a while" grant lasts.
	DefaultTTL time.Duration
	// PromptTimeout bounds how long a request waits for a human. A shim call
	// that hangs forever is worse than one that fails, because it stalls
	// whatever script made it.
	PromptTimeout time.Duration
	// Rules are the global rules, applying to every host. Once a host's
	// config is adopted they are re-read from the global file as it changes;
	// these are what applies before that, and in tests.
	Rules []Rule
	// Schema is what this broker's subjects are made of. Zero means one
	// path-like field.
	Schema Schema
}

// Decider is what settled a verdict.
//
// The verdict used to carry only a sentence, built from the rule that matched
// and then thrown away. That sentence could not say which file the rule was in,
// and nothing could jump from a refusal in the Activity log to the rule that
// refused it, or count how often a rule decides anything. Carrying the identity
// costs a struct.
type Decider struct {
	Kind DeciderKind
	// RuleID and Source name the rule, for ByRule.
	RuleID string
	Source Source
	// GrantID names the grant, for ByGrant.
	GrantID string
	// Unmatched is what the unmatched policy said, for ByUnmatched: ask or
	// deny.
	Unmatched Action
}

// DeciderKind says which kind of thing decided.
type DeciderKind string

const (
	ByRule  DeciderKind = "rule"
	ByGrant DeciderKind = "grant"
	// ByUnmatched is nothing matching: the broker's unmatched policy decided.
	ByUnmatched DeciderKind = "unmatched"
	// ByUnreadable is a policy file that could not be read. Everything is
	// refused until it can be.
	ByUnreadable DeciderKind = "unreadable"
	// ByPrompt is a human answering. Only a broker's Asked carries it.
	ByPrompt DeciderKind = "prompt"
	// ByTimeout is nobody answering in time. Only a broker's Asked carries it.
	ByTimeout DeciderKind = "timeout"
)

// Fields renders the decider as event fields, so every broker's Activity
// record says what decided in the same words.
func (d Decider) Fields() []any {
	if d.Kind == "" {
		return nil
	}
	out := []any{"by", string(d.Kind)}
	if d.RuleID != "" {
		out = append(out, "rule", d.RuleID, "source", string(d.Source))
	}
	if d.GrantID != "" {
		out = append(out, "grant", d.GrantID)
	}
	if d.Unmatched != "" {
		out = append(out, "unmatched", string(d.Unmatched))
	}
	return out
}

// Verdict is the result of a policy lookup, carrying the reason so the log can
// explain itself.
type Verdict struct {
	Action Action
	Reason string
	// Until is when the authorisation lapses, or the zero time if it does not
	// lapse on its own (a rule, or a session grant). Callers that hold on to
	// anything derived from an allowed request — a cached secret, say — must
	// not keep it past this.
	Until time.Time
	// By is what decided.
	By Decider
}

// grant is an allowance created by answering a prompt. A zero expires means
// "for the rest of this session": it never times out, but it lives only in this
// process, so quitting devtun revokes it. That is the middle ground between a
// five-minute grant and a rule written to disk.
type grant struct {
	id      string
	host    string
	subject string
	expires time.Time
	created time.Time
	// action is what answering the prompt decided. A grant can refuse as well
	// as allow: "no, and stop asking this session" is a real answer, and
	// without it the only way to stop being asked about something you keep
	// declining is to approve it.
	action Action
}

// live reports whether the grant still applies.
func (g grant) live(now time.Time) bool {
	return g.expires.IsZero() || now.Before(g.expires)
}

func (g grant) public() Grant {
	return Grant{
		ID: g.id, Host: g.host, Subject: g.subject, Action: g.action,
		Expires: g.expires, Created: g.created, HostWide: g.subject == HostWildcard,
	}
}

// Grant is a live allowance, for something that wants to show or revoke one.
//
// The store keeps grants unexported because nothing outside should be able to
// forge one; this is a read-only copy of what it is holding, taken so that a
// user interface can say what access is currently open in their name. That
// sounds like a nicety and is not: a "allow anything from bedev for 5 minutes"
// is the single most consequential piece of state in the process, and until it
// could be listed the only thing anyone could do about it was drop every grant
// at once.
type Grant struct {
	// ID is stable for the life of the process, and never reused.
	ID      string
	Host    string
	Subject string
	// Action is what this grant decided. A refusal is as much live state as an
	// approval, and showing only the approvals would make the Access tab
	// answer "what is open" while quietly omitting "what is shut".
	Action Action
	// Expires is zero for a grant that lasts as long as devtun runs.
	Expires time.Time
	Created time.Time
	// HostWide reports a grant covering everything from a host rather than one
	// subject, which is the kind worth showing differently.
	HostWide bool
}

// GrantSpec is a grant to create from the interface rather than a prompt.
type GrantSpec struct {
	Host    string
	Subject string
	// Action is allow, or deny for a "stop asking".
	Action Action
	// TTL is how long it lasts; zero is for this session.
	TTL time.Duration
}

// Store holds the policy and the live grants. It is safe for concurrent use:
// several shim connections can be in flight at once.
type Store struct {
	mu     sync.Mutex
	config Config
	book   RuleBook

	// cached is the last Load, valid while the book's revision is unchanged.
	// Loading means decoding YAML, and the interface asks for the rules twice a
	// second per broker; the decision path asks on every request.
	cached struct {
		valid    bool
		revision uint64
		loaded   Loaded
		err      error
	}

	grants    []grant
	nextGrant int
	// edits counts changes the book's revision does not: grants made, revoked
	// and forgotten, and books swapped.
	edits uint64
}

// NewStore returns a store for the given configuration, filling in the
// durations the caller left at zero. Until AdoptBook is called its host rules
// live in memory.
func NewStore(config Config) *Store {
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = defaultTTL
	}
	if config.PromptTimeout <= 0 {
		config.PromptTimeout = defaultPromptTimeout
	}
	config.Schema = config.Schema.withDefaults()
	return &Store{
		config: config,
		book:   &memoryBook{loaded: Loaded{Global: append([]Rule(nil), config.Rules...)}},
	}
}

// AdoptBook installs where this store's rules are written down. The store is
// built before any connection exists — grants outlive every one of them — so
// the rule book arrives here rather than in the constructor.
func (s *Store) AdoptBook(book RuleBook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Carry the old book's count forward so Revision never goes backwards.
	s.edits += s.book.Revision() + 1
	s.book = book
	s.cached.valid = false
}

// Config returns a copy of the configuration.
func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

// Schema is what this store's subjects are made of.
func (s *Store) Schema() Schema {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config.Schema
}

// loadLocked returns the rules as they are now, IDs assigned. The caller
// holds s.mu.
func (s *Store) loadLocked() (Loaded, error) {
	rev := s.book.Revision()
	if s.cached.valid && s.cached.revision == rev {
		return s.cached.loaded, s.cached.err
	}
	loaded, err := s.book.Load()
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	loaded.Global = assignIDs(SourceGlobal, loaded.Global)
	loaded.Host = assignIDs(SourceHost, loaded.Host)
	loaded.Remembered = assignIDs(SourceRemembered, loaded.Remembered)
	s.cached.valid, s.cached.revision, s.cached.loaded, s.cached.err = true, rev, loaded, err
	return loaded, err
}

// allRules is the one ordered list: global, then the host's own, then what
// devtun remembered. Order within a pass is immaterial to the verdict — every
// rule of the matching action is tried — but it is the order an explanation
// lists them in, so it has to be stable.
func allRules(l Loaded) []Rule {
	out := make([]Rule, 0, len(l.Global)+len(l.Host)+len(l.Remembered))
	out = append(out, l.Global...)
	out = append(out, l.Host...)
	return append(out, l.Remembered...)
}

// PolicyErr reports a policy file that cannot be read. While it is non-nil
// every request is refused.
func (s *Store) PolicyErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.loadLocked()
	return err
}

// Revision changes whenever the rules or grants change, including a hand edit
// to a rule file picked up from disk. An interface compares it to know when
// what it is showing is stale.
func (s *Store) Revision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.book.Revision() + s.edits
}

// UnmatchedPolicy is what happens to a request nothing matches.
type UnmatchedPolicy struct {
	// Action is ActionAsk or ActionDeny.
	Action Action
	// Level is which file said so: "host", "global" or "default".
	Level string
	// Err is a value that is neither ask nor deny. Action is then deny: a
	// typo in the setting that makes an allowlist must not open it.
	Err error
}

// Unmatched reports the effective unmatched policy.
func (s *Store) Unmatched() UnmatchedPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded, _ := s.loadLocked()
	return unmatchedOf(loaded)
}

func unmatchedOf(l Loaded) UnmatchedPolicy {
	value := strings.ToLower(strings.TrimSpace(l.Unmatched))
	switch value {
	case "":
		return UnmatchedPolicy{Action: ActionAsk, Level: "default"}
	case string(ActionAsk):
		return UnmatchedPolicy{Action: ActionAsk, Level: l.UnmatchedLevel}
	case string(ActionDeny):
		return UnmatchedPolicy{Action: ActionDeny, Level: l.UnmatchedLevel}
	}
	return UnmatchedPolicy{
		Action: ActionDeny, Level: l.UnmatchedLevel,
		Err: fmt.Errorf("unmatched: %q is neither ask nor deny, so it is read as deny", l.Unmatched),
	}
}

// Matched is one rule or grant that matched a request, in an Explanation.
type Matched struct {
	// Exactly one of Rule and Grant is set.
	Rule  *Rule
	Grant *Grant
	// Decided marks the one that settled the verdict.
	Decided bool
	// Outranked marks one that matched and did not decide, because something
	// earlier in evaluation order did: an allow under a matching deny, or a
	// grant under a rule of the same sense.
	Outranked bool
}

// Explanation is a verdict with its working shown.
type Explanation struct {
	Verdict Verdict
	// Matches is every rule and grant that matched, in evaluation order: deny
	// rules, deny grants, allow rules, allow grants.
	Matches   []Matched
	Unmatched UnmatchedPolicy
}

// Decide evaluates host and subject against the rules and live grants.
func (s *Store) Decide(host, subject string) Verdict {
	return s.Explain(host, subject).Verdict
}

// Explain is Decide with every rule and grant that matched, marked with which
// one decided. It is the same evaluation, not a re-creation of it, so the test
// box and the "why?" view cannot disagree with what a real request got.
func (s *Store) Explain(host, subject string) Explanation {
	s.mu.Lock()
	defer s.mu.Unlock()

	loaded, err := s.loadLocked()
	if err != nil {
		// Fail closed, and completely. A broken file might be the one holding
		// the deny that matters, and acting on the rest of the policy would be
		// acting on a policy nobody wrote.
		return Explanation{Verdict: Verdict{
			Action: ActionDeny,
			Reason: "refused: " + err.Error(),
			By:     Decider{Kind: ByUnreadable},
		}, Unmatched: unmatchedOf(loaded)}
	}

	// Refusals first — every refusal, written down or clicked through — then
	// approvals. Deny wins over allow at every level.
	//
	// It would be tidier to say "persistent beats live" and let a standing
	// allow rule override a session refusal. It would also be wrong. If I have
	// a rule allowing a whole vault and then answer "no, stop asking" for one
	// secret in it, the most recent and most specific thing I said was no; a
	// policy that quietly kept allowing it would be answering a question I did
	// not ask. Among decisions of the *same* sense, persistent still wins,
	// which is why rules are consulted before grants within each pass.
	var matches []Matched
	rules := allRules(loaded)
	now := time.Now()
	for _, pass := range []Action{ActionDeny, ActionAllow} {
		for i := range rules {
			if rules[i].Action == pass && s.ruleMatches(rules[i], host, subject) {
				r := rules[i]
				matches = append(matches, Matched{Rule: &r})
			}
		}
		for _, g := range s.grants {
			if !g.live(now) || g.host != host || !s.subjectMatches(g.action, g.subject, subject) {
				continue
			}
			if (pass == ActionDeny) != (g.action == ActionDeny) {
				continue
			}
			pg := g.public()
			matches = append(matches, Matched{Grant: &pg})
		}
	}

	unmatched := unmatchedOf(loaded)
	out := Explanation{Matches: matches, Unmatched: unmatched}
	if len(matches) == 0 {
		out.Verdict = Verdict{
			Action: unmatched.Action,
			Reason: "no matching rule",
			By:     Decider{Kind: ByUnmatched, Unmatched: unmatched.Action},
		}
		if unmatched.Action == ActionDeny {
			out.Verdict.Reason = "no rule allows it, and unmatched requests are refused"
		}
		return out
	}
	for i := range matches {
		matches[i].Outranked = i > 0
	}
	matches[0].Decided = true
	out.Verdict = verdictOf(matches[0], now)
	return out
}

// verdictOf turns the deciding match into a verdict.
func verdictOf(m Matched, now time.Time) Verdict {
	if r := m.Rule; r != nil {
		verb := "allowed"
		if r.Action == ActionDeny {
			verb = "denied"
		}
		// The host is spelled out even when the rule left it empty, and the
		// subject is quoted rather than joined to the host with an arrow,
		// because an SSH subject already contains one: "denied by rule  → ** →
		// **" was an empty host and two arrows, and read as nothing at all.
		return Verdict{
			Action: r.Action,
			Reason: fmt.Sprintf("%s by rule %q (%s, %s)", verb, r.Subject, sourceWords(r.Source), hostWords(r.HostPattern())),
			By:     Decider{Kind: ByRule, RuleID: r.ID, Source: r.Source},
		}
	}

	g := m.Grant
	by := Decider{Kind: ByGrant, GrantID: g.ID}
	if g.Action == ActionDeny {
		if g.Expires.IsZero() {
			return Verdict{Action: ActionDeny, Reason: "refused for this session", By: by}
		}
		return Verdict{
			Action: ActionDeny, By: by,
			Reason: fmt.Sprintf("refused, %s left", g.Expires.Sub(now).Round(time.Second)),
		}
	}
	scope := "grant"
	if g.HostWide {
		scope = "host grant"
	}
	if g.Expires.IsZero() {
		return Verdict{Action: ActionAllow, Reason: scope + ", this session", By: by}
	}
	return Verdict{
		Action: ActionAllow, By: by, Until: g.Expires,
		Reason: fmt.Sprintf("%s, %s left", scope, g.Expires.Sub(now).Round(time.Second)),
	}
}

func sourceWords(s Source) string {
	switch s {
	case SourceGlobal:
		return "global config"
	case SourceHost:
		return "host file"
	default:
		return "remembered"
	}
}

func hostWords(pattern string) string {
	if pattern == HostWildcard {
		return "every host"
	}
	return "host " + pattern
}

func (s *Store) ruleMatches(rule Rule, host, subject string) bool {
	return Match(rule.HostPattern(), host) && s.subjectMatches(rule.Action, rule.Subject, subject)
}

// subjectMatches is the schema's match for a rule or grant of the given action:
// an allow goes through Schema.Allows, so a value the schema marks Literal is
// approved only by a pattern that names it; a deny matches as written.
func (s *Store) subjectMatches(action Action, pattern, subject string) bool {
	if action == ActionAllow {
		return s.config.Schema.Allows(pattern, subject)
	}
	return s.config.Schema.Match(pattern, subject)
}

// Rules is every rule — global, the host's own, then remembered — IDs and
// sources filled in. A file that cannot be read contributes nothing; PolicyErr
// says why.
func (s *Store) Rules() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded, _ := s.loadLocked()
	return allRules(loaded)
}

// Rule finds one rule by ID.
func (s *Store) Rule(id string) (Rule, bool) {
	for _, r := range s.Rules() {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// AddRule records a new rule in the remembered list and returns it as stored.
// Its Added stamp is filled in if the caller left it zero.
func (s *Store) AddRule(r Rule) (Rule, error) {
	if r.Action != ActionAllow && r.Action != ActionDeny {
		return Rule{}, fmt.Errorf("a rule allows or denies; %q is neither", r.Action)
	}
	if strings.TrimSpace(r.Subject) == "" {
		return Rule{}, errors.New("a rule needs a subject")
	}
	if r.Added.IsZero() {
		r.Added = time.Now().UTC().Truncate(time.Second)
	}
	r.ID, r.Source = "", ""

	var stored Rule
	err := s.edit(SourceRemembered, func(rules []Rule) ([]Rule, error) {
		rules = append(rules, r)
		stored = assignIDs(SourceRemembered, rules)[len(rules)-1]
		return rules, nil
	})
	return stored, err
}

// RemoveRule deletes one rule.
func (s *Store) RemoveRule(id string) error {
	return s.editByID(id, func(Rule) (*Rule, error) { return nil, nil })
}

// SetRuleAction turns a rule into an allow or a deny, keeping its subject and
// note.
//
// Either direction. Turning a deny into an allow is loosening, and the confirm
// that should stand in front of it belongs to the interface, which knows there
// is a person to ask; the store's job is to do what it is told, exactly, to the
// rule it was told.
func (s *Store) SetRuleAction(id string, action Action) (Rule, error) {
	if action != ActionAllow && action != ActionDeny {
		return Rule{}, fmt.Errorf("a rule allows or denies; %q is neither", action)
	}
	return s.updateByID(id, func(r *Rule) {
		if r.Action != action {
			r.Action = action
			r.Added = time.Now().UTC().Truncate(time.Second)
		}
	})
}

// RuleEdit is a change to a rule's text. A nil field is left as it is.
type RuleEdit struct {
	Host    *string
	Subject *string
	Note    *string
}

// UpdateRule changes a rule's host, subject or note. The rule's ID changes with
// its content; the returned rule carries the new one.
func (s *Store) UpdateRule(id string, e RuleEdit) (Rule, error) {
	if e.Subject != nil && strings.TrimSpace(*e.Subject) == "" {
		return Rule{}, errors.New("a rule needs a subject")
	}
	return s.updateByID(id, func(r *Rule) {
		if e.Host != nil {
			r.Host = *e.Host
		}
		if e.Subject != nil {
			r.Subject = *e.Subject
		}
		if e.Note != nil {
			r.Note = *e.Note
		}
	})
}

func (s *Store) updateByID(id string, change func(*Rule)) (Rule, error) {
	var updated Rule
	err := s.editByID(id, func(r Rule) (*Rule, error) {
		change(&r)
		return &r, nil
	}, func(r Rule) { updated = r })
	if err != nil {
		return Rule{}, err
	}
	return updated, nil
}

// editByID finds a rule by ID in the list it belongs to — as that list is on
// disk now — and replaces it with what change returns, or removes it for nil.
//
// result, when given, receives the edited rule as it will be stored — its ID
// computed at its own position in the list being written, inside the same
// transaction. Recovering it afterwards by searching for a rule with the same
// content found the first of two identical rules, not necessarily the one
// edited, and a later remove by that ID took out the other.
func (s *Store) editByID(id string, change func(Rule) (*Rule, error), result ...func(Rule)) error {
	source, err := s.sourceOf(id)
	if err != nil {
		return err
	}
	return s.edit(source, func(rules []Rule) ([]Rule, error) {
		for i, r := range rules {
			if r.ID != id {
				continue
			}
			next, err := change(r)
			if err != nil {
				return nil, err
			}
			if next == nil {
				return append(rules[:i:i], rules[i+1:]...), nil
			}
			out := append([]Rule(nil), rules...)
			out[i] = *next
			for _, report := range result {
				report(assignIDs(source, out)[i])
			}
			return out, nil
		}
		return nil, ErrNotFound
	})
}

// sourceOf works out which list an ID is in. Global IDs are refused here,
// which is the one place ErrReadOnly comes from.
func (s *Store) sourceOf(id string) (Source, error) {
	r, ok := s.Rule(id)
	switch {
	case !ok:
		return "", ErrNotFound
	case !r.Editable():
		return "", ErrReadOnly
	}
	return r.Source, nil
}

// edit runs one transaction against the rule book and drops the cache.
func (s *Store) edit(source Source, change func([]Rule) ([]Rule, error)) error {
	s.mu.Lock()
	book := s.book
	// No writes while any of the policy cannot be read. The edit touches one
	// list, but the person deciding what to add is looking at a policy that is
	// not the one in force, and a remembered rule written beside a broken
	// hand-written list is a decision made blind.
	_, loadErr := s.loadLocked()
	s.mu.Unlock()
	if loadErr != nil {
		return loadErr
	}

	err := book.Edit(source, func(rules []Rule) ([]Rule, error) {
		// Strip what is derived before it is written: the book stores rules,
		// and IDs and sources are worked out on the way back in.
		next, err := change(rules)
		for i := range next {
			next[i].ID, next[i].Source = "", ""
		}
		return next, err
	})

	s.mu.Lock()
	s.cached.valid = false
	s.mu.Unlock()
	return err
}

// Grants lists what is currently allowed or refused by a prompt rather than by
// a rule, dropping any that have lapsed. Oldest first.
func (s *Store) Grants() []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var out []Grant
	for _, g := range s.grants {
		if g.live(now) {
			out = append(out, g.public())
		}
	}
	return out
}

// RevokeGrant drops one live grant, reporting whether it found it.
//
// By ID, and only a live one. It used to be by host and subject, and found the
// first grant with that pair — which, once a five-minute grant had lapsed and
// been granted again, was the lapsed one. The revoke "succeeded", the live
// grant carried on, and the screen said it was gone.
func (s *Store) RevokeGrant(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for i, g := range s.grants {
		if g.id == id && g.live(now) {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			s.edits++
			return true
		}
	}
	return false
}

// AddGrant creates a grant from the interface, for something a person wants
// open (or shut) before it is asked for.
func (s *Store) AddGrant(spec GrantSpec) (Grant, error) {
	if spec.Action != ActionAllow && spec.Action != ActionDeny {
		return Grant{}, fmt.Errorf("a grant allows or refuses; %q is neither", spec.Action)
	}
	if strings.TrimSpace(spec.Host) == "" || strings.TrimSpace(spec.Subject) == "" {
		return Grant{}, errors.New("a grant needs a host and a subject")
	}
	if spec.TTL < 0 {
		return Grant{}, errors.New("a grant cannot last a negative time")
	}
	g := grant{host: spec.Host, subject: spec.Subject, action: spec.Action}
	if spec.TTL > 0 {
		g.expires = time.Now().Add(spec.TTL)
	}
	return s.addGrant(g).public(), nil
}

// GrantTemporary allows subject from host until the TTL expires. A subject of
// HostWildcard grants everything from that host.
func (s *Store) GrantTemporary(host, subject string, ttl time.Duration) {
	s.addGrant(grant{host: host, subject: subject, expires: time.Now().Add(ttl), action: ActionAllow})
}

// GrantSession allows subject from host for as long as this process runs.
// Nothing is written to disk, so quitting is how it is revoked.
func (s *Store) GrantSession(host, subject string) {
	s.addGrant(grant{host: host, subject: subject, action: ActionAllow})
}

// RefuseSession refuses subject from host for as long as this process runs.
//
// It is the answer to "no, and stop asking", which the menu lacked entirely:
// the only way to stop being asked about something you keep declining was to
// approve it, which is a poor thing for a security prompt to teach. Nothing is
// written to disk, so quitting undoes it.
func (s *Store) RefuseSession(host, subject string) {
	s.addGrant(grant{host: host, subject: subject, action: ActionDeny})
}

func (s *Store) addGrant(g grant) grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.nextGrant++
	g.id = fmt.Sprintf("g%d", s.nextGrant)
	g.created = time.Now()
	s.grants = append(s.grants, g)
	s.edits++
	return g
}

// RefusePermanent records a deny rule for the host, in the remembered list.
//
// This is "never", and it is meant to be hard to undo by accident: a deny beats
// every allow, including one clicked through later. The way back is to remove
// it on the Access tab, behind a confirm, or edit the file.
func (s *Store) RefusePermanent(host, subject, note string) error {
	_, err := s.AddRule(Rule{Host: host, Subject: subject, Action: ActionDeny, Note: note})
	return err
}

// GrantPermanent records an allow rule for the host, in the remembered list.
func (s *Store) GrantPermanent(host, subject, note string) error {
	_, err := s.AddRule(Rule{Host: host, Subject: subject, Action: ActionAllow, Note: note})
	return err
}

// ForgetGrants drops every live *allow* grant — the "lock it back up" action.
//
// Refusals survive it. They used to go too, which made the panic button reopen
// every question somebody had closed with "no, and stop asking": the one
// action meant to tighten everything loosened something. ForgetRefusals is the
// separate, deliberate way to drop those.
func (s *Store) ForgetGrants() int {
	return s.forget(func(g grant) bool { return g.action != ActionDeny })
}

// ForgetRefusals drops every live refusal ("stop asking" grants).
func (s *Store) ForgetRefusals() int {
	return s.forget(func(g grant) bool { return g.action == ActionDeny })
}

func (s *Store) forget(drop func(grant) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	kept := s.grants[:0]
	n := 0
	for _, g := range s.grants {
		if drop(g) {
			n++
			continue
		}
		kept = append(kept, g)
	}
	s.grants = kept
	if n > 0 {
		s.edits++
	}
	return n
}

func (s *Store) pruneLocked() {
	now := time.Now()
	kept := s.grants[:0]
	for _, g := range s.grants {
		if g.live(now) {
			kept = append(kept, g)
		}
	}
	s.grants = kept
}
