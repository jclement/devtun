// Package policy decides whether a remote host may have a particular secret.
//
// There are two layers. Persistent *rules* are the ones the user can read, edit
// and audit; they are what "always allow" writes. Temporary *grants* live only
// in the running process and expire, which is what "allow for five minutes"
// creates. Everything not covered by either falls through to a prompt.
//
// Rules themselves come from two places — the global set in the user's config
// and the per-host set devtun writes when a prompt is answered "always" — and
// the store treats them as one list. That matters because deny always beats
// allow, and it has to beat it across both sets or a global block could be
// undone by a per-host approval. A persistent deny also beats a live grant, so
// a rule added to block something cannot be undone by clicking through a
// prompt.
package authz

import (
	"fmt"
	"sort"
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

// Rule is one persistent policy entry. Host and Subject are globs (see Match).
// The YAML tags are load-bearing: per-host rules are round-tripped through the
// host's config document, and the global ones are read straight out of the
// user's config file by the caller that builds the service.
type Rule struct {
	Host    string    `yaml:"host"`
	Subject string    `yaml:"subject"`
	Action  Action    `yaml:"action"`
	Note    string    `yaml:"note,omitempty"`
	Added   time.Time `yaml:"added,omitempty"`
}

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
	// Rules are the global rules, applying to every host.
	Rules []Rule
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
}

// grant is an allowance created by answering a prompt. A zero expires means
// "for the rest of this session": it never times out, but it lives only in this
// process, so quitting devtun revokes it. That is the middle ground between a
// five-minute grant and a rule written to disk.
type grant struct {
	host    string
	subject string
	expires time.Time
}

// live reports whether the grant still applies.
func (g grant) live(now time.Time) bool {
	return g.expires.IsZero() || now.Before(g.expires)
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
	Host    string
	Subject string
	// Expires is zero for a grant that lasts as long as devtun runs.
	Expires time.Time
	// HostWide reports a grant covering everything from a host rather than one
	// secret, which is the kind worth showing differently.
	HostWide bool
}

// Grants lists what is currently allowed by a prompt rather than by a rule,
// dropping any that have lapsed.
func (s *Store) Grants() []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var out []Grant
	for _, g := range s.grants {
		if !g.live(now) {
			continue
		}
		out = append(out, Grant{
			Host: g.host, Subject: g.subject, Expires: g.expires,
			HostWide: g.subject == HostWildcard,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// RevokeGrant drops one live grant, reporting whether it found it. Revoking a
// grant you can see is the counterpart to being able to see it at all.
func (s *Store) RevokeGrant(host, subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, g := range s.grants {
		if g.host == host && g.subject == subject {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			return true
		}
	}
	return false
}

// Saver writes a host's rules back to wherever they are kept. It is an
// interface because the store has no business knowing: in devtun they go into
// the host's own config document, and a nil Saver is a store that keeps its
// rules in memory only, which is what tests use.
type Saver interface {
	SaveRules(rules []Rule) error
}

// Store holds the loaded policy and the live grants. It is safe for concurrent
// use: several shim connections can be in flight at once.
type Store struct {
	mu        sync.Mutex
	config    Config
	hostRules []Rule
	saver     Saver
	grants    []grant
}

// NewStore returns a store for the given configuration, filling in the
// durations the caller left at zero.
func NewStore(config Config) *Store {
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = defaultTTL
	}
	if config.PromptTimeout <= 0 {
		config.PromptTimeout = defaultPromptTimeout
	}
	return &Store{config: config}
}

// AdoptHostRules installs the rules already recorded for the host this store is
// serving, and the saver that writes new ones back. The store is built before
// any connection exists — grants outlive every one of them — so the per-host
// half arrives here rather than in the constructor.
func (s *Store) AdoptHostRules(rules []Rule, saver Saver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostRules = rules
	s.saver = saver
}

// Config returns a copy of the configuration.
func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

// Decide evaluates host and subject against the rules and live grants.
func (s *Store) Decide(host, subject string) Verdict {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Denies first, across both rule sets, so neither can be used to escape the
	// other. Only then allows, and only then the grants a prompt created.
	for _, rule := range s.allRulesLocked() {
		if rule.Action == ActionDeny && ruleMatches(rule, host, subject) {
			return Verdict{Action: ActionDeny, Reason: fmt.Sprintf("denied by rule %s → %s", rule.Host, rule.Subject)}
		}
	}
	for _, rule := range s.allRulesLocked() {
		if rule.Action == ActionAllow && ruleMatches(rule, host, subject) {
			return Verdict{Action: ActionAllow, Reason: fmt.Sprintf("allowed by rule %s → %s", rule.Host, rule.Subject)}
		}
	}

	now := time.Now()
	for _, g := range s.grants {
		if g.host != host || !g.live(now) || !Match(g.subject, subject) {
			continue
		}
		scope := "grant"
		if g.subject == HostWildcard {
			scope = "host grant"
		}
		if g.expires.IsZero() {
			return Verdict{Action: ActionAllow, Reason: scope + ", this session"}
		}
		return Verdict{
			Action: ActionAllow,
			Reason: fmt.Sprintf("%s, %s left", scope, time.Until(g.expires).Round(time.Second)),
			Until:  g.expires,
		}
	}

	return Verdict{Action: ActionAsk, Reason: "no matching rule"}
}

// allRulesLocked is the global set followed by the host's own. Order within a
// pass is immaterial — every rule of the matching action is tried — so this
// only has to be stable.
func (s *Store) allRulesLocked() []Rule {
	all := make([]Rule, 0, len(s.config.Rules)+len(s.hostRules))
	all = append(all, s.config.Rules...)
	all = append(all, s.hostRules...)
	return all
}

func ruleMatches(rule Rule, host, subject string) bool {
	hostPattern := rule.Host
	if hostPattern == "" {
		hostPattern = HostWildcard
	}
	return Match(hostPattern, host) && Match(rule.Subject, subject)
}

// GrantTemporary allows subject from host until the TTL expires. A subject of
// HostWildcard grants everything from that host.
func (s *Store) GrantTemporary(host, subject string, ttl time.Duration) {
	s.addGrant(grant{host: host, subject: subject, expires: time.Now().Add(ttl)})
}

// GrantSession allows subject from host for as long as this process runs.
// Nothing is written to disk, so quitting is how it is revoked.
func (s *Store) GrantSession(host, subject string) {
	s.addGrant(grant{host: host, subject: subject})
}

func (s *Store) addGrant(g grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.grants = append(s.grants, g)
}

// GrantPermanent appends an allow rule to the host's own set and persists it.
func (s *Store) GrantPermanent(host, subject, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostRules = append(s.hostRules, Rule{
		Host:    host,
		Subject: subject,
		Action:  ActionAllow,
		Note:    note,
		Added:   time.Now().UTC().Truncate(time.Second),
	})
	return s.saveLocked()
}

// Rules returns a copy of the host's own rules — the ones devtun wrote and can
// take back. The global rules are the user's file to edit.
func (s *Store) Rules() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Rule, len(s.hostRules))
	copy(out, s.hostRules)
	return out
}

// Revoke removes the host rule at index (as printed by Rules) and persists the
// remainder.
func (s *Store) Revoke(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.hostRules) {
		return fmt.Errorf("no rule at index %d (there are %d)", index, len(s.hostRules))
	}
	s.hostRules = append(s.hostRules[:index], s.hostRules[index+1:]...)
	return s.saveLocked()
}

// ForgetGrants drops every live grant, which is the "lock it back up" action.
func (s *Store) ForgetGrants() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.grants)
	s.grants = nil
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

func (s *Store) saveLocked() error {
	if s.saver == nil {
		return nil // in-memory store, used by tests
	}
	out := make([]Rule, len(s.hostRules))
	copy(out, s.hostRules)
	return s.saver.SaveRules(out)
}
