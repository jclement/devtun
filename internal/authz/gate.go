package authz

import (
	"context"
	"fmt"
	"sync"

	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// rulesKey is where a service's own rules live in its slice of the host's
// config document. Every gated service uses the same key, in its own namespace.
const rulesKey = "rules"

// Gate is everything a service needs to put a human in front of a capability:
// the policy store, the prompter, the broker that runs the sequence, and the
// ritual of picking up a host's own rules the first time it attaches.
//
// It exists because four services now want exactly this and disagree about
// only one thing — what a *subject* is. The vault's subjects are `op://`
// references, the agent's are a key and a destination, the browser's are sites,
// the tunnels service's are ports. Everything else was, and had begun to drift
// as, a near-copy: the fix for an answer racing the prompt deadline went into
// one of them and had to be carried to the other by hand.
//
// A Gate is safe to construct for a host that turns out not to support the
// service. It touches no file and asks nobody anything until Authorize.
type Gate struct {
	store    *Store
	prompter prompt.Prompter

	mu      sync.Mutex
	adopted bool
}

// NewGate builds the apparatus. A nil prompter means nobody can be asked, which
// refuses everything policy does not already allow — the zero value of a
// decision is no.
func NewGate(config Config, prompter prompt.Prompter) *Gate {
	if prompter == nil {
		prompter = prompt.DenyAll{}
	}
	return &Gate{store: NewStore(config), prompter: prompt.Serialize(prompter)}
}

// SetPrompter replaces how approvals are asked for.
//
// It exists because the interface's modal cannot be constructed until the
// Bubble Tea program is, which is after every service. Without it the nil
// substitution in NewGate would be permanent, and every request under the
// interface would be refused with no way to say yes — which is exactly how the
// SSH agent shipped broken once already.
//
// Call it before the session starts; it is not safe afterwards.
func (g *Gate) SetPrompter(p prompt.Prompter) {
	if p == nil {
		p = prompt.DenyAll{}
	}
	g.prompter = prompt.Serialize(p)
}

// Adopt picks up the rules already recorded for this host, once.
//
// GetLocal, not Get: the global rules arrived through the service's options,
// and Get falls through to the global section when the host has no rules of its
// own — so "allow always", which writes the whole slice back, would copy them
// into the host file, where deleting one globally no longer reaches it.
//
// A rules document that will not parse is an error rather than an empty set.
// Rules include denies, so carrying on without them silently widens access, and
// refusing to attach is the only safe reading of a policy we cannot read.
func (g *Gate) Adopt(label string, config service.Config, what string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.adopted {
		return nil
	}

	var rules []Rule
	if _, err := config.GetLocal(rulesKey, &rules); err != nil {
		return fmt.Errorf("reading the %s rules for %s: %w", what, label, err)
	}
	g.store.AdoptHostRules(rules, configSaver{config: config})
	g.adopted = true
	return nil
}

// Authorize decides one request: policy first, a human only when policy has no
// answer, and the answer written back so the same question is not asked twice.
func (g *Gate) Authorize(ctx context.Context, request prompt.Request) Asked {
	broker := &Broker{Store: g.store, Prompter: g.prompter}
	return broker.Authorize(ctx, request)
}

// Decide answers from policy alone, without asking anybody.
//
// It is for a caller that cannot block — a scan loop reconciling a dozen ports
// — and that will start the question separately. ActionAsk means "nobody has
// decided this yet", not "no".
func (g *Gate) Decide(host, subject string) Verdict { return g.store.Decide(host, subject) }

// Store exposes the policy store for a service that needs more than the gate
// offers, such as binding a cache's lifetime to the grant that allowed it.
func (g *Gate) Store() *Store { return g.store }

// The rest is the surface the interface's Access tab drives. It is delegation
// rather than an embedded *Store because the store also carries operations
// that have no business being reachable from a UI.

// Rules are the rules devtun wrote for this host.
func (g *Gate) Rules() []Rule { return g.store.Rules() }

// GlobalRules are the rules from the top-level config: visible so a person can
// see everything that is deciding, and not removable here, because devtun did
// not write them.
func (g *Gate) GlobalRules() []Rule { return g.store.GlobalRules() }

// Revoke removes the host rule at index, as numbered by Rules.
func (g *Gate) Revoke(index int) error { return g.store.Revoke(index) }

// Deny turns the host rule at index into a refusal. It only tightens.
func (g *Gate) Deny(index int) error { return g.store.Deny(index) }

// Grants lists the allowances a prompt created that have not yet lapsed.
func (g *Gate) Grants() []Grant { return g.store.Grants() }

// RevokeGrant drops a single live grant, reporting whether it was there.
func (g *Gate) RevokeGrant(host, subject string) bool { return g.store.RevokeGrant(host, subject) }

// ForgetGrants drops every live grant — the "lock it back up" action.
func (g *Gate) ForgetGrants() int { return g.store.ForgetGrants() }

// configSaver persists the host's rules through the service's slice of the host
// config. Set marks the document dirty rather than writing it out; the session
// saves once, on exit, which is the bargain every service makes.
type configSaver struct{ config service.Config }

// SaveRules stores the whole rule set under the service's "rules" key.
func (c configSaver) SaveRules(rules []Rule) error { return c.config.Set(rulesKey, rules) }
