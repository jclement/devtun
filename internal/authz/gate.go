package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// Where a service's rules live in its slice of a config document. Every gated
// service uses the same keys, in its own namespace.
const (
	// rulesKey is the hand-written list, in the global file and the host's.
	rulesKey = "rules"
	// rememberedKey is the list devtun writes, in the host's file only.
	rememberedKey = "remembered"
	// unmatchedKey is ask or deny: what happens when nothing matches.
	unmatchedKey = "unmatched"
)

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
	// canAsk records whether there is anywhere to put a question. The prompter
	// is never nil — a nil one becomes DenyAll — so by the time anything reads
	// it, "nobody can be asked" and "everybody says no" are the same object.
	// They are not the same situation, and only one of them is a bug.
	canAsk bool

	mu      sync.Mutex
	adopted bool
}

// NewGate builds the apparatus. A nil prompter means nobody can be asked, which
// refuses everything policy does not already allow — the zero value of a
// decision is no.
func NewGate(config Config, prompter prompt.Prompter) *Gate {
	if prompter == nil {
		prompter = prompt.DenyAll{}
		return &Gate{store: NewStore(config), prompter: prompt.Serialize(prompter)}
	}
	return &Gate{store: NewStore(config), prompter: prompt.Serialize(prompter), canAsk: true}
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
	g.canAsk = p != nil
	if p == nil {
		p = prompt.DenyAll{}
	}
	g.prompter = prompt.Serialize(p)
}

// CanAsk reports whether this gate has anywhere to put a question.
//
// A gate with nowhere to ask refuses everything the policy does not already
// allow, and from the caller's side that is indistinguishable from a refusal
// somebody meant. It is what `devtun doctor` checks, and what stops a service
// being left off the list of things handed a prompter — which has now happened
// twice.
func (g *Gate) CanAsk() bool { return g.canAsk }

// Adopt starts reading this host's rules from its config, once.
//
// From then on the rules are read through the config as it is on disk — a
// rule typed into the file while devtun runs applies to the next request — and
// written back one change at a time, against the file as it is then.
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

	book := &configBook{config: config, global: g.store.Config().Rules}
	if _, err := book.Load(); err != nil {
		return fmt.Errorf("reading the %s rules for %s: %w", what, label, err)
	}
	g.store.AdoptBook(book)
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

// The rest is the Policy surface the interface's Access tab and the web board
// drive. It is delegation rather than an embedded *Store because the store also
// carries operations that have no business being reachable from a UI.

// Rules is every rule — global, host, remembered — in evaluation order.
func (g *Gate) Rules() []Rule { return g.store.Rules() }

// Rule finds one rule by ID.
func (g *Gate) Rule(id string) (Rule, bool) { return g.store.Rule(id) }

// AddRule records a rule in the host's remembered list.
func (g *Gate) AddRule(r Rule) (Rule, error) { return g.store.AddRule(r) }

// RemoveRule deletes a host or remembered rule.
func (g *Gate) RemoveRule(id string) error { return g.store.RemoveRule(id) }

// SetRuleAction makes a rule an allow or a deny.
func (g *Gate) SetRuleAction(id string, a Action) (Rule, error) { return g.store.SetRuleAction(id, a) }

// UpdateRule changes a rule's host, subject or note.
func (g *Gate) UpdateRule(id string, e RuleEdit) (Rule, error) { return g.store.UpdateRule(id, e) }

// Grants lists the live grants, allow and refuse.
func (g *Gate) Grants() []Grant { return g.store.Grants() }

// RevokeGrant drops one live grant by ID.
func (g *Gate) RevokeGrant(id string) bool { return g.store.RevokeGrant(id) }

// AddGrant opens (or shuts) something before it is asked for.
func (g *Gate) AddGrant(spec GrantSpec) (Grant, error) { return g.store.AddGrant(spec) }

// ForgetGrants drops every live allow grant. Refusals survive.
func (g *Gate) ForgetGrants() int { return g.store.ForgetGrants() }

// ForgetRefusals drops every live refusal.
func (g *Gate) ForgetRefusals() int { return g.store.ForgetRefusals() }

// Explain is a verdict with every matching rule and grant.
func (g *Gate) Explain(host, subject string) Explanation { return g.store.Explain(host, subject) }

// Unmatched is what happens to a request nothing matches.
func (g *Gate) Unmatched() UnmatchedPolicy { return g.store.Unmatched() }

// Schema is what this broker's subjects are made of.
func (g *Gate) Schema() Schema { return g.store.Schema() }

// PolicyErr reports a policy file that cannot be read.
func (g *Gate) PolicyErr() error { return g.store.PolicyErr() }

// Revision changes whenever the rules or grants do.
func (g *Gate) Revision() uint64 { return g.store.Revision() }

// configBook is a RuleBook over a service's slice of the config.
//
// It reads through the config on every Load, which re-reads a file only when
// it has changed on disk, so a hand edit applies without a restart. It writes
// through EditNode when the config offers it — a transaction against the file
// as it is now, which keeps every rule it was not asked to touch exactly as
// written, comments included — and falls back to replacing the list for a
// config that does not.
type configBook struct {
	config service.Config
	// global is used when the config cannot read the global file by itself.
	global []Rule
}

// The optional parts of a config the book uses. hostcfg's sections have all
// of them; a test's map need not.
type (
	globalReader interface {
		GetGlobal(key string, v any) (bool, error)
	}
	nodeEditor interface {
		EditNode(key string, edit func(*yaml.Node) (*yaml.Node, error)) error
	}
	errReporter interface{ Err() error }
	revisioned  interface{ Revision() uint64 }
)

func (b *configBook) Load() (Loaded, error) {
	var l Loaded
	var errs []error
	if r, ok := b.config.(errReporter); ok {
		errs = append(errs, r.Err())
	}

	l.Global = b.global
	if gr, ok := b.config.(globalReader); ok {
		var global []Rule
		if _, err := gr.GetGlobal(rulesKey, &global); err != nil {
			errs = append(errs, err)
		}
		l.Global = global
		var unmatched string
		if found, err := gr.GetGlobal(unmatchedKey, &unmatched); err != nil {
			errs = append(errs, err)
		} else if found && strings.TrimSpace(unmatched) != "" {
			l.Unmatched, l.UnmatchedLevel = unmatched, "global"
		}
	}

	if _, err := b.config.GetLocal(rulesKey, &l.Host); err != nil {
		errs = append(errs, err)
	}
	if _, err := b.config.GetLocal(rememberedKey, &l.Remembered); err != nil {
		errs = append(errs, err)
	}
	// An empty or null value is no value: it inherits, it does not reset to
	// ask. `unmatched:` left blank in a host file under a global deny is a
	// half-finished edit, and reading it as "ask" would quietly undo the
	// allowlist the global file set.
	var unmatched string
	if found, err := b.config.GetLocal(unmatchedKey, &unmatched); err != nil {
		errs = append(errs, err)
	} else if found && strings.TrimSpace(unmatched) != "" {
		l.Unmatched, l.UnmatchedLevel = unmatched, "host"
	}
	return l, errors.Join(errs...)
}

func (b *configBook) Revision() uint64 {
	if r, ok := b.config.(revisioned); ok {
		return r.Revision()
	}
	// Without a revision every Load is fresh, which is correct and slower.
	return revisionUnknown()
}

func (b *configBook) Edit(source Source, edit func([]Rule) ([]Rule, error)) error {
	key := rememberedKey
	if source == SourceHost {
		key = rulesKey
	}

	ne, ok := b.config.(nodeEditor)
	if !ok {
		var current []Rule
		if _, err := b.config.GetLocal(key, &current); err != nil {
			return err
		}
		next, err := edit(assignIDs(source, current))
		if err != nil {
			return err
		}
		return b.config.Set(key, next)
	}

	return ne.EditNode(key, func(node *yaml.Node) (*yaml.Node, error) {
		var items []*yaml.Node
		var current []Rule
		if node != nil {
			if node.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s: expected a list of rules", key)
			}
			for _, item := range node.Content {
				var r Rule
				if err := item.Decode(&r); err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				items = append(items, item)
				current = append(current, r)
			}
		}
		next, err := edit(assignIDs(source, current))
		if err != nil {
			return nil, err
		}
		if len(next) == 0 {
			return nil, nil
		}

		// Reuse the node of every rule that is unchanged, so its comments and
		// layout survive; encode only what is new or edited.
		out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if node != nil {
			out.Style, out.HeadComment, out.LineComment = node.Style, node.HeadComment, node.LineComment
		}
		used := make([]bool, len(items))
		for _, r := range next {
			out.Content = append(out.Content, nodeFor(r, current, items, used))
		}
		return out, nil
	})
}

// nodeFor is the existing node for a rule that has not changed, or a new one.
func nodeFor(r Rule, current []Rule, items []*yaml.Node, used []bool) *yaml.Node {
	for i := range current {
		if !used[i] && current[i].sameContent(r) {
			used[i] = true
			return items[i]
		}
	}
	var n yaml.Node
	if err := n.Encode(r); err != nil {
		// Encoding a struct of strings and a time does not fail; if it ever
		// did, an empty map is refused by the next Load rather than written
		// as something it was not.
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	return &n
}

// revisionUnknown is a revision that never repeats, for a book that cannot
// tell when it changed.
func revisionUnknown() uint64 {
	unknownMu.Lock()
	defer unknownMu.Unlock()
	unknownRev++
	return unknownRev
}

var (
	unknownMu  sync.Mutex
	unknownRev uint64
)

// Policy is the surface the interface's Access tab and the web board drive,
// one per gated broker. Removing a deny, or turning one into an allow, is
// allowed here; the confirm that stands in front of loosening belongs to the
// surface that has a person to ask.
type Policy interface {
	Rules() []Rule
	Rule(id string) (Rule, bool)
	AddRule(r Rule) (Rule, error)
	RemoveRule(id string) error
	SetRuleAction(id string, a Action) (Rule, error)
	UpdateRule(id string, e RuleEdit) (Rule, error)

	Grants() []Grant
	RevokeGrant(id string) bool
	AddGrant(spec GrantSpec) (Grant, error)
	ForgetGrants() int
	ForgetRefusals() int

	Explain(host, subject string) Explanation
	Unmatched() UnmatchedPolicy
	Schema() Schema
	PolicyErr() error
	Revision() uint64
}

var _ Policy = (*Gate)(nil)

// Surface is a Gate's Policy methods and nothing else, for a broker to embed.
//
// Embedding the Gate itself would hand the interface Authorize, Adopt and the
// raw Store along with the rules; writing the delegation out in each broker is
// how three copies drift. This is the narrow middle.
type Surface struct{ gate *Gate }

// Surface returns the Policy half of the gate.
func (g *Gate) Surface() Surface { return Surface{gate: g} }

var _ Policy = Surface{}

func (s Surface) Rules() []Rule                { return s.gate.Rules() }
func (s Surface) Rule(id string) (Rule, bool)  { return s.gate.Rule(id) }
func (s Surface) AddRule(r Rule) (Rule, error) { return s.gate.AddRule(r) }
func (s Surface) RemoveRule(id string) error   { return s.gate.RemoveRule(id) }
func (s Surface) SetRuleAction(id string, a Action) (Rule, error) {
	return s.gate.SetRuleAction(id, a)
}
func (s Surface) UpdateRule(id string, e RuleEdit) (Rule, error) { return s.gate.UpdateRule(id, e) }
func (s Surface) Grants() []Grant                                { return s.gate.Grants() }
func (s Surface) RevokeGrant(id string) bool                     { return s.gate.RevokeGrant(id) }
func (s Surface) AddGrant(spec GrantSpec) (Grant, error)         { return s.gate.AddGrant(spec) }
func (s Surface) ForgetGrants() int                              { return s.gate.ForgetGrants() }
func (s Surface) ForgetRefusals() int                            { return s.gate.ForgetRefusals() }
func (s Surface) Explain(host, subject string) Explanation       { return s.gate.Explain(host, subject) }
func (s Surface) Unmatched() UnmatchedPolicy                     { return s.gate.Unmatched() }
func (s Surface) Schema() Schema                                 { return s.gate.Schema() }
func (s Surface) PolicyErr() error                               { return s.gate.PolicyErr() }
func (s Surface) Revision() uint64                               { return s.gate.Revision() }
