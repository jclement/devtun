package authz

import (
	"fmt"
	"time"

	"github.com/jclement/devtun/internal/prompt"
)

// Turning an answer into policy.
//
// This is the step between "the human chose something" and "the store knows
// about it", and it lived in each broker until there were two of them. The
// copies were near-identical, which is the usual sign: the vault and the agent
// disagree about what a subject *is*, and agree completely about what "yes, for
// five minutes" should do to the store.
//
// It is here rather than in prompt because it is a policy operation — prompt's
// job ends when a human has chosen.

// Outcome is what recording an answer did.
type Outcome struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Until is when anything derived from this decision — a cached secret —
	// must be dropped. Zero means the decision does not lapse on its own,
	// which is true of a rule and of a session grant.
	Until time.Time
	// Note is a sentence for the log when something was written down, empty
	// when the answer left no trace. The caller emits it, because only the
	// caller knows which sink and which wording its service uses.
	Note string
	// Err is a failure to persist. The decision still stands for this request:
	// a rule that could not be saved is a rule the user will be asked about
	// again, which is annoying, and refusing the request they just approved
	// would be worse.
	Err error
}

// Record applies a prompt answer to the store.
//
// The TTL comes from the caller rather than from Config so a broker can use a
// different one — an agent signature and a vault read do not have to expire on
// the same clock — though neither currently does.
func Record(s *Store, host, subject string, choice prompt.Choice, ttl time.Duration) Outcome {
	switch choice {
	case prompt.ChoiceAllowOnce:
		// Nothing is recorded, so nothing derived from it may be kept either:
		// an expiry of now is what stops a cache holding this value at all.
		return Outcome{Allowed: true, Until: time.Now()}

	case prompt.ChoiceAllowSecretTTL:
		s.GrantTemporary(host, subject, ttl)
		return Outcome{Allowed: true, Until: time.Now().Add(ttl)}
	case prompt.ChoiceAllowHostTTL:
		s.GrantTemporary(host, HostWildcard, ttl)
		return Outcome{Allowed: true, Until: time.Now().Add(ttl)}

	case prompt.ChoiceAllowSecretSession:
		s.GrantSession(host, subject)
		return Outcome{Allowed: true}
	case prompt.ChoiceAllowHostSession:
		s.GrantSession(host, HostWildcard)
		return Outcome{Allowed: true}

	case prompt.ChoiceAllowSecretAlways:
		note := "approved interactively on " + time.Now().Format("2006-01-02")
		if err := s.GrantPermanent(host, subject, note); err != nil {
			return Outcome{Allowed: true, Err: err}
		}
		return Outcome{Allowed: true, Note: fmt.Sprintf("saved a rule allowing %s from %s", subject, host)}

	case prompt.ChoiceRefuseSession:
		s.RefuseSession(host, subject)
		return Outcome{Note: fmt.Sprintf("will not ask about %s from %s again this session", subject, host)}

	case prompt.ChoiceRefuseAlways:
		note := "refused interactively on " + time.Now().Format("2006-01-02")
		if err := s.RefusePermanent(host, subject, note); err != nil {
			return Outcome{Err: err}
		}
		return Outcome{Note: fmt.Sprintf("saved a rule refusing %s from %s", subject, host)}

	default:
		// ChoiceDeny, and anything a future menu adds that this has not been
		// taught about. Refusing an answer we do not understand is the only
		// safe reading, and it is why ChoiceDeny is the zero value.
		return Outcome{}
	}
}
