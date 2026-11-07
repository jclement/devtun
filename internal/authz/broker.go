package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jclement/devtun/internal/prompt"
)

// Deciding one request, end to end.
//
// This is the sequence every broker runs: consult policy, ask a human if policy
// has no answer, then turn the answer into policy so the same question is not
// asked twice. It existed twice — once for the vault, once for the agent — as
// near-copies, because the two disagree about what a *subject* is and agree
// completely about everything else.
//
// Near-copies of a security decision are the worst kind to keep. The copies had
// already drifted once: a fix for an answer racing the prompt deadline went
// into one of them and had to be noticed and carried to the other by hand.

// Asked is the outcome of putting one request through policy and, if needed, a
// human.
type Asked struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Reason is for the log, and says which of the several possible routes to
	// this answer was taken.
	Reason string
	// Until bounds anything derived from an allowed request — a cached secret
	// must not outlive it. Zero means it does not lapse on its own.
	Until time.Time
	// Note is a sentence about something written down, empty when the answer
	// left no trace. The caller emits it through its own event sink.
	Note string
	// Err is a failure to persist. The decision still stands.
	Err error
	// By is what decided: a rule, a grant, the unmatched policy, a human, or
	// nobody answering. A broker puts By.Fields() on its Activity event, which
	// is what lets a refusal in the log lead back to the rule that refused it.
	By Decider
}

// Broker asks the question a service cannot ask for itself.
type Broker struct {
	Store    *Store
	Prompter prompt.Prompter
}

// Authorize decides one request.
//
// The request carries the wording — what to call the subject, what a
// destination-scoped grant covers, which rows of detail to show — because that
// is the only part that differs between brokers, and it is the part that has to
// be right at the moment somebody is deciding.
func (b *Broker) Authorize(ctx context.Context, request prompt.Request) Asked {
	verdict := b.Store.Decide(request.Host, request.Subject)
	switch verdict.Action {
	case ActionAllow:
		return Asked{Allowed: true, Reason: verdict.Reason, Until: verdict.Until, By: verdict.By}
	case ActionDeny:
		return Asked{Reason: verdict.Reason, By: verdict.By}
	}

	config := b.Store.Config()
	if request.TTL == 0 {
		request.TTL = config.DefaultTTL
	}

	askCtx, cancel := context.WithTimeout(ctx, config.PromptTimeout)
	defer cancel()

	choice, err := b.Prompter.Ask(askCtx, request)

	// Belt and braces on the deadline. A Prompter is meant to abandon its
	// question when the context fires, and both of devtun's do — but this is
	// the one decision where trusting a collaborator to have got that right is
	// not good enough. A select whose cases are both ready picks at random, so
	// an answer arriving in the same instant as the timeout could otherwise be
	// returned as an approval the deadline had already refused.
	timedOut := Asked{
		Reason: fmt.Sprintf("no answer within %s", config.PromptTimeout),
		By:     Decider{Kind: ByTimeout},
	}
	if askCtx.Err() != nil {
		return timedOut
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return timedOut
		}
		return Asked{Reason: err.Error(), By: Decider{Kind: ByPrompt}}
	}

	// A refusal is recorded too, now that the menu can express "stop asking"
	// and "never". Only a plain No leaves no trace.
	outcome := Record(b.Store, request.Host, request.Subject, choice, config.DefaultTTL)
	asked := Asked{
		Allowed: outcome.Allowed,
		Until:   outcome.Until,
		Note:    outcome.Note,
		Err:     outcome.Err,
		Reason:  "refused at the prompt",
		By:      Decider{Kind: ByPrompt},
	}
	if outcome.Allowed {
		asked.Reason = "approved: " + choice.String()
	}
	return asked
}
