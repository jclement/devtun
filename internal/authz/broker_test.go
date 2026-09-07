package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/prompt"
)

// answering is a prompter that gives a fixed answer, optionally after a delay.
type answering struct {
	choice prompt.Choice
	delay  time.Duration
	err    error
	asked  int
}

func (a *answering) Ask(ctx context.Context, _ prompt.Request) (prompt.Choice, error) {
	a.asked++
	if a.delay > 0 {
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
		}
	}
	return a.choice, a.err
}

func request() prompt.Request {
	return prompt.Request{Host: "bedev", Subject: "op://V/I/F", Noun: "secret"}
}

func broker(store *Store, p prompt.Prompter) *Broker { return &Broker{Store: store, Prompter: p} }

// A standing rule answers without troubling anybody.
func TestPolicyAnswersWithoutAsking(t *testing.T) {
	store := NewStore(Config{Rules: []Rule{
		{Host: "bedev", Subject: "op://V/**", Action: ActionAllow},
	}})
	prompter := &answering{choice: prompt.ChoiceDeny}

	asked := broker(store, prompter).Authorize(context.Background(), request())

	if !asked.Allowed {
		t.Errorf("a matching allow rule should allow, got %q", asked.Reason)
	}
	if prompter.asked != 0 {
		t.Error("policy had an answer; nobody should have been asked")
	}
}

func TestADenyRuleRefusesWithoutAsking(t *testing.T) {
	store := NewStore(Config{Rules: []Rule{
		{Host: "bedev", Subject: "op://V/**", Action: ActionDeny},
	}})
	prompter := &answering{choice: prompt.ChoiceAllowOnce}

	asked := broker(store, prompter).Authorize(context.Background(), request())

	if asked.Allowed {
		t.Error("a deny rule must not be promptable past")
	}
	if prompter.asked != 0 {
		t.Error("a refusal on the books should not become a question")
	}
}

// The invariant that had already drifted between the two copies: an answer
// arriving in the same instant as the deadline must not become an approval.
func TestAnAnswerThatRacesTheDeadlineIsRefused(t *testing.T) {
	store := NewStore(Config{PromptTimeout: time.Millisecond})
	prompter := &answering{choice: prompt.ChoiceAllowSecretSession, delay: 20 * time.Millisecond}

	asked := broker(store, prompter).Authorize(context.Background(), request())

	if asked.Allowed {
		t.Fatal("an answer after the deadline was treated as an approval")
	}
	if asked.Reason == "" {
		t.Error("the refusal should say it timed out")
	}
}

// Whatever a prompter does wrong, the answer is no.
func TestAPrompterFailureRefuses(t *testing.T) {
	store := NewStore(Config{})
	prompter := &answering{choice: prompt.ChoiceAllowOnce, err: errors.New("no terminal")}

	if asked := broker(store, prompter).Authorize(context.Background(), request()); asked.Allowed {
		t.Error("a prompter that errored must not grant access")
	}
}

// The answer is recorded, so the same question is not asked twice.
func TestAnApprovalIsRemembered(t *testing.T) {
	store := NewStore(Config{})
	prompter := &answering{choice: prompt.ChoiceAllowSecretSession}
	b := broker(store, prompter)

	if asked := b.Authorize(context.Background(), request()); !asked.Allowed {
		t.Fatalf("first request refused: %q", asked.Reason)
	}
	if asked := b.Authorize(context.Background(), request()); !asked.Allowed {
		t.Fatalf("second request refused: %q", asked.Reason)
	}
	if prompter.asked != 1 {
		t.Errorf("asked %d times, want once — the grant should cover the second", prompter.asked)
	}
}

// And so is a refusal, which is the answer that had no expression at all
// before: the only way to stop being asked was to say yes.
func TestARefusalIsRemembered(t *testing.T) {
	store := NewStore(Config{})
	prompter := &answering{choice: prompt.ChoiceRefuseSession}
	b := broker(store, prompter)

	if asked := b.Authorize(context.Background(), request()); asked.Allowed {
		t.Fatal("a refusal must not allow")
	}
	asked := b.Authorize(context.Background(), request())
	if asked.Allowed {
		t.Fatal("still refused")
	}
	if prompter.asked != 1 {
		t.Errorf("asked %d times, want once — 'stop asking' should mean it", prompter.asked)
	}
}

// The TTL comes from config when the request does not set one, so a broker
// need not know the number to get the right grant.
func TestTheRequestInheritsTheConfiguredTTL(t *testing.T) {
	store := NewStore(Config{DefaultTTL: 42 * time.Minute})
	var seen time.Duration
	prompter := prompt.PrompterFunc(func(_ context.Context, r prompt.Request) (prompt.Choice, error) {
		seen = r.TTL
		return prompt.ChoiceDeny, nil
	})

	broker(store, prompter).Authorize(context.Background(), request())

	if seen != 42*time.Minute {
		t.Errorf("the prompt saw a TTL of %s, want the configured 42m", seen)
	}
}
