package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/prompt"
)

// fakeConfig is a service.Config over a map, with a switch for a document that
// will not decode.
type fakeConfig struct {
	docs   map[string]any
	broken bool
	saved  []Rule
}

func (c *fakeConfig) Get(key string, v any) (bool, error) { return c.GetLocal(key, v) }

func (c *fakeConfig) GetLocal(key string, v any) (bool, error) {
	if c.broken {
		return false, errors.New("yaml: line 3: did not find expected key")
	}
	doc, ok := c.docs[key]
	if !ok {
		return false, nil
	}
	rules, ok := doc.([]Rule)
	if !ok {
		return false, errors.New("not rules")
	}
	*(v.(*[]Rule)) = rules
	return true, nil
}

func (c *fakeConfig) Set(key string, v any) error {
	if rules, ok := v.([]Rule); ok {
		c.saved = rules
	}
	if c.docs == nil {
		c.docs = map[string]any{}
	}
	c.docs[key] = v
	return nil
}

type allowAlways struct{}

func (allowAlways) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	return prompt.ChoiceAllowSecretAlways, nil
}

// A gate with nobody to ask refuses. This is the property every service relies
// on: a nil prompter is not "no policy", it is "no".
func TestGateWithNoPrompterRefuses(t *testing.T) {
	gate := NewGate(Config{}, nil)
	if gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "x"}).Allowed {
		t.Error("a gate with no prompter allowed a request")
	}
}

func TestGateSetPrompterInstallsAnAnswer(t *testing.T) {
	gate := NewGate(Config{}, nil)
	gate.SetPrompter(allowAlways{})
	if !gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "x"}).Allowed {
		t.Error("the installed prompter did not get to answer")
	}
	// ...and installing nil closes it again.
	gate.SetPrompter(nil)
	if gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "y"}).Allowed {
		t.Error("installing nil opened the door")
	}
}

// Adopt reads the host's own rules once, and what a prompt writes goes back to
// the same place.
func TestGateAdoptsHostRulesOnceAndWritesBack(t *testing.T) {
	config := &fakeConfig{docs: map[string]any{
		"rules": []Rule{{Host: "bedev", Subject: "op://V/deny/me", Action: ActionDeny}},
	}}

	gate := NewGate(Config{}, allowAlways{})
	if err := gate.Adopt("bedev", config, "1Password"); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if got := len(gate.Rules()); got != 1 {
		t.Fatalf("the host's rules were not adopted: %d", got)
	}
	// The adopted deny decides, without anybody being asked.
	if gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "op://V/deny/me"}).Allowed {
		t.Error("an adopted deny rule did not decide")
	}

	// An "always" answer is written back through the same config.
	gate.Authorize(context.Background(), prompt.Request{Host: "bedev", Subject: "op://V/allow/me"})
	if len(config.saved) != 2 {
		t.Errorf("the new rule was not saved: %+v", config.saved)
	}

	// A second Adopt is a no-op: re-reading on every reconnect would restore
	// rules that had been revoked in between.
	if err := gate.Adopt("bedev", &fakeConfig{}, "1Password"); err != nil {
		t.Fatalf("second Adopt: %v", err)
	}
	if got := len(gate.Rules()); got != 2 {
		t.Errorf("a second Adopt changed the rules: %d", got)
	}
}

// Rules that will not parse include denies, so reading them as empty silently
// widens access. Refusing to attach is the only safe reading.
func TestGateRefusesToAdoptRulesItCannotRead(t *testing.T) {
	gate := NewGate(Config{}, nil)
	err := gate.Adopt("bedev", &fakeConfig{broken: true}, "1Password")
	if err == nil {
		t.Fatal("a broken rules document was adopted as empty")
	}
	if got := err.Error(); !strings.Contains(got, "1Password") || !strings.Contains(got, "bedev") {
		t.Errorf("the error says neither what nor where: %q", got)
	}
}
