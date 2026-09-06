package authz

import (
	"testing"
	"time"

	"github.com/jclement/devtun/internal/prompt"
)

// Every menu choice must reach the store as the thing it says it is. This
// translation used to live in each broker, and a third copy is how the two
// would have drifted.
func TestRecordTranslatesEveryChoice(t *testing.T) {
	const host, subject = "bedev", "op://V/I/F"

	tests := []struct {
		choice  prompt.Choice
		allowed bool
		// after is what a fresh Decide should say once the answer is recorded.
		after Action
	}{
		{prompt.ChoiceAllowOnce, true, ActionAsk},
		{prompt.ChoiceAllowSecretTTL, true, ActionAllow},
		{prompt.ChoiceAllowSecretSession, true, ActionAllow},
		{prompt.ChoiceAllowHostTTL, true, ActionAllow},
		{prompt.ChoiceAllowHostSession, true, ActionAllow},
		{prompt.ChoiceDeny, false, ActionAsk},
		{prompt.ChoiceRefuseSession, false, ActionDeny},
	}
	for _, test := range tests {
		t.Run(test.choice.String(), func(t *testing.T) {
			store := NewStore(Config{})
			out := Record(store, host, subject, test.choice, time.Minute)

			if out.Allowed != test.allowed {
				t.Errorf("Allowed = %v, want %v", out.Allowed, test.allowed)
			}
			if got := store.Decide(host, subject).Action; got != test.after {
				t.Errorf("after recording, Decide = %v, want %v", got, test.after)
			}
		})
	}
}

// "Allow once" must leave nothing behind that a cache could hold onto.
func TestAllowOnceExpiresImmediately(t *testing.T) {
	out := Record(NewStore(Config{}), "bedev", "op://V/I/F", prompt.ChoiceAllowOnce, time.Hour)

	if out.Until.IsZero() {
		t.Fatal("allow once must carry an expiry, or a cache may keep the value indefinitely")
	}
	if out.Until.After(time.Now().Add(time.Second)) {
		t.Errorf("allow once should expire now, not at %v", out.Until)
	}
}

// A choice this function has not been taught about must refuse. It is why
// ChoiceDeny is the zero value.
func TestUnknownChoiceRefuses(t *testing.T) {
	out := Record(NewStore(Config{}), "bedev", "op://V/I/F", prompt.Choice(99), time.Minute)

	if out.Allowed {
		t.Error("an unrecognised answer must not grant access")
	}
}

// A rule that could not be saved must not undo the approval the user just
// gave: they said yes, and the worst case is being asked again.
func TestFailingToSaveARuleStillAllows(t *testing.T) {
	store := NewStore(Config{})
	store.AdoptHostRules(nil, failingSaver{})

	out := Record(store, "bedev", "op://V/I/F", prompt.ChoiceAllowSecretAlways, time.Minute)

	if !out.Allowed {
		t.Error("a save failure must not turn an approval into a refusal")
	}
	if out.Err == nil {
		t.Error("the failure should still be reported")
	}
}

// The mirror of the above: a "never" that could not be written must still
// refuse this request.
func TestFailingToSaveARefusalStillRefuses(t *testing.T) {
	store := NewStore(Config{})
	store.AdoptHostRules(nil, failingSaver{})

	out := Record(store, "bedev", "op://V/I/F", prompt.ChoiceRefuseAlways, time.Minute)

	if out.Allowed {
		t.Error("a failed save must not turn a refusal into an approval")
	}
	if out.Err == nil {
		t.Error("the failure should be reported")
	}
}

type failingSaver struct{}

func (failingSaver) SaveRules([]Rule) error { return errSaveFailed }

var errSaveFailed = &saveError{}

type saveError struct{}

func (*saveError) Error() string { return "disk is full" }
