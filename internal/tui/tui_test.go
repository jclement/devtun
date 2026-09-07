package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
)

// stubPrompter stands in for the interface's own modal, which cannot exist
// without a running program.
type stubPrompter struct{ asked bool }

func (s *stubPrompter) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	s.asked = true
	return prompt.ChoiceAllowOnce, nil
}

// The default is the modal: somebody is looking at this window, and the
// question belongs in it.
func TestApproverDefaultsToTheModal(t *testing.T) {
	modal := &stubPrompter{}
	for _, backend := range []prompt.Backend{"", prompt.BackendAuto, prompt.BackendTUI} {
		if got := approverFor(backend, modal, nil); got != prompt.Prompter(modal) {
			t.Errorf("backend %q did not get the modal", backend)
		}
	}
}

// `deny` has to mean what it says under the interface too. A session told to
// answer nothing must not put up a modal that anyone walking past could
// approve — which is what happened before, since the interface installed its
// modal over whatever had been asked for.
func TestApproverHonoursDenyUnderTheInterface(t *testing.T) {
	modal := &stubPrompter{}
	approver := approverFor(prompt.BackendDeny, modal, nil)

	got, err := approver.Ask(t.Context(), prompt.Request{Host: "bedev", Subject: "op://V/I/F"})
	if got != prompt.ChoiceDeny {
		t.Errorf("choice = %v, want deny", got)
	}
	if err == nil {
		t.Error("a refusal with no human should say why")
	}
	if modal.asked {
		t.Error("the modal was shown for a session that answers nothing")
	}
}

// Asking for a desktop dialog either gets one or says, once and in the log,
// that this machine has none — and never leaves the session unable to ask.
func TestApproverFallsBackToTheModalWithNoDialogProgram(t *testing.T) {
	modal := &stubPrompter{}
	bus := event.NewBus(16)
	approver := approverFor(prompt.BackendDialog, modal, bus)

	if approver == nil {
		t.Fatal("no prompter at all")
	}
	if approver != prompt.Prompter(modal) {
		// This machine can draw a dialog; there is nothing to warn about.
		return
	}
	var said bool
	for _, e := range bus.History() {
		if e.Kind == "prompt" && strings.Contains(e.Text, "interface") {
			said = true
		}
	}
	if !said {
		t.Errorf("the fallback to the modal was silent: %+v", bus.History())
	}
}
