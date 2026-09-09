package tui

import (
	"context"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/approval"
	"github.com/jclement/devtun/internal/prompt"
)

// stubPrompter stands in for the interface's own modal, which cannot exist
// without a running program.
type stubPrompter struct{ asked bool }

func (s *stubPrompter) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	s.asked = true
	return prompt.ChoiceAllowOnce, nil
}

// The interface's modal is one surface among several now, and the desk is what
// puts a question to all of them. These used to test approverFor, which picked
// exactly one place to ask; the behaviours it guarded still matter, and they
// belong to Desk.Fill.

// Under the interface, the terminal surface is the modal — not a form drawn
// over the alt screen, which is what would happen if the plain terminal
// prompter were used here.
func TestTheInterfaceSuppliesTheModalAsItsTerminalSurface(t *testing.T) {
	modal := &stubPrompter{}
	desk := approval.New(approval.Options{})

	desk.Fill(prompt.MustParseSurfaces("tui"), modal)
	if got := desk.Asking(); got != 1 {
		t.Fatalf("the desk asks %d surfaces for `tui`, want 1", got)
	}
	if _, err := desk.Ask(t.Context(), prompt.Request{Host: "bedev", Subject: "op://V/I/F"}); err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if !modal.asked {
		t.Error("the modal was not the surface asked")
	}
}

// `deny` has to mean what it says under the interface too. A session told to
// answer nothing must not put up a modal that anyone walking past could
// approve — which is what happened before, since the interface installed its
// modal over whatever had been asked for.
func TestDenyLeavesNoSurfaceUnderTheInterface(t *testing.T) {
	modal := &stubPrompter{}
	desk := approval.New(approval.Options{})

	desk.Fill(prompt.MustParseSurfaces("deny"), modal)
	if got := desk.Asking(); got != 0 {
		t.Errorf("`deny` left %d surfaces to ask", got)
	}
	if modal.asked {
		t.Error("the modal was shown for a session that answers nothing")
	}
}

// The board is a surface a person chooses, and it is not a Prompter: it
// watches the desk. Asking for it alone must not leave the desk thinking it
// has somewhere to put a question that it can also draw.
func TestTheBoardIsASurfaceWithoutBeingAPrompter(t *testing.T) {
	desk := approval.New(approval.Options{})
	desk.Fill(prompt.MustParseSurfaces("web"), &stubPrompter{})
	if got := desk.Asking(); got != 0 {
		t.Errorf("the board was installed as a prompter: %d", got)
	}
	// It is still published, which is how the board gets it.
	go func() { _, _ = desk.Ask(t.Context(), prompt.Request{Host: "bedev", Subject: "op://V/I/F"}) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(desk.Waiting()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a `web` question was never published for the board to see")
		}
		time.Sleep(time.Millisecond)
	}
}
