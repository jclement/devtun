package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/onepassword/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
)

func testRequest() prompt.Request {
	return prompt.Request{
		Host:    "bedev",
		Subject: "op://Personal/Docker/PAT",
		Argv:    []string{"read", "op://Personal/Docker/PAT"},
		Caller:  service.Caller{User: "jeff", Host: "bedev", Program: "deploy.sh", PID: 4242, CWD: "~/projects/api"},
		TTL:     5 * time.Minute,
	}
}

// Property one: deny is the zero Choice, so anything that goes wrong lands on
// it rather than on an allow.
func TestDenyIsTheZeroChoice(t *testing.T) {
	var zero prompt.Choice
	if zero != prompt.ChoiceDeny {
		t.Fatalf("the zero Choice is %v, not deny — every error path here returns it", zero)
	}
	if zero.Allows() {
		t.Fatal("the zero Choice allows")
	}
}

// With nothing on screen there is nobody to ask, which is a refusal and says
// so — never an allow.
func TestAskWithNothingAttachedDenies(t *testing.T) {
	p := NewPrompter()
	choice, err := p.Ask(context.Background(), testRequest())
	if choice != prompt.ChoiceDeny {
		t.Errorf("choice = %v, want deny", choice)
	}
	if !errors.Is(err, prompt.ErrNoPrompter) {
		t.Errorf("err = %v, want ErrNoPrompter", err)
	}

	// Detaching has to put it back to refusing, or a request arriving as the
	// interface exits would hang on a program that is gone.
	p.Attach(tea.NewProgram(nil))
	p.Detach()
	if choice, _ := p.Ask(context.Background(), testRequest()); choice != prompt.ChoiceDeny {
		t.Errorf("after Detach the choice is %v, want deny", choice)
	}
}

// Property two: the caller wraps Ask with the prompt timeout, and when it
// fires the modal is abandoned. Walking away from a prompt is a refusal, not
// an error, so the error is nil.
func TestAskHonoursTheContextDeadline(t *testing.T) {
	// A program that is never run: Send blocks on it, which is exactly the
	// case the deadline has to rescue.
	programCtx, cancelProgram := context.WithCancel(context.Background())
	t.Cleanup(cancelProgram)
	p := NewPrompter()
	p.Attach(tea.NewProgram(nil, tea.WithContext(programCtx)))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	choice, err := p.Ask(ctx, testRequest())
	if err != nil {
		t.Errorf("err = %v, want nil: a timeout is a refusal, not a failure", err)
	}
	if choice != prompt.ChoiceDeny {
		t.Errorf("choice = %v, want deny", choice)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Ask took %v to give up", elapsed)
	}
}

// A cancelled context is the same answer as a timed-out one.
func TestAskOnACancelledContextDenies(t *testing.T) {
	programCtx, cancelProgram := context.WithCancel(context.Background())
	t.Cleanup(cancelProgram)
	p := NewPrompter()
	p.Attach(tea.NewProgram(nil, tea.WithContext(programCtx)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if choice, err := p.Ask(ctx, testRequest()); choice != prompt.ChoiceDeny || err != nil {
		t.Errorf("Ask = (%v, %v), want (deny, nil)", choice, err)
	}
}

// Property three: the menu comes from prompt.MenuFor, so the terminal, the
// macOS dialog and this modal can never offer different things.
func TestAskBuildsItsOptionsFromMenuFor(t *testing.T) {
	probe := &probeModel{got: make(chan approvalMsg, 1)}
	program, done := runHeadless(t, probe)

	p := NewPrompter()
	p.Attach(program)

	answered := make(chan prompt.Choice, 1)
	request := testRequest()
	go func() {
		choice, _ := p.Ask(context.Background(), request)
		answered <- choice
	}()

	var msg approvalMsg
	select {
	case msg = <-probe.got:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the program")
	}

	want := prompt.MenuFor(request)
	if len(msg.options) != len(want) {
		t.Fatalf("the modal offers %d options, MenuFor gives %d", len(msg.options), len(want))
	}
	for i := range want {
		if msg.options[i] != want[i] {
			t.Errorf("option %d is %+v, want %+v", i, msg.options[i], want[i])
		}
	}
	// Narrowest first, deny last.
	if msg.options[0].Choice != prompt.ChoiceAllowOnce {
		t.Errorf("the first option is %v, want allow once", msg.options[0].Choice)
	}
	if last := msg.options[len(msg.options)-1].Choice; last != prompt.ChoiceDeny {
		t.Errorf("the last option is %v, want deny", last)
	}

	msg.reply <- prompt.ChoiceAllowOnce
	select {
	case got := <-answered:
		if got != prompt.ChoiceAllowOnce {
			t.Errorf("Ask returned %v, want the answer that was given", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ask never picked up the answer")
	}

	program.Quit()
	<-done
}

// The modal itself: what it shows, and that every way of dismissing it denies.
func TestApprovalModalShowsTheRequestAndDeniesOnEscape(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	request := testRequest()
	reply := make(chan prompt.Choice, 1)
	m.Update(approvalMsg{request: request, options: prompt.MenuFor(request), reply: reply})

	view := plainView(m)
	for _, want := range []string{
		"bedev", "op://Personal/Docker/PAT",
		"op read op://Personal/Docker/PAT",
		"jeff@bedev", "deploy.sh", "pid 4242", "~/projects/api",
		"caller details come from the remote box and are not verified",
		"Allow once", "Deny",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the approval modal is missing %q:\n%s", want, view)
		}
	}

	send(m, "esc")
	select {
	case choice := <-reply:
		if choice != prompt.ChoiceDeny {
			t.Errorf("escape answered %v, want deny", choice)
		}
	default:
		t.Fatal("escape answered nothing at all")
	}
	if m.approval != nil {
		t.Error("the modal is still on screen")
	}
}

// The cursor starts on the narrowest option, so the safe answer is the one
// under enter and the broad ones take deliberate effort to reach.
func TestApprovalModalAnswersTheSelectedOption(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	request := testRequest()
	reply := make(chan prompt.Choice, 1)
	m.Update(approvalMsg{request: request, options: prompt.MenuFor(request), reply: reply})

	send(m, "enter")
	select {
	case choice := <-reply:
		if choice != prompt.ChoiceAllowOnce {
			t.Errorf("enter on arrival answered %v, want allow once", choice)
		}
	default:
		t.Fatal("enter answered nothing")
	}
}

// A request the asker has given up on must not sit on screen waiting.
func TestApprovalIsWithdrawnWhenTheAskerGivesUp(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	request := testRequest()
	reply := make(chan prompt.Choice, 1)
	m.Update(approvalMsg{request: request, options: prompt.MenuFor(request), reply: reply})
	m.Update(approvalCancelMsg{reply: reply})

	if m.approval != nil {
		t.Error("the abandoned modal is still on screen")
	}
	if strings.Contains(plainView(m), "Allow once") {
		t.Errorf("the abandoned modal is still drawn:\n%s", plainView(m))
	}
}

// The shell-rc question shows the same three things the terminal version does:
// the file, the exact lines, and that the edit goes in a marked block.
func TestSetupModalShowsTheFileAndTheBlock(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	reply := make(chan bool, 1)
	m.Update(setupMsg{plan: session.RCPlan{
		File:  "/home/jeff/.zshrc",
		Shell: "zsh",
		Lines: []string{`export PATH="/home/jeff/.devtun/bin:$PATH"`},
	}, reply: reply})

	view := plainView(m)
	for _, want := range []string{"/home/jeff/.zshrc", `export PATH="/home/jeff/.devtun/bin:$PATH"`, "marked block"} {
		if !strings.Contains(view, want) {
			t.Errorf("the setup modal is missing %q:\n%s", want, view)
		}
	}

	send(m, "n")
	select {
	case yes := <-reply:
		if yes {
			t.Error("n answered yes")
		}
	default:
		t.Fatal("n answered nothing")
	}
}

// AskSetup with nothing on screen declines, which is the same as the log-mode
// prompter does when nobody is watching.
func TestAskSetupWithNothingAttachedDeclines(t *testing.T) {
	p := NewPrompter()
	yes, err := p.AskSetup(context.Background(), session.RCPlan{File: "~/.zshrc"})
	if yes || err != nil {
		t.Errorf("AskSetup = (%v, %v), want (false, nil)", yes, err)
	}
}

// --- a headless program to talk to ----------------------------------------

// probeModel is the smallest program a prompter can be attached to. It records
// what arrives so the real Send-and-reply path is exercised rather than a
// re-implementation of it.
type probeModel struct{ got chan approvalMsg }

func (p *probeModel) Init() tea.Cmd { return nil }

func (p *probeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if a, ok := msg.(approvalMsg); ok {
		p.got <- a
	}
	return p, nil
}

func (p *probeModel) View() tea.View { return tea.NewView("") }

// runHeadless starts a program with no terminal at either end.
func runHeadless(t *testing.T, model tea.Model) (*tea.Program, chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	program := tea.NewProgram(model,
		tea.WithContext(ctx),
		tea.WithInput(nil),
		tea.WithOutput(io.Discard),
		tea.WithoutRenderer(),
		tea.WithoutSignals(),
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := program.Run(); err != nil && !errors.Is(err, tea.ErrProgramKilled) {
			t.Errorf("the probe program failed: %v", err)
		}
	}()
	t.Cleanup(func() { program.Kill() })
	return program, done
}
