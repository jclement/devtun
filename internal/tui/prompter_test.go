package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
)

func testRequest() prompt.Request {
	return prompt.Request{
		Host:    "bedev",
		Subject: "op://Personal/Docker/PAT",
		Rows:    []prompt.Row{{Label: "command", Value: "op " + strings.Join([]string{"read", "op://Personal/Docker/PAT"}, " ")}},
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
	// Narrowest first, and nothing that grants access below a refusal — so
	// overshooting downward can never land on an approval.
	if msg.options[0].Choice != prompt.ChoiceAllowOnce {
		t.Errorf("the first option is %v, want allow once", msg.options[0].Choice)
	}
	if last := msg.options[len(msg.options)-1].Choice; last.Allows() {
		t.Errorf("the last option is %v, which grants access", last)
	}
	seenRefusal := false
	for _, item := range msg.options {
		if !item.Choice.Allows() {
			seenRefusal = true
		} else if seenRefusal {
			t.Errorf("%q grants access but sits below a refusal", item.Label)
		}
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
		"Yes, once", "No",
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
	if strings.Contains(plainView(m), "Yes, once") {
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

// A service built with no prompter refuses by construction, which is the right
// default and exactly why forgetting to install one is silent: under the
// interface every signature was refused in the instant it was requested, and no
// prompt ever appeared. Finding brokers by interface means a fifth cannot be
// forgotten.
func TestEveryPromptableServiceGetsTheModal(t *testing.T) {
	installed := map[string]bool{}
	services := []service.Service{
		&promptableStub{id: "1password", seen: installed},
		&promptableStub{id: "ssh-agent", seen: installed},
		&unpromptableStub{id: "tunnels"},
	}

	prompter := NewPrompter()
	for _, svc := range services {
		if p, ok := svc.(interface{ SetPrompter(prompt.Prompter) }); ok {
			p.SetPrompter(prompter)
		}
	}

	for _, want := range []string{"1password", "ssh-agent"} {
		if !installed[want] {
			t.Errorf("%s never got the approval modal, so it would refuse everything silently", want)
		}
	}
	if len(installed) != 2 {
		t.Errorf("installed on %v, want exactly the two brokers", installed)
	}
}

type promptableStub struct {
	id   string
	seen map[string]bool
}

func (s *promptableStub) Meta() service.Meta { return service.Meta{ID: s.id} }
func (s *promptableStub) Probe(context.Context, service.Host) service.Support {
	return service.Supported()
}
func (s *promptableStub) Attach(context.Context, service.Host) (service.Instance, error) {
	return nil, nil
}
func (s *promptableStub) SetPrompter(prompt.Prompter) { s.seen[s.id] = true }

type unpromptableStub struct{ id string }

func (s *unpromptableStub) Meta() service.Meta { return service.Meta{ID: s.id} }
func (s *unpromptableStub) Probe(context.Context, service.Host) service.Support {
	return service.Supported()
}
func (s *unpromptableStub) Attach(context.Context, service.Host) (service.Instance, error) {
	return nil, nil
}

// A waiting approval is a popup in the middle of the screen.
//
// It was briefly a pair of bands down the top and bottom edges, on the theory
// that you would want to see the board while deciding. In front of a real
// terminal that theory was simply wrong: edges are where a interface puts the
// things you are meant to ignore, and a question that has stopped the world
// belongs in the middle of it where it cannot be read as chrome.
func TestAWaitingApprovalIsAPopupInTheMiddle(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(
		row(3000, 3000, "node vite"), row(5173, 5174, "vite --host"))})

	reply := make(chan prompt.Choice, 1)
	request := prompt.Request{
		Host: "bedev", Subject: "op://Personal/Docker/PAT", TTL: 5 * time.Minute,
		Rows:   []prompt.Row{{Label: "command", Value: "op read op://Personal/Docker/PAT"}},
		Caller: service.Caller{User: "jsc", Host: "bedev", Program: "deploy.sh", PID: 4412},
	}
	m.Update(approvalMsg{request: request, options: prompt.MenuFor(request), reply: reply})

	view := plainView(m)
	// The question, in full.
	for _, want := range []string{
		"bedev wants", "op://Personal/Docker/PAT",
		"op read op://Personal/Docker/PAT", "deploy.sh",
		"are not verified",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the band is missing %q:\n%s", want, view)
		}
	}
	// And it is centred, not pinned to an edge: the first and last rows of the
	// frame are still the frame's own borders.
	lines := strings.Split(view, "\n")
	if !strings.Contains(lines[0], "devtun") {
		t.Errorf("the top of the frame is not the header:\n%s", view)
	}
	if !strings.Contains(lines[len(lines)-1], "╰") {
		t.Errorf("the bottom of the frame is not its own border:\n%s", view)
	}
}

// Every answer is on screen. A security menu that shows one option and a count
// is asking somebody to decide blind, and the order — every approval above
// every refusal — only protects you if you can see it.
func TestEveryAnswerIsVisibleRatherThanCollapsed(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	reply := make(chan prompt.Choice, 1)
	request := prompt.Request{Host: "bedev", Subject: "op://V/I/F", TTL: 5 * time.Minute}
	options := prompt.MenuFor(request)
	m.Update(approvalMsg{request: request, options: options, reply: reply})

	view := plainView(m)
	for _, option := range options {
		if !strings.Contains(view, option.Label) {
			t.Errorf("the answer %q is not on screen:\n%s", option.Label, view)
		}
	}
}

// The answers are numbered on screen, so the numbers answer: somebody who has
// just been interrupted should not have to work out a cursor to say no.
func TestANumberAnswersTheQuestion(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	reply := make(chan prompt.Choice, 1)
	request := prompt.Request{Host: "bedev", Subject: "op://V/I/F", TTL: 5 * time.Minute}
	options := prompt.MenuFor(request)
	m.Update(approvalMsg{request: request, options: options, reply: reply})

	send(m, "1")
	select {
	case got := <-reply:
		if got != options[0].Choice {
			t.Errorf("pressing 1 answered %v, want %v", got, options[0].Choice)
		}
	default:
		t.Fatal("pressing 1 did not answer the question")
	}
	if m.approval != nil {
		t.Error("the band is still on screen after being answered")
	}
}
