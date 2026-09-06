package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/ui"
)

// Prompter asks for approval inside the running interface.
//
// It exists because the other three prompters cannot: a huh form and an
// osascript dialog both want a terminal, and under the TUI the terminal is
// already spoken for. So the question becomes a message, the answer comes back
// on a channel, and the modal is drawn by the same renderer as everything else.
//
// Ask is called from a per-connection goroutine and never from the UI
// goroutine — which is exactly why the reply is a channel rather than a
// callback, and why every path out of it that is not a human pressing a key
// ends in ChoiceDeny.
type Prompter struct {
	mu      sync.Mutex
	program *tea.Program
}

var _ prompt.Prompter = (*Prompter)(nil)

// NewPrompter returns a Prompter with nothing attached. Until a program is,
// it refuses: there is nobody to ask.
func NewPrompter() *Prompter { return &Prompter{} }

// Attach binds the prompter to the running program. Detach unbinds it, which
// is what makes a question asked after the interface has gone a refusal rather
// than a hang.
func (p *Prompter) Attach(program *tea.Program) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.program = program
}

// Detach unbinds the program.
func (p *Prompter) Detach() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.program = nil
}

func (p *Prompter) attached() *tea.Program {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.program
}

// approvalMsg carries a request into the program, with the channel its answer
// comes back on.
type approvalMsg struct {
	request prompt.Request
	options []prompt.MenuItem
	reply   chan<- prompt.Choice
	// deadline is when the asker gives up, taken from its context. Zero when
	// it has no deadline, in which case nothing is counted down.
	deadline time.Time
}

// approvalCancelMsg withdraws a request whose asker has given up, so the modal
// does not sit there waiting for an answer nobody is listening for.
type approvalCancelMsg struct{ reply chan<- prompt.Choice }

// approvalState is the modal on screen.
type approvalState struct {
	request prompt.Request
	options []prompt.MenuItem
	cursor  int
	reply   chan<- prompt.Choice
	// deadline is when the asker gives up. Showing it matters: the modal is
	// answered by a human who may be in another window, and a question that
	// silently becomes a refusal is worse than one that says it is about to.
	deadline time.Time
}

// Ask puts the request to the human and waits for an answer.
//
// Every way out of here that is not a deliberate choice returns ChoiceDeny,
// which is the zero Choice: a timeout, a cancelled context, an interface that
// has already exited. The caller wraps this with the prompt timeout, and when
// that fires the modal is abandoned — walking away from a prompt is a refusal,
// not an error, so the error is nil.
func (p *Prompter) Ask(ctx context.Context, request prompt.Request) (prompt.Choice, error) {
	program := p.attached()
	if program == nil {
		return prompt.ChoiceDeny, prompt.ErrNoPrompter
	}

	// Buffered, so answering never blocks the UI goroutine even if this one
	// has already walked away on the context.
	reply := make(chan prompt.Choice, 1)
	// The prompt timeout lives on the caller's context, not on the Request, so
	// this is where the countdown has to come from.
	deadline, _ := ctx.Deadline()
	msg := approvalMsg{
		request:  request,
		deadline: deadline,
		// The menu is built once, here, from the shared definition: the
		// terminal, the macOS dialog and this modal must never be able to
		// offer different things.
		options: prompt.MenuFor(request),
		reply:   reply,
	}

	// Send from a goroutine: Program.Send blocks until the program has
	// started, and a request that arrives in that window must still be able to
	// time out. The send unblocks on its own when the program's context is
	// cancelled, so nothing is leaked past the session.
	go program.Send(msg)

	select {
	case choice := <-reply:
		// A select whose cases are both ready picks at random, so an answer
		// arriving in the same instant as the deadline could otherwise be
		// returned as an allow *after* the prompt had timed out. The deadline
		// wins: the zero value of a decision is no, and "no" has to survive a
		// coin toss.
		if ctx.Err() != nil {
			return prompt.ChoiceDeny, nil
		}
		return choice, nil
	case <-ctx.Done():
		go program.Send(approvalCancelMsg{reply: reply})
		return prompt.ChoiceDeny, nil
	}
}

// openApproval puts a request on screen. A second request cannot arrive while
// one is showing — prompt.Serialize guarantees one question at a time — but if
// one somehow did, refusing it is the safe reading.
func (m *Model) openApproval(msg approvalMsg) tea.Cmd {
	if m.approval != nil {
		msg.reply <- prompt.ChoiceDeny
		return nil
	}
	// A request is worth interrupting whatever else is open for.
	m.showHelp, m.showDetail, m.protocolPrompt, m.confirming = false, false, false, false
	m.menu.open = false
	m.closeEditor()
	m.approval = &approvalState{
		request: msg.request, options: msg.options, reply: msg.reply,
		deadline: msg.deadline,
		// Where the cursor starts is the service's call: a one-off secret wants
		// the narrowest option under the cursor, an agent signing for a `git
		// push` wants the session one, or the menu costs a keystroke per
		// signature. The order never changes — only the starting point.
		cursor: prompt.PreferredIndex(msg.options, msg.request.Prefer),
	}
	// Ring the terminal. devtun is meant to run in a window you are not looking
	// at, so a request that only appears on screen is a request that gets
	// answered by its own timeout.
	return func() tea.Msg { return bellMsg{} }
}

// bellMsg asks the view to emit a terminal bell on the next frame.
type bellMsg struct{}

// dismissApproval drops a modal whose asker has given up on it.
func (m *Model) dismissApproval(reply chan<- prompt.Choice) {
	if m.approval != nil && m.approval.reply == reply {
		m.approval = nil
	}
}

// answer sends the choice back and closes the modal.
func (m *Model) answer(choice prompt.Choice) tea.Cmd {
	if m.approval == nil {
		return nil
	}
	m.approval.reply <- choice
	subject := m.approval.request.Subject
	m.approval = nil
	if choice == prompt.ChoiceDeny {
		return m.showToast(toastMsg{text: "denied " + subject, bad: true})
	}
	return m.showToast(toastMsg{text: choice.String() + ": " + subject})
}

func (m *Model) handleApprovalKey(msg tea.KeyPressMsg) tea.Cmd {
	a := m.approval
	switch msg.String() {
	case "up", "k":
		if a.cursor > 0 {
			a.cursor--
		}
	case "down", "j":
		if a.cursor < len(a.options)-1 {
			a.cursor++
		}
	case "enter", " ":
		if a.cursor >= 0 && a.cursor < len(a.options) {
			return m.answer(a.options[a.cursor].Choice)
		}
	case "esc", "q", "n", "ctrl+c":
		// Every way of dismissing this means the same thing.
		return m.answer(prompt.ChoiceDeny)
	}
	return nil
}

// approvalBox renders the request.
//
// The subject carries ui.Secret, the same treatment it gets in the log and in
// the terminal prompt, and the caller details carry the fixed warning that they
// come from the remote box and are not verified — because they are the part a
// hurried reader is most likely to take as proof of who is asking.
func (m *Model) approvalBox() string {
	a := m.approval
	if a == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(ui.Host.Render(a.request.Host) + " wants " + ui.Secret.Render(a.request.Subject) + "\n\n")

	row := func(label, value string) {
		if value == "" {
			return
		}
		b.WriteString(ui.Muted.Render(pad(label, 8)) + " " + value + "\n")
	}
	// The rows come from the service. This used to hardcode `op ` + argv, which
	// put an empty command row in front of anyone approving a signature.
	for _, r := range a.request.Rows {
		row(r.Label, r.Value)
	}
	row("caller", describeCaller(a.request))
	row("cwd", a.request.Caller.CWD)
	// The caveat only belongs on screen when there are caller details to
	// caveat. An agent connection carries no provenance at all, and a warning
	// about information that is not shown trains people to skip the line.
	if a.request.Caller != (service.Caller{}) {
		b.WriteString(ui.Muted.Render("caller details come from the remote box and are not verified") + "\n")
	}
	b.WriteString("\n")

	// Narrowest first, deny last: the safe answer is the one under the cursor
	// and the broad ones take deliberate effort to reach.
	for i, item := range a.options {
		style := ui.Muted
		if item.Choice == prompt.ChoiceDeny {
			style = ui.Error
		}
		if i == a.cursor {
			b.WriteString(ui.Banner.Render("▸ ") + ui.Selected.Render(item.Label) + "\n")
			continue
		}
		b.WriteString("  " + style.Render(item.Label) + "\n")
	}
	b.WriteString("\n" + ui.Muted.Render("↑↓ choose · enter approve · esc deny"))
	if left := time.Until(a.deadline).Round(time.Second); !a.deadline.IsZero() && left > 0 {
		b.WriteString(ui.Muted.Render(fmt.Sprintf("  ·  refuses itself in %s", left)))
	}
	// Violet, the colour that means "vault" everywhere else in devtun. The
	// help and detail overlays share the accent border, so an approval framed
	// like them is one more box to dismiss rather than a question about a
	// secret.
	return m.boxOfStyle(ui.SecretPanel, b.String())
}

func describeCaller(request prompt.Request) string {
	caller := request.Caller
	var parts []string
	if caller.User != "" && caller.Host != "" {
		parts = append(parts, caller.User+"@"+caller.Host)
	}
	if caller.Program != "" {
		parts = append(parts, caller.Program)
	}
	if caller.PID != 0 {
		parts = append(parts, fmt.Sprintf("pid %d", caller.PID))
	}
	return strings.Join(parts, "  ")
}

// --- the shell-rc question -------------------------------------------------

// setupMsg carries the shell-rc question into the program.
type setupMsg struct {
	plan  session.RCPlan
	reply chan<- bool
}

// setupCancelMsg withdraws it.
type setupCancelMsg struct{ reply chan<- bool }

// setupState is the modal on screen.
type setupState struct {
	plan  session.RCPlan
	reply chan<- bool
}

// AskSetup asks whether devtun may add itself to the remote shell rc.
//
// It is the same question cmd/devtun puts to a terminal in log mode, and shows
// the same three things: which file, which lines, and that the edit goes in a
// marked block so it can be found and replaced rather than appended to. As with
// Ask, anything other than a deliberate yes is a no.
func (p *Prompter) AskSetup(ctx context.Context, plan session.RCPlan) (bool, error) {
	program := p.attached()
	if program == nil {
		return false, nil
	}

	reply := make(chan bool, 1)
	go program.Send(setupMsg{plan: plan, reply: reply})

	select {
	case yes := <-reply:
		return yes, nil
	case <-ctx.Done():
		go program.Send(setupCancelMsg{reply: reply})
		return false, nil
	}
}

func (m *Model) handleSetupKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "y", "Y", "enter":
		m.setup.reply <- true
		m.setup = nil
		return m.showToast(toastMsg{text: "adding devtun to your shell on " + m.d.host})
	case "n", "N", "esc", "q", "ctrl+c":
		m.setup.reply <- false
		m.setup = nil
		return m.showToast(toastMsg{text: "left your shell rc alone"})
	}
	return nil
}

func (m *Model) setupBox() string {
	s := m.setup
	if s == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(ui.Banner.Render("devtun needs one line in your shell on "+m.d.host) + "\n\n")
	b.WriteString(ui.Muted.Render(pad("file", 6)) + " " + ui.Host.Render(s.plan.File) + "\n")
	for _, line := range s.plan.Lines {
		b.WriteString(strings.Repeat(" ", 7) + ui.OK.Render(line) + "\n")
	}
	b.WriteString("\n" + ui.Muted.Render(
		"It goes in a marked block, so devtun can find and replace it later rather") + "\n")
	b.WriteString(ui.Muted.Render(
		"than appending a second copy. Say no and it will just tell you what to paste.") + "\n\n")
	b.WriteString(ui.Banner.Render("y") + ui.Muted.Render(" add it") + ui.Muted.Render("   ·   ") +
		ui.Banner.Render("n") + ui.Muted.Render(" leave it alone"))
	return m.boxOf(b.String())
}
