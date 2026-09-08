package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/ui"
)

// A waiting approval takes over the frame's edges rather than covering the
// middle of it.
//
// It was a centred modal, and a modal is the wrong shape for this. Deciding
// whether a box may read a secret is a decision you often want to make *while
// looking at what that box is doing* — which port just opened, what the last
// thing in the log was — and a panel over the middle of the screen hides
// exactly that. So the request goes in a band across the top, the answers go in
// a band across the bottom, both red, and the board stays legible between them.
//
// Red is not decoration here. It is the one state where devtun is holding
// something open and waiting for a person, and the cost of not noticing is a
// timeout that reads as a refusal somebody never made.

// approvalPending reports whether a question is on screen.
func (m *Model) approvalPending() bool { return m.approval != nil }

// approvalBanner is the band under the tab rule: who is asking, for what, and
// every detail the service supplied.
//
// All of it, not a summary. The detail rows are what make an approval a
// decision rather than a reflex — "deploy.sh in ~/projects/api wants this" is a
// different question from "something wants this" — and the unverified caveat is
// the line that stops those details being read as fact. A band that dropped
// them to stay one row tall would be a prettier way of asking somebody to guess.
func (m *Model) approvalBanner() []string {
	a := m.approval
	if a == nil {
		return nil
	}

	subject := a.request.Subject
	if scope := a.request.ScopeSuffix(); scope != "" {
		subject += scope
	}
	head := ui.Danger.Render(a.request.Host+" wants ") + ui.Secret.Render(subject)
	if left := approvalLeft(a.deadline, m.d.now()); left != "" {
		head += ui.Muted.Render("  ·  " + left)
	}
	lines := []string{head}

	row := func(label, value string) {
		if value == "" {
			return
		}
		lines = append(lines, ui.Muted.Render(pad(label, 8))+" "+value)
	}
	for _, r := range a.request.Rows {
		row(r.Label, r.Value)
	}
	row("caller", describeCaller(a.request))
	row("cwd", a.request.Caller.CWD)
	// The caveat only belongs on screen when there are caller details to
	// caveat. An agent connection carries no provenance at all, and a warning
	// about information that is not shown trains people to skip the line.
	if a.request.Caller != (service.Caller{}) {
		lines = append(lines, ui.Muted.Render("caller details come from the remote box and are not verified"))
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, m.boxLine(clampWidth(line, m.inner())))
	}
	return out
}

// approvalBannerHeight is how many rows the request band takes, which the body
// has to give up.
func (m *Model) approvalBannerHeight() int { return len(m.approvalBanner()) }

// approvalLeft is how long until the question answers itself with a refusal.
//
// Worth showing for the same reason the modal showed it: a person deciding may
// be in another window, and a question that silently becomes a no is worse
// than one that says it is about to.
func approvalLeft(deadline, now time.Time) string {
	if deadline.IsZero() {
		return ""
	}
	if left := deadline.Sub(now); left > 0 {
		return FormatAge(left) + " to answer"
	}
	return "no longer waiting"
}

// approvalOptions is the band along the bottom: every answer, with the one
// under the cursor marked.
//
// Every answer, wrapped over as many rows as it takes rather than collapsed to
// the selected one. A menu that shows a single option and a count is asking
// somebody to scroll through a security decision blind — and this menu's whole
// design is that the order is visible, with every approval above every refusal
// so overshooting downward cannot land on a yes.
//
// Numbered as well as highlighted. ↑↓ and enter is what the modal used and what
// the hands know, but somebody who has just been interrupted should not have to
// work out a cursor before they can say no.
func (m *Model) approvalOptions() []string {
	a := m.approval
	if a == nil {
		return nil
	}

	rendered := make([]string, len(a.options))
	widths := make([]int, len(a.options))
	for i, option := range a.options {
		label := fmt.Sprintf("%d %s", i+1, option.Label)
		widths[i] = ansi.StringWidth(label) + 2 // the padding the cursor adds
		switch {
		case i == a.cursor:
			rendered[i] = ui.Selected.Reverse(true).Render(" " + label + " ")
		case option.Choice.Allows():
			rendered[i] = " " + ui.Muted.Render(label) + " "
		default:
			rendered[i] = " " + ui.Error.Render(label) + " "
		}
	}

	const gap = 2
	var out []string
	var row strings.Builder
	used := 0
	for i, cell := range rendered {
		width := widths[i]
		if used > 0 && used+gap+width > m.inner() {
			out = append(out, m.boxLine(row.String()))
			row.Reset()
			used = 0
		}
		if used > 0 {
			row.WriteString(strings.Repeat(" ", gap))
			used += gap
		}
		row.WriteString(cell)
		used += width
	}
	if used > 0 {
		out = append(out, m.boxLine(row.String()))
	}
	return out
}

// approvalOptionsHeight is how many rows the answers take.
func (m *Model) approvalOptionsHeight() int { return len(m.approvalOptions()) }

// approvalHint is the bottom border's label while a question is waiting. It
// replaces the key bar, because none of those keys does anything right now.
func (m *Model) approvalHint() string {
	return ui.Danger.Render("↑↓ choose") + ui.Muted.Render(" · ") +
		ui.Danger.Render("enter") + ui.Muted.Render(" answer · ") +
		ui.Danger.Render("esc") + ui.Muted.Render(" refuse")
}
