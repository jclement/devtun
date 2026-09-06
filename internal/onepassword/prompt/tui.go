// The terminal approval prompt. This is the backend that always works — over
// SSH, inside tmux, on a headless box — so it is the fallback for every other
// one.
package prompt

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/jclement/devtun/internal/ui"
)

// TUI asks in the terminal running devtun.
type TUI struct{}

// Ask renders the request and a menu of grant options.
func (t *TUI) Ask(ctx context.Context, request Request) (Choice, error) {
	if !ui.IsInteractive() {
		return ChoiceDeny, ErrNoPrompter
	}

	choice := ChoiceDeny
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[Choice]().
				Title(headline(request)).
				Description(details(request)).
				Options(optionsFor(request)...).
				Value(&choice),
		),
	).WithShowHelp(true)

	err := form.RunWithContext(ctx)
	switch {
	case err == nil:
		return choice, nil
	case errors.Is(err, huh.ErrUserAborted), errors.Is(err, huh.ErrTimeout), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// Walking away from the prompt is a refusal, not an error.
		return ChoiceDeny, nil
	default:
		return ChoiceDeny, fmt.Errorf("asking for approval: %w", err)
	}
}

// headline is the one line that has to be readable at a glance, because it is
// what someone half-paying-attention will actually act on.
func headline(request Request) string {
	return fmt.Sprintf("%s wants %s", ui.Host.Render(request.Host), ui.Secret.Render(request.Subject))
}

// details lays out the supporting facts, including the warning that the caller
// information cannot be trusted.
func details(request Request) string {
	rows := [][2]string{
		{"command", "op " + strings.Join(request.Argv, " ")},
	}
	if caller := describeCaller(request); caller != "" {
		rows = append(rows, [2]string{"caller", caller})
	}
	if request.Caller.CWD != "" {
		rows = append(rows, [2]string{"cwd", request.Caller.CWD})
	}

	var lines []string
	for _, row := range rows {
		lines = append(lines, ui.Muted.Render(fmt.Sprintf("%-8s", row[0]))+" "+truncate(row[1], 96))
	}
	lines = append(lines, ui.Muted.Render("caller details come from the remote box and are not verified"))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func describeCaller(request Request) string {
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

// optionsFor builds the menu from the shared definition, so the terminal and
// the native dialog can never offer different things.
func optionsFor(request Request) []huh.Option[Choice] {
	menu := MenuFor(request)
	options := make([]huh.Option[Choice], len(menu))
	for i, item := range menu {
		options[i] = huh.NewOption(item.Label, item.Choice)
	}
	return options
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit-1] + "…"
}
