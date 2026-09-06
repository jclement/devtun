// Native macOS approval dialog.
//
// This is the one place the 1Password service shells out to something platform-
// specific, and
// it is deliberately optional: everything works with the terminal prompt alone.
// It earns its keep because devtun usually runs in a window you are not
// looking at, and a dialog that comes to the front is the difference between
// noticing an unexpected secret request and clicking past it.
//
// AppleScript's `choose from list` is used rather than `display dialog` because
// the latter caps out at three buttons and there are five answers worth giving.
package prompt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// denySentinel is what the script prints when the dialog is cancelled. A
// sentinel rather than an exit code keeps a cancelled dialog distinguishable
// from osascript failing to run at all.
const denySentinel = "__DEVTUN_DENY__"

// Dialog asks with a native desktop dialog, falling back to another prompter if
// the dialog cannot be shown (no window server on a headless login, say).
type Dialog struct {
	fallback Prompter
}

// dialogAvailable reports whether the native dialog can be used on this build.
func dialogAvailable() bool {
	_, err := exec.LookPath("osascript")
	return err == nil
}

// Ask shows the dialog and maps the selected label back to a Choice.
func (d *Dialog) Ask(ctx context.Context, request Request) (Choice, error) {
	labels, choices := dialogOptions(request)

	script := buildChooserScript(
		"devtun — 1Password",
		dialogPrompt(request),
		labels,
	)

	command := exec.CommandContext(ctx, "osascript", "-e", script)
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return ChoiceDeny, ctx.Err()
		}
		if d.fallback != nil {
			return d.fallback.Ask(ctx, request)
		}
		return ChoiceDeny, fmt.Errorf("showing approval dialog: %w", err)
	}

	selected := strings.TrimSpace(string(output))
	if selected == denySentinel || selected == "" {
		return ChoiceDeny, nil
	}
	for i, label := range labels {
		if label == selected {
			return choices[i], nil
		}
	}
	// An answer we cannot map is not an answer. Refusing is the safe reading.
	return ChoiceDeny, errors.New("unrecognised answer from approval dialog")
}

// dialogOptions is the shared menu minus Deny, which the dialog expresses as
// its cancel button — so closing it, pressing Escape and clicking Deny all mean
// the same thing.
func dialogOptions(request Request) (labels []string, choices []Choice) {
	for _, item := range MenuFor(request) {
		if item.Choice == ChoiceDeny {
			continue
		}
		labels = append(labels, item.Label)
		choices = append(choices, item.Choice)
	}
	return labels, choices
}

// dialogPrompt is the body text. It stays short: a dialog nobody reads is worse
// than no dialog, and the detail is available in the proxy's log either way.
func dialogPrompt(request Request) string {
	lines := []string{
		fmt.Sprintf("%s is asking for:", request.Host),
		"",
		request.Subject,
	}
	if caller := describeCaller(request); caller != "" {
		lines = append(lines, "", caller+"  (unverified)")
	}
	return strings.Join(lines, "\n")
}

// buildChooserScript assembles the AppleScript. Cancelling the dialog — by the
// Deny button, Escape, or closing it — takes the `false` branch, so every way
// of dismissing it means no.
func buildChooserScript(title, prompt string, labels []string) string {
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[i] = applescriptString(label)
	}
	var script strings.Builder
	// `activate` brings the dialog forward when osascript is allowed to become
	// the front application; when it is not, the dialog still appears, just
	// behind. Wrapped in a try so the refusal is never fatal.
	script.WriteString("try\n\tactivate\nend try\n")
	fmt.Fprintf(&script, "set theOptions to {%s}\n", strings.Join(quoted, ", "))
	fmt.Fprintf(&script,
		"set theAnswer to choose from list theOptions with title %s with prompt %s default items {%s} OK button name \"Approve\" cancel button name \"Deny\"\n",
		applescriptString(title), applescriptString(prompt), quoted[0])
	fmt.Fprintf(&script, "if theAnswer is false then\n\treturn %s\nelse\n\treturn item 1 of theAnswer\nend if\n",
		applescriptString(denySentinel))
	return script.String()
}

// applescriptString quotes a Go string as an AppleScript literal.
func applescriptString(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(s) + `"`
}
