// The macOS chooser: osascript.
//
// AppleScript's `choose from list` is used rather than `display dialog` because
// the latter caps out at three buttons and there are more answers than that
// worth giving.
package prompt

import (
	"context"
	"fmt"
	"strings"
)

// choosers is what this platform can ask with, best first.
//
// prettyprompt leads when it is installed, because the difference between the
// two is whether the person actually reads the question. osascript is what
// every Mac has, so it is the one that is always there.
func choosers() []chooser { return []chooser{prettyPromptChooser{}, osascriptChooser{}} }

type osascriptChooser struct{}

func (osascriptChooser) name() string { return "osascript" }

// available only asks whether osascript exists. Unlike the Unix helpers there
// is no display variable to check: on macOS a GUI session either exists or the
// dialog fails immediately, and immediately is cheap.
func (osascriptChooser) available() bool { return haveProgram("osascript") }

func (osascriptChooser) ask(ctx context.Context, title, prompt string, labels []string) (string, error) {
	return runChooser(ctx, "osascript", "-e", buildChooserScript(title, prompt, labels))
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
