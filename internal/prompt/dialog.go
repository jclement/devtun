// The desktop approval dialog, on whatever this machine has to draw one with.
//
// devtun usually runs in a window you are not looking at. A dialog that comes
// to the front is the difference between noticing an unexpected secret request
// and clicking past it, which is the whole argument for the feature — so this
// is optional everywhere and works with the terminal prompt alone.
//
// There is no bundled GUI toolkit and there is not going to be one: every Go
// option that draws its own window wants cgo, and devtun is a static binary you
// copy to three operating systems. What every desktop does have is a program
// whose entire job is to ask a question — osascript on macOS, zenity or kdialog
// on a Linux desktop, PowerShell's Windows Forms on Windows. Each is a chooser
// here, they are tried in order, and the terminal is what happens when none of
// them is there.
package prompt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// denySentinel is what a chooser's script prints when the dialog is cancelled.
// A sentinel rather than an exit code keeps a cancelled dialog distinguishable
// from the helper failing to run at all.
const denySentinel = "__DEVTUN_DENY__"

// chooser is one way of putting a list of answers in front of a person.
//
// It deals in labels rather than in Choices on purpose: the menu is built once,
// in MenuFor, and a chooser that knew what the options meant would be a second
// place for the wording of a security question to drift.
type chooser interface {
	// name is what the log calls it when it fails.
	name() string
	// available reports whether it can be used right now — the program exists
	// and there is a desktop to draw on.
	available() bool
	// ask shows the list and returns the chosen label, denySentinel or "" for
	// a refusal, and an error only when the dialog could not be shown at all.
	ask(ctx context.Context, title, prompt string, labels []string) (string, error)
}

// pickChooser returns the first usable chooser for this machine.
func pickChooser() chooser {
	for _, c := range choosers() {
		if c.available() {
			return c
		}
	}
	return nil
}

// dialogAvailable reports whether a desktop dialog can be shown here.
func dialogAvailable() bool { return pickChooser() != nil }

// DialogBackend names the chooser that would be used, for `devtun doctor` and
// for the error message when someone asks for a dialog on a machine with none.
// It is empty when there is no usable one.
func DialogBackend() string {
	if c := pickChooser(); c != nil {
		return c.name()
	}
	return ""
}

// chooserNames lists what this platform would look for, so an error can say
// what to install rather than only that something is missing.
func chooserNames() []string {
	var names []string
	for _, c := range choosers() {
		names = append(names, c.name())
	}
	if len(names) == 0 {
		names = append(names, "nothing — no dialog program is known for this platform")
	}
	return names
}

// Dialog asks with a desktop dialog, falling back to another prompter when one
// cannot be shown — a headless login, a machine with no helper installed, or a
// helper that failed on the day.
type Dialog struct {
	fallback Prompter
	// chooser overrides the platform pick. Tests set it; nothing else does.
	chooser chooser
}

// Ask shows the dialog and maps the selected label back to a Choice.
func (d *Dialog) Ask(ctx context.Context, request Request) (Choice, error) {
	pick := d.chooser
	if pick == nil {
		pick = pickChooser()
	}
	if pick == nil {
		return d.fall(ctx, request, errors.New("no desktop dialog program on this machine"))
	}

	labels, choices := dialogOptions(request)
	selected, err := pick.ask(ctx, dialogTitle(request), dialogPrompt(request), labels)
	if err != nil {
		if ctx.Err() != nil {
			return ChoiceDeny, ctx.Err()
		}
		return d.fall(ctx, request, fmt.Errorf("showing the %s approval dialog: %w", pick.name(), err))
	}

	selected = strings.TrimSpace(selected)
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

// fall hands the question to the fallback prompter, or reports why it could
// not be asked. A dialog that cannot be drawn must never become a silent
// approval, and must not become a silent refusal either when there is a
// terminal right there.
func (d *Dialog) fall(ctx context.Context, request Request, cause error) (Choice, error) {
	if d.fallback != nil {
		return d.fallback.Ask(ctx, request)
	}
	return ChoiceDeny, cause
}

// dialogTitle names the window after what is being asked for, since a dialog
// that says "1Password" while asking about an SSH key is worse than one with no
// title at all.
func dialogTitle(request Request) string {
	switch request.SubjectNoun() {
	case "key":
		return "devtun — SSH agent"
	default:
		return "devtun — 1Password"
	}
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
// than no dialog, and the detail is available in the log either way.
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

// lookPath is exec.LookPath, indirected so a test can pretend a helper is or is
// not installed without writing files into a directory on the real PATH.
var lookPath = exec.LookPath

func haveProgram(name string) bool {
	_, err := lookPath(name)
	return err == nil
}

// runChooser executes a dialog helper and reads the answer off its stdout.
//
// Exit status 1 with nothing printed is how zenity, kdialog and yad all report
// "cancelled", and cancelled is a refusal, not a failure — it must never reach
// the fallback prompter and ask the same question twice. Any other failure is a
// helper that could not run, which is exactly what the fallback is for.
func runChooser(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.Output()
	answer := strings.TrimRight(string(output), "\r\n")
	if err == nil {
		return answer, nil
	}
	if answer != "" {
		// It printed an answer and then failed at something else; the answer
		// is what the person said.
		return answer, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return denySentinel, nil
	}
	return "", err
}
