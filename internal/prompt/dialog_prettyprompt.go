//go:build darwin

// prettyprompt, when it is installed.
//
// osascript's `choose from list` is a system list box from 1993 with the
// question crammed into a prompt line above it. It works, and for the question
// devtun asks — a remote box wants to sign with your key, right now, for this
// destination — "it works" is doing a lot of heavy lifting. Somebody who
// glances at that dialog and clicks the top item has not really been asked.
//
// prettyprompt (github.com/jclement/prettyprompt) draws a themed panel in the
// middle of the display you are looking at, with markdown in the body and a
// danger theme for exactly this kind of question. It is a separate program
// devtun neither ships nor requires: found on PATH it is used, and when it is
// not, osascript is still there.
package prompt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// prettyPromptName is the binary. Not configurable: this is a program devtun
// recognises, not one it is pointed at.
const prettyPromptName = "prettyprompt"

type prettyPromptChooser struct{}

func (prettyPromptChooser) name() string { return prettyPromptName }

func (prettyPromptChooser) available() bool { return haveProgram(prettyPromptName) }

// ask puts the menu up and reads the answer back as JSON.
//
// --json rather than the bare value, because the bare form prints nothing at
// all for a cancel and nothing at all for a timeout, and those are the same
// empty string as a bug that printed nothing. A security prompt should not have
// to guess which of those just happened.
func (prettyPromptChooser) ask(ctx context.Context, title, prompt string, labels []string) (string, error) {
	args := []string{"choose", title, "--message", prompt, "--json",
		// The question is always the same kind of question: something on
		// another machine wants to use something of yours, now.
		"--theme", "danger",
		"--icon", prettyPromptIcon(title),
		// Centre of the display being looked at, rather than wherever the
		// mouse happens to be resting.
		"--screen", "focused",
	}
	for _, label := range labels {
		args = append(args, "-o", label)
	}
	// devtun already bounds the request; telling prettyprompt as well means the
	// panel takes itself off screen when the answer stops mattering, rather
	// than sitting there inviting an answer to a question that has expired.
	if deadline, ok := ctx.Deadline(); ok {
		if seconds := int(time.Until(deadline).Seconds()); seconds > 0 {
			args = append(args, "--timeout", fmt.Sprint(seconds), "--on-timeout", "cancel")
		}
	}

	output, err := runChooser(ctx, prettyPromptName, args...)
	if err != nil {
		return "", err
	}
	return parsePrettyPrompt(output)
}

// parsePrettyPrompt reads the one line of JSON prettyprompt prints.
//
// Anything that is not an outright answer is a refusal: a cancel is a person
// saying no, and a timeout is devtun's own deadline arriving. Both are the zero
// value of a decision, and neither is an error worth falling back over — the
// question was asked and it was not answered yes.
func parsePrettyPrompt(output string) (string, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		// It exited without printing, which is what a cancel does when --json
		// is somehow not honoured. Treated as the refusal it almost certainly
		// is rather than as a reason to ask again somewhere else.
		return denySentinel, nil
	}
	var result struct {
		Status string `json:"status"`
		Value  string `json:"value"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return "", fmt.Errorf("prettyprompt printed something that is not JSON: %q", output)
	}
	switch result.Status {
	case "ok":
		return result.Value, nil
	case "cancelled", "timeout":
		return denySentinel, nil
	default:
		return "", fmt.Errorf("prettyprompt reported status %q", result.Status)
	}
}

// prettyPromptIcon picks an SF Symbol from the window title, which is already
// named after the kind of thing being asked for.
func prettyPromptIcon(title string) string {
	switch {
	case strings.Contains(title, "key"), strings.Contains(title, "sign"):
		return "key.fill"
	case strings.Contains(title, "site"), strings.Contains(title, "open"):
		return "globe"
	default:
		return "lock.fill"
	}
}
