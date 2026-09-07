//go:build linux || freebsd || openbsd || netbsd || dragonfly

// The Unix desktop choosers.
//
// There is no one dialog program on Linux, so devtun uses whichever of the
// three common ones is installed: zenity (GTK, and what GNOME ships), kdialog
// (KDE), yad (a zenity fork that outlives it on some distributions). None is a
// dependency — with none of them present, `--prompt auto` is the terminal, and
// `--prompt dialog` says which programs it looked for.
//
// zenity is first because it is the one most likely to be there and to look
// like the rest of the desktop. Each is asked for a single-selection list of
// the same labels the terminal menu offers, so the wording of a security
// question cannot differ by which desktop you happen to run.
package prompt

import (
	"context"
	"os"
	"strconv"
	"strings"
)

func choosers() []chooser {
	return []chooser{zenityChooser{bin: "zenity"}, kdialogChooser{}, zenityChooser{bin: "yad"}}
}

// zenityChooser drives zenity, or yad, whose list dialog takes the same flags.
type zenityChooser struct{ bin string }

func (z zenityChooser) name() string { return z.bin }

func (z zenityChooser) available() bool { return hasDisplay() && haveProgram(z.bin) }

func (z zenityChooser) ask(ctx context.Context, title, prompt string, labels []string) (string, error) {
	args := []string{
		"--list",
		"--title=" + title,
		"--text=" + prompt,
		"--column=Answer",
		"--hide-header",
		"--ok-label=Approve",
		"--cancel-label=Deny",
		"--width=560",
		"--height=340",
	}
	args = append(args, labels...)

	answer, err := runChooser(ctx, z.bin, args...)
	if err != nil {
		return "", err
	}
	// Both print the row's columns joined by the separator. There is one
	// column here, so anything after the first is decoration — yad in
	// particular appends a trailing one.
	if before, _, found := strings.Cut(answer, "|"); found {
		answer = before
	}
	return answer, nil
}

// kdialogChooser drives KDE's kdialog.
//
// Its menu prints the *tag* of the chosen row rather than its text, so the tags
// are indices and the label is looked up here. That is a feature: it means a
// label containing anything at all cannot be confused with a tag.
type kdialogChooser struct{}

func (kdialogChooser) name() string { return "kdialog" }

func (kdialogChooser) available() bool { return hasDisplay() && haveProgram("kdialog") }

func (kdialogChooser) ask(ctx context.Context, title, prompt string, labels []string) (string, error) {
	args := []string{"--title", title, "--menu", prompt}
	for i, label := range labels {
		args = append(args, strconv.Itoa(i), label)
	}
	answer, err := runChooser(ctx, "kdialog", args...)
	if err != nil || answer == denySentinel {
		return answer, err
	}
	index, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || index < 0 || index >= len(labels) {
		// An answer that is not one of the tags we offered is not an answer.
		// Returning it unchanged lets the caller fail closed on it.
		return answer, nil
	}
	return labels[index], nil
}

// hasDisplay reports whether there is a graphical session to draw a window on.
//
// It matters on Unix and only there: a dialog program on a box reached over SSH
// will happily start, fail to connect to a display, and exit non-zero seconds
// later — which works, but spends those seconds not asking the person who is
// sitting at a terminal right now.
func hasDisplay() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
