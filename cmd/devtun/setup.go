package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/ui"
)

// errNobodyToAsk means the question could not be put, which is different from
// having been put and answered no.
var errNobodyToAsk = errors.New("no terminal to ask on")

// askSetupOnTerminal puts the shell-rc question to someone watching a log.
//
// It shows the exact file and the exact block before asking, because "may I
// edit a file in your home directory on another machine" is not a question
// anybody should answer without seeing what the edit is. The TUI asks the same
// question as a modal; both go through session.AskSetup, so the two can only
// differ in presentation.
func askSetupOnTerminal(ctx context.Context, plan session.RCPlan) (bool, error) {
	if !ui.IsInteractive() {
		// Nobody is watching, and silently editing someone's shell rc from an
		// unattended run is exactly the behaviour that makes a tool untrusted.
		//
		// This is an error rather than a "no" on purpose: a "no" is remembered,
		// and a single piped run must not permanently suppress a question the
		// human has never actually been asked.
		return false, errNobodyToAsk
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", ui.Banner.Render("devtun needs one line in your shell on the remote box"))
	fmt.Fprintf(&b, "  file  %s\n", ui.Host.Render(plan.File))
	for _, line := range plan.Lines {
		fmt.Fprintf(&b, "        %s\n", ui.OK.Render(line))
	}
	fmt.Fprintf(&b, "\n%s\n", ui.Muted.Render(
		"It goes in a marked block, so devtun can find and replace it later rather than\n"+
			"appending a second copy. Say no and it will just tell you what to paste."))
	fmt.Fprint(os.Stderr, ui.Panel.Render(strings.TrimRight(b.String(), "\n"))+"\n")

	fmt.Fprint(os.Stderr, "Add it for you? [y/N] ")

	// Read from the terminal rather than stdin generally: stdin may be a pipe
	// feeding something else entirely.
	answer := make(chan bool, 1)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			answer <- false
			return
		}
		answer <- strings.EqualFold(strings.TrimSpace(line), "y")
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr)
		return false, ctx.Err()
	case yes := <-answer:
		return yes, nil
	}
}
