// Asking the person at the keyboard.
//
// Everything this package can need a human for — an unknown host key, a key
// passphrase, a password, a keyboard-interactive challenge — goes through one
// small interface rather than through a UI package. That keeps the transport
// free of any opinion about how questions are rendered, and it makes "there is
// nobody to ask" a single, testable state: a nil Prompter.
package sshx

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNoTerminal is what an operation returns when it needs an answer and there
// is nobody to give one.
var ErrNoTerminal = errors.New("no terminal available for prompting")

// Prompter asks the user questions. A nil Prompter means an unattended run:
// anything that would need an answer fails instead of hanging.
type Prompter interface {
	// Confirm asks a yes/no question.
	Confirm(question string) (bool, error)
	// Secret reads a line without echoing it.
	Secret(prompt string) (string, error)
	// Line reads an echoed line.
	Line(prompt string) (string, error)
	// Notice prints an informational message.
	Notice(msg string)
}

// TerminalPrompter asks questions on a real terminal. All prompting happens
// before the TUI starts, so it can own the terminal freely.
type TerminalPrompter struct {
	in  *os.File
	out io.Writer
	r   *bufio.Reader
}

// NewTerminalPrompter returns a Prompter reading from in and writing to out.
// It returns nil when in is not a terminal, which callers treat as "cannot
// ask" — so the nil check that follows is the whole unattended path.
func NewTerminalPrompter(in *os.File, out io.Writer) *TerminalPrompter {
	if in == nil || !term.IsTerminal(int(in.Fd())) {
		return nil
	}
	return &TerminalPrompter{in: in, out: out, r: bufio.NewReader(in)}
}

// Notice prints an informational message.
func (p *TerminalPrompter) Notice(msg string) {
	fmt.Fprintln(p.out, msg)
}

// Confirm asks a yes/no question, repeating until it gets an answer.
func (p *TerminalPrompter) Confirm(question string) (bool, error) {
	for {
		fmt.Fprintf(p.out, "%s (yes/no) ", question)
		line, err := p.r.ReadString('\n')
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "yes", "y":
			return true, nil
		case "no", "n":
			return false, nil
		}
		fmt.Fprintln(p.out, `Please type "yes" or "no".`)
	}
}

// Line reads an echoed line of input.
func (p *TerminalPrompter) Line(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	line, err := p.r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// Secret reads a line with echo disabled.
func (p *TerminalPrompter) Secret(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	b, err := term.ReadPassword(int(p.in.Fd()))
	fmt.Fprintln(p.out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// notify shows a message if there is anyone to show it to.
func notify(p Prompter, msg string) {
	if p != nil {
		p.Notice(msg)
	}
}
