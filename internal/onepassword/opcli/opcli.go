// Package opcli runs the real 1Password CLI on the workstation.
//
// It is a thin wrapper on purpose. The service's job is to decide *whether* a
// command runs, not to reinterpret it, so this package changes nothing about
// the arguments it is given — the guard in package policy has already rejected
// anything that should not get here.
package opcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// DefaultTimeout bounds a single op invocation. It is generous because the
// first call after a lock waits for the user to authenticate with Touch ID.
const DefaultTimeout = 2 * time.Minute

// Runner executes op.
//
// Which 1Password account a call belongs to is decided per request by the
// caller, not held here: one session commonly serves a work account and a
// personal one, routed by the vault the reference names.
type Runner struct {
	// Path is the resolved op executable.
	Path string
	// Timeout bounds a single invocation.
	Timeout time.Duration
}

// Result is the outcome of one op invocation. A non-zero Exit is not a Go
// error: op uses exit codes to report ordinary conditions such as "no such
// item", and those belong to the caller on the remote box.
type Result struct {
	Exit   int
	Stdout []byte
	Stderr []byte
}

// New locates op and returns a runner. The error names the install step,
// because a missing op is the single most likely first-run failure.
func New(path string) (*Runner, error) {
	if path == "" {
		path = "op"
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("cannot find the 1Password CLI (%q) on this machine; install it with `brew install 1password-cli`: %w", path, err)
	}
	return &Runner{Path: resolved, Timeout: DefaultTimeout}, nil
}

// Run executes op with argv and the given stdin. An empty account lets op use
// whichever it considers the default.
func (r *Runner) Run(ctx context.Context, account string, argv []string, stdin []byte) (Result, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := argv
	if account != "" {
		args = append([]string{"--account", account}, args...)
	}

	command := exec.CommandContext(ctx, r.Path, args...)
	// op needs the user's own environment to find its session, its account
	// configuration and the desktop app it talks to for biometric unlock.
	command.Env = os.Environ()
	if len(stdin) > 0 {
		command.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return result, nil
	case errors.As(err, &exitErr):
		result.Exit = exitErr.ExitCode()
		return result, nil
	case ctx.Err() != nil:
		return result, fmt.Errorf("op timed out after %s (is 1Password waiting for you to unlock it?)", timeout)
	default:
		return result, fmt.Errorf("running op: %w", err)
	}
}
