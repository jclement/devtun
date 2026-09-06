// `op` on the remote box.
//
// It is deliberately thin. Anything it does not understand is forwarded
// verbatim to the workstation, which is the only side that knows what is
// allowed; the shim's own opinions would be worthless anyway, since anything
// running on that box could simply not use the shim. The exceptions are the two
// commands whose semantics are *local* — `op inject` and `op run` both act on
// files and processes on the machine that invoked them, so forwarding them
// would read the workstation's files and run the deploy script on the
// workstation.
package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// opCallTimeout bounds a whole `op` exchange. It is long because the far end
// may be waiting for a human to approve, and possibly for Touch ID after that.
const opCallTimeout = 5 * time.Minute

// DispatchOp runs one `op` invocation and returns the process exit code.
func (c *Client) DispatchOp(ctx context.Context, argv []string, s Streams) int {
	// Waiting for a reconnecting session is worth a word on stderr; anything
	// the shim says about its own state belongs there, never on stdout, which
	// carries the secret.
	c.Notify = s.Err

	// The subcommand's own arguments start after it, which is not argv[1:]
	// when global options came first: `op --account work run -- deploy.sh` would
	// otherwise hand `run` the argument list "work run -- deploy.sh" and try to
	// execute "work".
	command, rest := splitCommand(argv)
	switch command {
	case "inject":
		return c.inject(ctx, rest, s)
	case "run":
		return c.runProcess(ctx, rest, s)
	default:
		return c.passthrough(ctx, argv, s)
	}
}

// splitCommand returns the op subcommand and the arguments that follow it,
// skipping any global options in front.
func splitCommand(argv []string) (command string, rest []string) {
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return "", nil
		}
		if !strings.HasPrefix(arg, "-") {
			return arg, argv[i+1:]
		}
		name, _, hasInline := strings.Cut(arg, "=")
		if globalFlagTakesValue(name) && !hasInline {
			i++
		}
	}
	return "", nil
}

// passthrough forwards the command to the workstation untouched.
func (c *Client) passthrough(ctx context.Context, argv []string, s Streams) int {
	var stdin []byte
	if !s.InIsTerminal && s.In != nil {
		data, err := io.ReadAll(io.LimitReader(s.In, MaxFrameBytes))
		if err != nil {
			return fail(s, fmt.Errorf("reading stdin: %w", err))
		}
		stdin = data
	}

	response, err := c.exec(ctx, argv, stdin)
	if err != nil {
		return fail(s, err)
	}
	if len(response.Stdout) > 0 {
		_, _ = s.Out.Write(response.Stdout)
	}
	if len(response.Stderr) > 0 {
		_, _ = s.Err.Write(response.Stderr)
	}
	if response.Error != "" {
		fmt.Fprintln(s.Err, "op (via devtun): "+response.Error)
	}
	return response.Exit
}

// exec forwards an op command and returns the session's response.
func (c *Client) exec(ctx context.Context, argv []string, stdin []byte) (*opResponse, error) {
	var response opResponse
	request := opRequest{Op: opExec, Argv: argv, Stdin: stdin}
	if err := c.converse(ctx, ServiceOp, opCallTimeout, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// resolve turns secret references into values in a single round trip, so a
// template with twenty references costs at most a handful of approvals rather
// than twenty.
func (c *Client) resolve(ctx context.Context, refs []string) (map[string]string, error) {
	var response opResponse
	if err := c.converse(ctx, ServiceOp, opCallTimeout, opRequest{Op: opResolve, Refs: refs}, &response); err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	// A short batch fails the whole thing: a config file three-quarters filled
	// in is a deploy-time failure with no obvious cause.
	if len(response.Secrets) != len(refs) {
		return nil, fmt.Errorf("devtun returned %d of %d requested secrets", len(response.Secrets), len(refs))
	}
	return response.Secrets, nil
}

// leadingCommand returns the op subcommand, skipping the global options that
// may precede it.
//
// Taking the first non-flag argument is not good enough, and the failure is not
// cosmetic: for `op --account work run -- deploy.sh` the first non-flag
// argument is "work", so `run` was not recognised, and a command meant to be
// executed *here* was forwarded to the workstation instead. That is the wrong
// machine for the whole point of the tool, and it was half of a path that let a
// remote box run a string of its choosing on the vault holder.
//
// The workstation guard refuses these independently — it must, since nothing
// here is trusted — but the shim should not be the reason it has to.
func leadingCommand(argv []string) string {
	command, _ := splitCommand(argv)
	return command
}

// globalFlagTakesValue reports whether an `op` global option consumes the next
// argument. It mirrors the table in internal/onepassword/policy, which is the
// authority — the two are separated only because the shim must stay a small
// binary that does not drag policy onto a dev box.
func globalFlagTakesValue(name string) bool {
	switch name {
	case "--account", "--config", "--session", "--format", "--encoding":
		return true
	default:
		return false
	}
}
