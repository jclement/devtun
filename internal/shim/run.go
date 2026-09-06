// `op run` handled locally.
//
// `op run -- cmd` builds an environment with op:// references resolved and then
// executes cmd. The execution belongs on the box that asked — forwarding it
// would run the user's deploy script on their workstation — so the shim
// resolves the references through devtun and does the exec itself.
package shim

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jclement/devtun/internal/onepassword/opref"
)

// runProcess implements `op run [--env-file f]… [--] command [args…]`.
func (c *Client) runProcess(ctx context.Context, args []string, s Streams) int {
	var envFiles []string
	var command []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			command = args[i+1:]
			i = len(args)
		case arg == "--env-file":
			if i+1 >= len(args) {
				return fail(s, errors.New("--env-file needs a file name"))
			}
			i++
			envFiles = append(envFiles, args[i])
		case strings.HasPrefix(arg, "--env-file="):
			envFiles = append(envFiles, strings.TrimPrefix(arg, "--env-file="))
		case arg == "--no-masking":
			// Accepted and ignored: devtun never masks. Real masking would
			// mean buffering the child's stdout and stderr here, which breaks
			// interactive programs and progress output.
		case strings.HasPrefix(arg, "-"):
			return fail(s, fmt.Errorf("devtun's `op run` does not understand %q", arg))
		default:
			// The first bare word starts the command, with everything after it
			// belonging to that command rather than to op.
			command = args[i:]
			i = len(args)
		}
	}

	if len(command) == 0 {
		return fail(s, errors.New("no command given: use `op run -- your-command`"))
	}

	environment, err := c.buildEnvironment(ctx, envFiles)
	if err != nil {
		return fail(s, err)
	}

	// The child inherits the streams directly rather than through a pipe, so
	// an interactive program stays interactive — which is the same decision
	// that rules out masking.
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Env = environment
	child.Stdin = s.In
	child.Stdout = s.Out
	child.Stderr = s.Err

	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		return fail(s, fmt.Errorf("running %s: %w", command[0], err))
	}
	return 0
}

// buildEnvironment merges the process environment with any --env-file, then
// resolves every value that is a secret reference in one round trip.
func (c *Client) buildEnvironment(ctx context.Context, envFiles []string) ([]string, error) {
	values := environmentMap(os.Environ())
	for _, path := range envFiles {
		entries, err := parseEnvFile(path)
		if err != nil {
			return nil, err
		}
		for key, value := range entries {
			values[key] = value
		}
	}

	var refs []string
	seen := make(map[string]bool)
	for _, value := range values {
		if !strings.HasPrefix(value, opref.Scheme) {
			continue
		}
		if _, err := opref.Parse(value); err != nil {
			continue
		}
		if !seen[value] {
			seen[value] = true
			refs = append(refs, value)
		}
	}

	if len(refs) > 0 {
		secrets, err := c.resolve(ctx, refs)
		if err != nil {
			return nil, err
		}
		for key, value := range values {
			if secret, ok := secrets[value]; ok {
				values[key] = secret
			}
		}
	}

	environment := make([]string, 0, len(values))
	for key, value := range values {
		environment = append(environment, key+"="+value)
	}
	return environment, nil
}

func environmentMap(entries []string) map[string]string {
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		if eq := strings.IndexByte(entry, '='); eq > 0 {
			values[entry[:eq]] = entry[eq+1:]
		}
	}
	return values
}

// parseEnvFile reads KEY=VALUE lines, tolerating comments, blank lines, a
// leading `export`, and quoted values — the shapes that actually appear in the
// .env files people already have.
func parseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the env file %s: %w", path, err)
	}
	values := make(map[string]string)
	for number, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, number+1)
		}
		key := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	return values, nil
}
