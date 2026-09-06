// `op inject` handled locally.
//
// Injection reads a template and writes a filled-in copy. Both of those are
// files on the box that ran the command, so the substitution has to happen
// here; only the secret lookups travel to the workstation, and they travel as
// one batch so a template with twenty references is one approval.
package shim

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jclement/devtun/internal/onepassword/opref"
)

// injectedFileMode is deliberately private to the user: the output of an
// injection is, by construction, a file full of secrets.
const injectedFileMode = 0o600

// inject implements `op inject [-i in] [-o out] [-f]`.
func (c *Client) inject(ctx context.Context, args []string, s Streams) int {
	var inFile, outFile string
	var force bool

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-i" || arg == "--in-file":
			if i+1 >= len(args) {
				return fail(s, fmt.Errorf("%s needs a file name", arg))
			}
			i++
			inFile = args[i]
		case strings.HasPrefix(arg, "--in-file="):
			inFile = strings.TrimPrefix(arg, "--in-file=")
		case arg == "-o" || arg == "--out-file":
			if i+1 >= len(args) {
				return fail(s, fmt.Errorf("%s needs a file name", arg))
			}
			i++
			outFile = args[i]
		case strings.HasPrefix(arg, "--out-file="):
			outFile = strings.TrimPrefix(arg, "--out-file=")
		case arg == "-f" || arg == "--force":
			force = true
		case strings.HasPrefix(arg, "-"):
			// Unknown flags are refused rather than ignored: silently dropping
			// one would produce a file that looks right and is not.
			return fail(s, fmt.Errorf("devtun's `op inject` does not understand %q", arg))
		default:
			return fail(s, fmt.Errorf("unexpected argument %q", arg))
		}
	}

	template, err := readTemplate(inFile, s)
	if err != nil {
		return fail(s, err)
	}

	refs := opref.Find(template)
	filled := template
	if len(refs) > 0 {
		// Nothing is written until every reference has a value; see resolve.
		secrets, err := c.resolve(ctx, refs)
		if err != nil {
			return fail(s, err)
		}
		filled = substitute(template, refs, secrets)
	}

	if outFile == "" {
		_, _ = io.WriteString(s.Out, filled)
		return 0
	}
	if !force {
		if _, err := os.Stat(outFile); err == nil {
			return fail(s, fmt.Errorf("%s already exists; pass --force to overwrite it", outFile))
		}
	}
	if err := os.WriteFile(outFile, []byte(filled), injectedFileMode); err != nil {
		return fail(s, fmt.Errorf("writing %s: %w", outFile, err))
	}
	return 0
}

func readTemplate(inFile string, s Streams) (string, error) {
	if inFile == "" {
		if s.InIsTerminal || s.In == nil {
			return "", fmt.Errorf("no template given: pass --in-file, or pipe one in")
		}
		data, err := io.ReadAll(s.In)
		if err != nil {
			return "", fmt.Errorf("reading the template from stdin: %w", err)
		}
		return string(data), nil
	}
	data, err := os.ReadFile(inFile)
	if err != nil {
		return "", fmt.Errorf("reading the template %s: %w", inFile, err)
	}
	return string(data), nil
}

// substitute replaces references longest-first, so that a reference which is a
// prefix of another (op://v/i/pass and op://v/i/password) cannot corrupt it.
func substitute(template string, refs []string, secrets map[string]string) string {
	ordered := make([]string, len(refs))
	copy(ordered, refs)
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if len(ordered[j]) > len(ordered[i]) {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	replacements := make([]string, 0, len(ordered)*2)
	for _, ref := range ordered {
		replacements = append(replacements, ref, secrets[ref])
	}
	return strings.NewReplacer(replacements...).Replace(template)
}
