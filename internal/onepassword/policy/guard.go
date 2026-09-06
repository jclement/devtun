// The guard is the layer that runs before any human is asked anything. Policy
// decides *which secrets* a host may have; the guard decides *what shape of
// command* is allowed to reach the local `op` at all.
//
// It matters because the proxy runs commands against an unlocked vault on the
// user's own machine. Without a guard, "pass the arguments through" would hand
// anyone with a shell on the dev box `op item delete`, and `op read --out-file`
// would write files on the laptop rather than the remote box. So: commands are
// default-deny against an allowlist, and a small set of flags is rejected
// outright because they redirect the command at local state.
package policy

import (
	"fmt"
	"strings"
)

// readOnlyCommands is the default allowlist. Every entry is a command path as
// it appears on the command line. These read; none of them mutate a vault.
var readOnlyCommands = []string{
	"read",
	"item get",
	"item list",
	"document get",
	"vault get",
	"vault list",
	"account get",
	"account list",
	"whoami",
	"user get",
}

// localStateFlags are refused on every command. Each of them would make the
// command act on the machine running the proxy instead of the machine that
// asked, or would swap out the credentials being used.
var localStateFlags = map[string]string{
	"out-file": "writes a file on the proxy machine, not the host that asked",
	"o":        "writes a file on the proxy machine, not the host that asked",
	"session":  "overrides the proxy's own 1Password session",
	"config":   "points op at a different local configuration",
}

// blockedCommands are refused with an explanation rather than a bare denial,
// because they have a working alternative the user should know about.
var blockedCommands = map[string]string{
	"run":    "`op run` would execute your command on the proxy machine; the shim runs it locally instead — make sure the remote `op` is the devtun shim",
	"inject": "`op inject` reads a template on the machine that asked; the shim resolves the references and writes the output there — make sure the remote `op` is the devtun shim",
	"signin": "sign in on the machine running devtun",
	"update": "update op on the machine running devtun",
}

// Guard checks command shape against the allowlist and flag rules.
type Guard struct {
	allowed  map[string]bool
	allowAll bool
}

// NewGuard builds a guard from configuration. Commands listed in
// Config.AllowCommands are added to the read-only defaults.
func NewGuard(config Config) *Guard {
	allowed := make(map[string]bool, len(readOnlyCommands)+len(config.AllowCommands))
	for _, command := range readOnlyCommands {
		allowed[command] = true
	}
	for _, command := range config.AllowCommands {
		allowed[normalizeCommand(command)] = true
	}
	return &Guard{allowed: allowed, allowAll: config.AllowAllCommands}
}

// Check reports why argv may not be proxied, or nil if it may. The error text
// is shown to the user on the remote box, so it explains the fix.
func (g *Guard) Check(argv []string) error {
	for _, arg := range argv {
		name, ok := flagName(arg)
		if !ok {
			continue
		}
		if reason, blocked := localStateFlags[name]; blocked {
			return fmt.Errorf("flag %q is not allowed through the proxy: it %s", "--"+name, reason)
		}
	}

	command, err := commandPath(argv)
	if err != nil {
		return err
	}
	if command == "" {
		// Only a genuinely command-less invocation gets here — `op --version`
		// and `op --help`. Anything else that parsed to no command is refused
		// by commandPath rather than falling through to this.
		return nil
	}
	if reason, blocked := blockedCommands[strings.Fields(command)[0]]; blocked {
		return fmt.Errorf("`op %s` is not proxied: %s", strings.Fields(command)[0], reason)
	}
	if g.allowAll {
		return nil
	}
	for _, candidate := range commandCandidates(command) {
		if g.allowed[candidate] {
			return nil
		}
	}
	return fmt.Errorf("`op %s` is not on the proxy's allowlist; add it to allow_commands in your devtun config if you meant to permit it", command)
}

// opGlobalFlags are the options `op` accepts *before* a subcommand. The value
// says whether the flag consumes the following argument.
//
// This table is the difference between a guard and a decoration. It was once
// absent, and the consequence was severe enough to be worth recording: with the
// old code, `commandPath` stopped at the first thing beginning with a dash, so
// `op --account work item delete X` produced an empty command path, which the
// caller treated as "no command to authorise" and allowed. Every read-only
// restriction could be stepped around by prefixing any global flag — and since
// the shim's own dispatch had the same blind spot, `op --account work run --
// sh -c …` was forwarded rather than handled locally and ran on the
// workstation. A vault-holding machine executing a string chosen by a
// semi-trusted box is the worst outcome this project has.
var opGlobalFlags = map[string]bool{
	"--account":        true,
	"--config":         true,
	"--session":        true,
	"--format":         true,
	"--encoding":       true,
	"--cache":          false,
	"--no-cache":       false,
	"--debug":          false,
	"--no-color":       false,
	"--iso-timestamps": false,
	"--version":        false,
	"--help":           false,
	"-h":               false,
	"-v":               false,
}

// commandPath returns the leading positional arguments — up to three, which
// covers every `op` command path — joined by spaces.
//
// An unrecognised option before the subcommand is an error rather than
// something to skip past. We cannot know whether it consumes the next argument,
// and guessing wrong either hides the real command or invents one; both fail
// open. Refusing means a new `op` global flag needs a line added here, which is
// a maintenance cost paid deliberately in exchange for the guard meaning
// something.
func commandPath(argv []string) (string, error) {
	var words []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]

		if !strings.HasPrefix(arg, "-") {
			words = append(words, arg)
			if len(words) == 3 {
				break
			}
			continue
		}
		// Flags after the subcommand belong to it, and are vetted separately.
		if len(words) > 0 {
			break
		}
		// `--` ends option parsing; whatever follows is not a command path.
		if arg == "--" {
			break
		}

		name, inline, hasInline := strings.Cut(arg, "=")
		takesValue, known := opGlobalFlags[name]
		if !known {
			return "", fmt.Errorf("`op %s` is not a global option devtun recognises, so it cannot tell which command this is; refusing", name)
		}
		if takesValue && !hasInline {
			i++ // the flag's value is not a command
		}
		_ = inline
	}
	return strings.Join(words, " "), nil
}

// commandCandidates yields the successively shorter prefixes of a command path,
// longest first, so that "item get Docker" matches the "item get" entry without
// the allowlist needing to know about arguments.
func commandCandidates(command string) []string {
	words := strings.Fields(command)
	candidates := make([]string, 0, len(words))
	for i := len(words); i > 0; i-- {
		candidates = append(candidates, strings.Join(words[:i], " "))
	}
	return candidates
}

// flagName extracts the flag name from an argument, without dashes and without
// any =value suffix.
func flagName(arg string) (string, bool) {
	if !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" {
		return "", false
	}
	name := strings.TrimLeft(arg, "-")
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		name = name[:eq]
	}
	return name, true
}

func normalizeCommand(command string) string {
	return strings.Join(strings.Fields(command), " ")
}
