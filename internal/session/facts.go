package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jclement/devtun/internal/service"
)

// Probing the remote box.
//
// autotun and opproxy each ran their own probes, which between them meant four
// round trips before anything useful happened. devtun probes once and every
// service reads the result.
//
// The subtle half is *which shell* answers. `ssh host command` runs a
// non-interactive, non-login shell: no .zshrc, no .bash_profile, a bare PATH.
// A box configured perfectly for the person who logs into it therefore looks
// unconfigured to a naive probe — which is how opproxy came to print a block of
// setup instructions, on every single connection, to someone who had already
// followed them. Instructions that appear when nothing is wrong stop being
// read, which is exactly when it matters that they are.
//
// So the tool discovery runs under the user's own login *and* interactive
// shell, merged, first answer winning. That is bounded by its own timeout
// because it runs a shell that can do anything.

const factsTimeout = 15 * time.Second

// tools every service between them wants to know about. One list, so the probe
// stays a single round trip no matter how many services are enabled.
var probedTools = []string{"op", "ss", "lsof", "netstat", "nc", "socat", "python3", "docker", "git"}

// probedEnv is the short list of environment variables worth asking the user's
// own shell about. It is an allowlist on purpose: a remote environment commonly
// holds tokens, and reading all of it to answer "is SSH_AUTH_SOCK already set"
// would pull secrets into this process for no reason at all.
var probedEnv = []string{"SSH_AUTH_SOCK", "BROWSER"}

const (
	markBasics = "@@DEVTUN-BASICS"
	markShell  = "@@DEVTUN-SHELL"
	markEnd    = "@@DEVTUN-END"
)

// factsScript builds the one script that answers everything.
//
// It is deliberately POSIX — dash, busybox ash and ksh all have to run it, and
// the Alpine container with 40MB of userland is a real dev box. No arrays, no
// [[ ]], no local.
func factsScript() string {
	// The inner probe is run by the user's own shell. It must survive being
	// embedded in a single-quoted argument, so it contains no single quotes.
	var inner strings.Builder
	inner.WriteString(`printf "PATH\t%s\n" "$PATH"; `)
	for _, name := range probedEnv {
		fmt.Fprintf(&inner, `printf "env.%s\t%%s\n" "${%s-}"; `, name, name)
	}
	for _, tool := range probedTools {
		fmt.Fprintf(&inner, `printf "%s\t%%s\n" "$(command -v %s 2>/dev/null || true)"; `, tool, tool)
	}

	return fmt.Sprintf(`LC_ALL=C
echo %s
printf '%%s\n' "${HOME:-}" "${XDG_RUNTIME_DIR:-}" "${SHELL:-}" \
  "$(id -un 2>/dev/null)" "$(uname -n 2>/dev/null)" \
  "$(uname -s 2>/dev/null)" "$(uname -m 2>/dev/null)"
echo %s
${SHELL:-/bin/sh} -lc '%s' 2>/dev/null
${SHELL:-/bin/sh} -ic '%s' 2>/dev/null
echo %s
`, markBasics, markShell, inner.String(), inner.String(), markEnd)
}

// factsRunner is the slice of the SSH client this needs.
type factsRunner interface {
	Output(ctx context.Context, script string) (string, error)
}

// probeFacts runs the probe and parses it.
func probeFacts(ctx context.Context, r factsRunner) (service.Facts, error) {
	ctx, cancel := context.WithTimeout(ctx, factsTimeout)
	defer cancel()

	out, err := r.Output(ctx, factsScript())
	if err != nil {
		return service.Facts{}, fmt.Errorf("probing the remote host: %w", err)
	}
	facts := parseFacts(out)
	if facts.Home == "" {
		return facts, fmt.Errorf("the remote host reported no home directory; is it a POSIX system?")
	}
	return facts, nil
}

// parseFacts reads the marker-delimited probe output.
//
// Markers matter because an interactive shell prints whatever it likes — a
// message of the day, a prompt escape, a version-manager banner — and none of
// that is ours. Anything outside the markers is ignored rather than guessed at.
func parseFacts(out string) service.Facts {
	facts := service.Facts{
		Tools: make(map[string]string),
		Env:   make(map[string]string),
	}

	section := ""
	var basics []string
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case markBasics:
			section = markBasics
			continue
		case markShell:
			section = markShell
			continue
		case markEnd:
			section = ""
			continue
		}
		switch section {
		case markBasics:
			basics = append(basics, strings.TrimRight(line, "\r"))
		case markShell:
			key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
			if !ok || value == "" {
				continue
			}
			// First answer wins: the login shell is asked before the
			// interactive one, and either counts.
			if key == "PATH" {
				// PATH is unioned across both shells, not first-answer-wins
				// like everything else here, and the difference is not
				// academic. A login shell answers with a perfectly non-empty
				// PATH that simply lacks devtun's directory, so under
				// first-wins it beat the interactive shell's answer — and
				// somebody who had put the line in .zshrc, exactly where the
				// instructions said, was told forever that they had not.
				facts.LoginPath = unionPath(facts.LoginPath, value)
				continue
			}
			if name, ok := strings.CutPrefix(key, "env."); ok {
				if facts.Env[name] == "" {
					facts.Env[name] = value
				}
				continue
			}
			if facts.Tools[key] == "" {
				facts.Tools[key] = value
			}
		}
	}

	// Pad so a short answer cannot index out of range.
	for len(basics) < 7 {
		basics = append(basics, "")
	}
	facts.Home = basics[0]
	facts.RuntimeDir = basics[1]
	facts.Shell = basics[2]
	facts.User = basics[3]
	facts.Hostname = basics[4]
	facts.OS = normalizeOS(basics[5])
	facts.Arch = normalizeArch(basics[6])
	return facts
}

// unionPath merges two PATH values, keeping order and dropping duplicates.
//
// The union is the honest answer to "can the user's shell find this": a
// directory on either shell's PATH will be found by something, and which of the
// two devtun happened to ask first is not a fact about the box.
func unionPath(existing, incoming string) string {
	if existing == "" {
		return incoming
	}
	if incoming == "" {
		return existing
	}
	seen := map[string]bool{}
	var out []string
	for _, entry := range append(strings.Split(existing, ":"), strings.Split(incoming, ":")...) {
		if entry == "" || seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	return strings.Join(out, ":")
}

// normalizeOS maps uname -s onto GOOS spelling, so a caller can compare it
// against runtime.GOOS and pick the right cross-built shim.
func normalizeOS(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	case "freebsd":
		return "freebsd"
	case "openbsd":
		return "openbsd"
	case "netbsd":
		return "netbsd"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// normalizeArch maps uname -m onto GOARCH spelling. Getting this wrong uploads
// a perfectly good binary that then fails with "cannot execute binary file".
func normalizeArch(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv6l", "arm":
		return "arm"
	case "i386", "i686", "386":
		return "386"
	case "riscv64":
		return "riscv64"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}
