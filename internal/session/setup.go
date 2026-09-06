package session

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/jclement/devtun/internal/service"
)

// Remote shell setup.
//
// devtun needs exactly one thing in the user's shell on the remote box: its
// bin directory on PATH, so the shim shadows `op` and the browser openers.
// Everything else — the socket path, the nonce — the shim works out for itself,
// deliberately, because a per-session environment variable cannot reach a shell
// that was started before this session.
//
// Two rules shape what follows. Printing instructions to someone who has
// already followed them is how instructions stop being read, so nothing is
// printed when nothing is missing. And a shell rc is the user's file, not ours
// — we already write to ~/.devtun without asking, but that is our directory —
// so appending to it is offered, never assumed.

// setupMarkerStart and setupMarkerEnd delimit the block devtun manages. They
// are what makes the edit idempotent and reversible: devtun rewrites between
// the markers rather than appending, so connecting fifty times leaves one
// block, and removing it is a visible, obvious edit.
const (
	setupMarkerStart = "# >>> devtun >>>"
	setupMarkerEnd   = "# <<< devtun <<<"
)

// SetupMode is how aggressive devtun is about the remote rc file.
type SetupMode string

const (
	// SetupAsk offers to make the edit and remembers the answer per host.
	SetupAsk SetupMode = "ask"
	// SetupAuto makes the edit without asking.
	SetupAuto SetupMode = "auto"
	// SetupNever only ever prints what is missing.
	SetupNever SetupMode = "never"
)

// ParseSetupMode validates the --setup flag.
func ParseSetupMode(s string) (SetupMode, error) {
	switch SetupMode(s) {
	case SetupAsk, SetupAuto, SetupNever:
		return SetupMode(s), nil
	case "":
		return SetupAsk, nil
	}
	return "", fmt.Errorf("unknown setup mode %q: use ask, auto or never", s)
}

// RCPlan describes the edit devtun would make to a remote shell rc.
type RCPlan struct {
	// File is the absolute remote path, empty when the shell is unrecognised.
	File string
	// Shell is the family we detected: zsh, bash, fish.
	Shell string
	// Block is the complete text devtun would place between its markers,
	// markers included.
	Block string
	// Lines are the bare export lines, for printing when we will not write.
	Lines []string
	// Writable reports whether devtun is willing to make the edit itself. A
	// dotfile managed by chezmoi, stow or a bare git repo is normally a
	// symlink, and appending to it either fails or is silently reverted on the
	// next apply — so we print instead and say why.
	Writable bool
	// Why explains a false Writable.
	Why string
}

// planRC works out what would have to change, and where.
func planRC(facts service.Facts, binDir string) RCPlan {
	shell := path.Base(facts.Shell)
	plan := RCPlan{Shell: shell}

	switch shell {
	case "zsh":
		plan.File = path.Join(facts.Home, ".zshrc")
		plan.Lines = []string{fmt.Sprintf(`export PATH="%s:$PATH"`, binDir)}
	case "bash", "sh":
		// .bashrc, not .bash_profile: `ssh host` and anything herdr starts is
		// an interactive non-login shell, which reads only the former.
		plan.File = path.Join(facts.Home, ".bashrc")
		plan.Lines = []string{fmt.Sprintf(`export PATH="%s:$PATH"`, binDir)}
	case "fish":
		// fish is not POSIX and `export` is a syntax error in it — a detail
		// worth getting right, because the failure is a shell that prints an
		// error on every single prompt.
		plan.File = path.Join(facts.Home, ".config/fish/config.fish")
		plan.Lines = []string{fmt.Sprintf("fish_add_path %s", binDir)}
	default:
		// An unrecognised shell gets advice, not an edit. Guessing the file is
		// how you end up appending bash syntax to a csh rc.
		plan.Lines = []string{fmt.Sprintf(`export PATH="%s:$PATH"`, binDir)}
		plan.Why = fmt.Sprintf("unrecognised login shell %q", facts.Shell)
		return plan
	}

	plan.Block = strings.Join(append(
		[]string{setupMarkerStart},
		append(plan.Lines, setupMarkerEnd)...,
	), "\n")
	plan.Writable = true
	return plan
}

// checkWritable decides whether devtun should touch the file, and is
// deliberately conservative. It runs on the remote because that is where the
// file is.
func checkWritable(ctx context.Context, h remoteRunner, plan RCPlan) RCPlan {
	if !plan.Writable {
		return plan
	}
	// -h is the symlink test: a dotfile managed by chezmoi, stow, yadm or a
	// bare git repo is almost always one, and an append to it is either
	// refused or quietly reverted the next time the manager runs. Better to
	// print and let the user put it in the source of truth.
	script := fmt.Sprintf(`f=%s
if [ -h "$f" ]; then echo symlink
elif [ -e "$f" ] && [ ! -w "$f" ]; then echo readonly
elif [ ! -e "$f" ] && [ ! -w "$(dirname "$f")" ]; then echo nodir
else echo ok
fi`, shellQuote(plan.File))

	out, err := h.Output(ctx, script)
	if err != nil {
		plan.Writable = false
		plan.Why = "could not inspect " + plan.File
		return plan
	}
	switch strings.TrimSpace(out) {
	case "ok":
		return plan
	case "symlink":
		plan.Writable = false
		plan.Why = plan.File + " is a symlink — it looks managed by a dotfiles tool, so devtun will not edit it"
	case "readonly":
		plan.Writable = false
		plan.Why = plan.File + " is not writable"
	case "nodir":
		plan.Writable = false
		plan.Why = path.Dir(plan.File) + " does not exist and cannot be created"
	default:
		plan.Writable = false
		plan.Why = "could not inspect " + plan.File
	}
	return plan
}

// applyRC writes the managed block into the remote rc file, replacing any
// block already there. It is idempotent: the markers are the key, so a second
// run rewrites rather than appends.
//
// The edit is made to a temporary copy and renamed over the original, so an
// interrupted write cannot leave the user with a truncated shell rc — which
// would greet them with a broken login on a box they may not have another way
// into.
func applyRC(ctx context.Context, h remoteRunner, plan RCPlan) error {
	if !plan.Writable {
		return fmt.Errorf("refusing to edit %s: %s", plan.File, plan.Why)
	}
	script := fmt.Sprintf(`set -e
f=%s
tmp="$f.devtun.$$"
mkdir -p "$(dirname "$f")"
[ -e "$f" ] || : > "$f"
# Drop any block we wrote before, then append the current one.
awk 'BEGIN{skip=0}
     $0==%s{skip=1; next}
     $0==%s{skip=0; next}
     skip==0{print}' "$f" > "$tmp"
# Trim trailing blank lines so repeated runs do not grow the file.
while [ -s "$tmp" ] && [ -z "$(tail -n 1 "$tmp")" ]; do
  sed -i.bak '$d' "$tmp" 2>/dev/null || sed -i '$d' "$tmp"
  rm -f "$tmp.bak"
done
[ -s "$tmp" ] && printf '\n' >> "$tmp"
cat >> "$tmp" <<'DEVTUN_BLOCK'
%s
DEVTUN_BLOCK
cp "$f" "$f.devtun-backup" 2>/dev/null || true
# Carry the original's permissions onto the replacement. Writing through a
# shell redirection gives the file whatever the umask says — commonly 0644 —
# so a 0600 rc holding a token would be widened to every user on the box by
# an edit that was only supposed to add a PATH line.
# GNU chmod first, then BSD/GNU stat, then a safe floor. The remote could be
# any of them and none of these is portable on its own.
chmod --reference="$f" "$tmp" 2>/dev/null \
  || chmod "$(stat -c %%a "$f" 2>/dev/null || stat -f %%Lp "$f" 2>/dev/null)" "$tmp" 2>/dev/null \
  || chmod 600 "$tmp"
mv "$tmp" "$f"
`, shellQuote(plan.File), awkLiteral(setupMarkerStart), awkLiteral(setupMarkerEnd), plan.Block)

	if _, err := h.Output(ctx, script); err != nil {
		return fmt.Errorf("editing %s: %w", plan.File, err)
	}
	return nil
}

// remoteRunner is the slice of the SSH client the setup code needs, so it can
// be tested without a network.
type remoteRunner interface {
	Output(ctx context.Context, script string) (string, error)
}

// awkLiteral quotes a string for comparison inside a single-quoted awk program.
func awkLiteral(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// shellQuote makes s safe as one POSIX shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
