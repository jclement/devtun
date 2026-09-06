package session

import (
	"context"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// Keeping the remote shim current.
//
// opproxy made installing the shim a separate command you had to remember, and
// forgetting it produced a confusing failure much later. devtun checks on every
// connect and uploads when the version differs, because the alternative — a
// stale shim speaking last month's protocol — is exactly the kind of problem
// that costs an hour and teaches nothing.
//
// The check is a version handshake rather than a checksum because the shim is
// pretending to be `op`, and asking a binary "are you ours?" is the only
// reliable way to tell it from the real 1Password CLI sitting in the same PATH.

// shimSyncer installs and refreshes the remote shim.
type shimSyncer struct {
	// Binary is the local path to a shim built for the remote's platform. When
	// empty, this process's own executable is used if the platforms match.
	Binary string
	Events event.Sink
}

// sync brings the remote shim up to date, reporting whether it uploaded.
func (s *shimSyncer) sync(ctx context.Context, c remoteClient, facts service.Facts, paths shim.RemotePaths, want string) (bool, error) {
	current, ok := s.remoteVersion(ctx, c, paths.Binary)
	if ok && current == want {
		if err := s.ensureLinks(ctx, c, paths); err != nil {
			return false, err
		}
		return false, nil
	}

	local, err := s.localBinary(facts)
	if err != nil {
		return false, err
	}
	if err := c.Upload(ctx, local, paths.Binary, 0o755); err != nil {
		return false, fmt.Errorf("uploading the shim to %s: %w", paths.Binary, err)
	}

	// Prove the upload can actually execute. A binary built for the wrong
	// architecture uploads perfectly and then fails with "cannot execute
	// binary file" at the worst possible moment.
	got, ok := s.remoteVersion(ctx, c, paths.Binary)
	if !ok {
		return false, fmt.Errorf("the shim uploaded to %s but will not run there; is it built for %s/%s?", paths.Binary, facts.OS, facts.Arch)
	}
	if got != want {
		return false, fmt.Errorf("uploaded shim %s reports version %q", paths.Binary, got)
	}
	if err := s.ensureLinks(ctx, c, paths); err != nil {
		return false, err
	}
	return true, nil
}

// remoteVersion asks the shim to identify itself.
func (s *shimSyncer) remoteVersion(ctx context.Context, c remoteClient, binary string) (string, bool) {
	out, err := c.Output(ctx, fmt.Sprintf("%s %s 2>/dev/null || true", shellQuote(binary), shim.VersionFlag))
	if err != nil {
		return "", false
	}
	fields := strings.Fields(strings.TrimSpace(out))
	// The handshake prefix stops a stray binary that happens to accept the
	// flag from being mistaken for ours.
	if len(fields) != 2 || fields[0] != shim.Handshake {
		return "", false
	}
	return fields[1], true
}

// localBinary finds a shim built for the remote's platform.
func (s *shimSyncer) localBinary(facts service.Facts) (string, error) {
	if s.Binary != "" {
		return s.Binary, nil
	}
	// dist/ is where `mise run build:all` puts the cross-built shims, so a
	// development checkout can install onto anything without a release.
	candidate := path.Join("dist", fmt.Sprintf("devtun-%s-%s", facts.OS, facts.Arch))
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	if facts.OS == runtime.GOOS && facts.Arch == runtime.GOARCH {
		self, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("locating this executable: %w", err)
		}
		return self, nil
	}
	return "", fmt.Errorf("no devtun binary for %s/%s: build one with `mise run build:all`, or pass --shim-binary",
		facts.OS, facts.Arch)
}

// ensureLinks creates the bin directory and the argv[0] symlinks.
//
// It runs every time rather than only after an upload: the links are what make
// the single PATH entry work, and a box where somebody tidied ~/.devtun/bin
// should heal itself on the next connection rather than failing quietly for the
// rest of the week.
func (s *shimSyncer) ensureLinks(ctx context.Context, c remoteClient, paths shim.RemotePaths) error {
	var b strings.Builder
	fmt.Fprintf(&b, "set -e\nmkdir -p %s\nchmod 700 %s\n", shellQuote(paths.Bin), shellQuote(paths.Dir))
	for _, name := range append([]string{"op"}, shim.OpenerNames...) {
		link := path.Join(paths.Bin, name)
		// -f so a stale link is replaced; -s so it stays one file on disk.
		fmt.Fprintf(&b, "ln -sf %s %s\n", shellQuote(paths.Binary), shellQuote(link))
	}
	if _, err := c.Output(ctx, b.String()); err != nil {
		return fmt.Errorf("creating the shim links in %s: %w", paths.Bin, err)
	}
	return nil
}
