package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/release"
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
	// empty, one is found or downloaded.
	Binary string
	// Version is this build, which is also the release a helper is taken from.
	Version string
	// Fetch downloads a helper for another platform. Nil disables downloading,
	// which is what a development build with no release wants.
	Fetch  func(ctx context.Context, goos, goarch string) (string, error)
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

	local, err := s.localBinary(ctx, facts)
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
//
// The order matters and each step is for a different person. An explicit
// --shim-binary is somebody who knows exactly what they want. dist/ is a
// development checkout that has cross-built. Using this executable itself
// covers the case where the remote happens to be the same platform. And the
// download is for everybody else — which, for a tool installed from Homebrew
// and pointed at a Linux box, is the ordinary case rather than the exotic one.
//
// That last step was missing at first, and the failure was quiet in the way
// that matters: tunnels kept working, so devtun looked fine, while 1Password
// and the SSH agent simply never started and the only clue was one line telling
// a Homebrew user to run a mise task in a repository they have never cloned.
func (s *shimSyncer) localBinary(ctx context.Context, facts service.Facts) (string, error) {
	if s.Binary != "" {
		return s.Binary, nil
	}
	// dist/ is where `mise run build:all` puts the cross-built helpers, so a
	// development checkout can install onto anything without cutting a release.
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

	if s.Fetch == nil {
		return "", fmt.Errorf("no devtun binary for %s/%s: build one with `mise run build:all`, or pass --shim-binary",
			facts.OS, facts.Arch)
	}
	s.Events.Emit(event.Event{
		Kind: "shim-fetching", Class: event.Lifecycle, Level: event.Info,
		Text: fmt.Sprintf("downloading the %s/%s helper from release %s", facts.OS, facts.Arch, s.Version),
	})
	binary, err := s.Fetch(ctx, facts.OS, facts.Arch)
	if err != nil {
		if errors.Is(err, release.ErrNoRelease) {
			return "", fmt.Errorf("no devtun binary for %s/%s: build one with `mise run build:all`, or pass --shim-binary",
				facts.OS, facts.Arch)
		}
		return "", fmt.Errorf("no devtun binary for %s/%s and it could not be downloaded: %w",
			facts.OS, facts.Arch, err)
	}
	return binary, nil
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
