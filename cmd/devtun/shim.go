package main

import (
	"context"

	"github.com/jclement/devtun/internal/buildinfo"
	"github.com/jclement/devtun/internal/shim"
)

// runShim handles the case where this binary was invoked under one of the
// names it is symlinked as on a remote dev box.
//
// The dispatch happens before cobra sees anything, and that ordering is the
// point: as `op`, every argument belongs to the 1Password command line,
// including ones that would otherwise collide with devtun's own flags. A
// `--version` meant for `op` must not be answered by devtun.
//
// It reports whether it handled the invocation, so `devtun` called by its own
// name falls through to the ordinary CLI.
func runShim(ctx context.Context, argv []string) (code int, handled bool) {
	name := shimName(argv)
	_, isShimName := shim.ServiceFor(name)

	// The version handshake is the exception, and it is easy to get wrong.
	// internal/session/shimsync.go runs the binary by its own name —
	// `~/.devtun/devtun-shim --devtun-shim` — which is deliberately NOT one of
	// the symlinked names, so ServiceFor misses. Falling through to cobra
	// there would leave the handshake unanswered, the helper would look stale
	// on every connect, and each session would re-upload it and then declare
	// that it will not run.
	if !isShimName && !isHandshake(argv) {
		return 0, false
	}
	return shim.RunAsShim(ctx, name, argv[1:], buildinfo.Version()), true
}

// isHandshake reports whether this invocation is the version probe.
func isHandshake(argv []string) bool {
	return len(argv) == 2 && argv[1] == shim.VersionFlag
}
