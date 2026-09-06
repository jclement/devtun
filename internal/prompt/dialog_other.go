//go:build !darwin

// Platforms without a native approval dialog. The type still exists so the
// backend selection logic in prompt.go compiles everywhere; it simply reports
// itself as unavailable, and `--prompt auto` resolves to the terminal.
package prompt

import (
	"context"
	"errors"
)

// Dialog is a placeholder on platforms with no native dialog support.
type Dialog struct {
	fallback Prompter
}

// dialogAvailable is always false here.
func dialogAvailable() bool { return false }

// Ask defers to the fallback prompter, or fails if there is none.
func (d *Dialog) Ask(ctx context.Context, request Request) (Choice, error) {
	if d.fallback != nil {
		return d.fallback.Ask(ctx, request)
	}
	return ChoiceDeny, errors.New("no native approval dialog on this platform; ask in the terminal instead")
}
