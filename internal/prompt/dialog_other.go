//go:build !darwin && !windows && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

// Platforms with no known dialog program. The chooser list is empty, so
// `--prompt auto` resolves to the terminal and `--prompt dialog` says plainly
// that there is nothing here to draw with.
package prompt

func choosers() []chooser { return nil }
