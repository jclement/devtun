// Package buildinfo carries the version stamped in at link time.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set by -ldflags at release time; the defaults are what a `go build` gets.
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

// Version returns the release version, or "dev" for a local build.
func Version() string { return version }

// Commit returns the git commit, falling back to what the Go toolchain
// embedded when ldflags were not supplied.
func Commit() string {
	if commit != "" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return s.Value[:7]
			}
		}
	}
	return "unknown"
}

// BuildDate returns the build timestamp, empty for a local build.
func BuildDate() string { return buildDate }

// Short is the one-line form for --version.
func Short() string {
	return fmt.Sprintf("devtun %s (%s, %s)", version, Commit(), orUnknown(buildDate))
}

// Long adds the toolchain and platform, for `devtun version`.
func Long() string {
	return fmt.Sprintf("%s\n%s %s/%s", Short(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// UserAgent identifies this build to an SSH server.
func UserAgent() string { return "SSH-2.0-devtun_" + version }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
