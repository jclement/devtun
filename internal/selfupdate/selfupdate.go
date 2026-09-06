// Package selfupdate implements `devtun update`: replacing the running
// binary with the latest GitHub release.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	gsu "github.com/creativeprojects/go-selfupdate"
	"golang.org/x/mod/semver"
)

// Slug is the GitHub repository releases are published to.
const Slug = "jclement/devtun"

// checksumFile is the name GoReleaser gives the aggregated checksum asset.
// Every downloaded archive is verified against it before anything is replaced.
const checksumFile = "checksums.txt"

// Release is the subset of a published release the command cares about.
// Keeping our own type means the decision logic is testable without
// constructing the upstream library's partly-unexported state.
type Release struct {
	Version string // e.g. "v1.2.3"
	URL     string
	Notes   string

	// handle carries the upstream release through to Apply.
	handle *gsu.Release
}

// Source publishes releases and can install one over a local binary.
type Source interface {
	// Latest returns the newest release for this platform, or nil if there
	// is none.
	Latest(ctx context.Context) (*Release, error)
	// Apply replaces the binary at path with the release.
	Apply(ctx context.Context, rel *Release, path string) error
}

// Options configures an update run.
type Options struct {
	// Current is the running version, e.g. "v0.1.0" or "dev".
	Current string
	// CheckOnly reports what is available without replacing anything.
	CheckOnly bool
	// Force updates even when the running build is not older than the release.
	Force bool
	// Out receives progress messages.
	Out io.Writer
	// Source overrides where releases come from; tests use this.
	Source Source
	// Executable overrides the path to replace; tests use this.
	Executable string
}

// ErrManagedInstall is returned when the binary is managed by a package
// manager that should perform the upgrade instead.
var ErrManagedInstall = errors.New("this devtun was installed by a package manager")

// ErrNoRelease is returned when the platform has no published asset.
var ErrNoRelease = errors.New("no release found")

// Run performs the update.
func Run(ctx context.Context, opts Options) error {
	if opts.Out == nil {
		opts.Out = io.Discard
	}

	exe, err := resolveExecutable(opts.Executable)
	if err != nil {
		return err
	}

	// Replacing a Homebrew-managed binary leaves brew's metadata claiming a
	// version that is no longer installed, and the next `brew upgrade`
	// silently reverts the update.
	if !opts.CheckOnly {
		if m, managed := packageManager(exe); managed {
			return fmt.Errorf("%w (%s)\n\nUpgrade it with:\n  %s", ErrManagedInstall, m.name, m.command)
		}
	}

	if !opts.CheckOnly && !opts.Force && !isReleaseBuild(opts.Current) {
		return fmt.Errorf("this is a development build (%s), not a release; "+
			"pass --force to replace it anyway", opts.Current)
	}

	source := opts.Source
	if source == nil {
		source, err = NewGitHubSource(Slug)
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(opts.Out, "checking %s for a newer release…\n", Slug)
	latest, err := source.Latest(ctx)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}
	if latest == nil {
		return fmt.Errorf("%w for %s/%s", ErrNoRelease, runtime.GOOS, runtime.GOARCH)
	}

	if !opts.Force && !isNewer(latest.Version, opts.Current) {
		fmt.Fprintf(opts.Out, "devtun %s is already the latest version\n", opts.Current)
		return nil
	}

	if opts.CheckOnly {
		fmt.Fprintf(opts.Out, "devtun %s is available (you have %s)\n  %s\n",
			latest.Version, opts.Current, latest.URL)
		return nil
	}

	fmt.Fprintf(opts.Out, "updating %s → %s…\n", opts.Current, latest.Version)
	if err := source.Apply(ctx, latest, exe); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("replacing %s: %w\n\nTry again with sudo, or download it yourself from\n  %s",
				exe, err, latest.URL)
		}
		return fmt.Errorf("replacing %s: %w", exe, err)
	}

	fmt.Fprintf(opts.Out, "updated to devtun %s\n", latest.Version)
	if notes := strings.TrimSpace(latest.Notes); notes != "" {
		fmt.Fprintf(opts.Out, "\n%s\n", notes)
	}
	return nil
}

// resolveExecutable finds the binary to replace, following symlinks so a
// package manager's bin/ link does not hide where the file really lives.
func resolveExecutable(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved, nil
	}
	return exe, nil
}

// githubSource fetches releases from GitHub via go-selfupdate.
type githubSource struct {
	updater *gsu.Updater
	repo    gsu.Repository
}

// NewGitHubSource returns a Source reading the given owner/repo, verifying
// every download against the release's published checksums.
func NewGitHubSource(slug string) (Source, error) {
	up, err := gsu.NewUpdater(gsu.Config{
		Validator: &gsu.ChecksumValidator{UniqueFilename: checksumFile},
	})
	if err != nil {
		return nil, fmt.Errorf("preparing the updater: %w", err)
	}
	return &githubSource{updater: up, repo: gsu.ParseSlug(slug)}, nil
}

func (s *githubSource) Latest(ctx context.Context) (*Release, error) {
	rel, found, err := s.updater.DetectLatest(ctx, s.repo)
	if err != nil {
		return nil, err
	}
	if !found || rel == nil {
		return nil, nil
	}
	return &Release{
		Version: normalize(rel.Version()),
		URL:     rel.URL,
		Notes:   rel.ReleaseNotes,
		handle:  rel,
	}, nil
}

func (s *githubSource) Apply(ctx context.Context, rel *Release, path string) error {
	if rel.handle == nil {
		return errors.New("release has no downloadable asset")
	}
	return s.updater.UpdateTo(ctx, rel.handle, path)
}

// normalize puts a version into the "vX.Y.Z" form semver comparison wants.
func normalize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// isNewer reports whether latest supersedes current. A current version that is
// not a real release (a dev build) is always superseded, so `update --force`
// is not needed just to get onto a release.
func isNewer(latest, current string) bool {
	if !isReleaseBuild(current) {
		return true
	}
	l, c := normalize(latest), normalize(current)
	if !semver.IsValid(l) || !semver.IsValid(c) {
		// Without comparable versions, only a difference is actionable.
		return l != c
	}
	return semver.Compare(l, c) > 0
}

// isReleaseBuild reports whether the version looks like a stamped release
// rather than a local or `go install`-from-source build.
func isReleaseBuild(v string) bool {
	v = normalize(v)
	switch {
	case v == "" || v == "vdev":
		return false
	case !semver.IsValid(v):
		return false
	case strings.HasPrefix(v, "v0.0.0"):
		// The pseudo-version `go install` writes for an untagged commit.
		return false
	}
	return true
}

// manager describes a package manager that owns the binary.
type manager struct {
	name    string
	command string
}

// packageManager reports whether the executable lives somewhere a package
// manager controls.
func packageManager(exe string) (manager, bool) {
	dir := filepath.ToSlash(filepath.Dir(exe))

	// Homebrew keeps real binaries under Cellar or Caskroom and symlinks them
	// into bin; the caller resolves symlinks before we get here.
	for _, marker := range []string{"/Cellar/", "/Caskroom/", "/homebrew/", "/linuxbrew/"} {
		if strings.Contains(dir, marker) {
			return manager{"Homebrew", "brew upgrade devtun"}, true
		}
	}
	switch {
	case strings.HasPrefix(dir, "/nix/store"):
		return manager{"Nix", "nix profile upgrade devtun"}, true
	case strings.HasPrefix(dir, "/snap/"):
		return manager{"Snap", "snap refresh devtun"}, true
	case dir == "/usr/bin" || strings.HasPrefix(dir, "/usr/lib"):
		return manager{"your system package manager", "your package manager's upgrade command"}, true
	}
	return manager{}, false
}
