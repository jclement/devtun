package selfupdate

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSource stands in for GitHub.
type fakeSource struct {
	release   *Release
	latestErr error
	applyErr  error

	appliedTo  string
	applyCalls int
}

func (f *fakeSource) Latest(context.Context) (*Release, error) {
	return f.release, f.latestErr
}

func (f *fakeSource) Apply(_ context.Context, _ *Release, path string) error {
	f.applyCalls++
	f.appliedTo = path
	return f.applyErr
}

// newRelease builds a release announcing the given version.
func newRelease(t *testing.T, version string) *Release {
	t.Helper()
	return &Release{
		Version: version,
		URL:     "https://github.com/jclement/devtun/releases/tag/" + version,
	}
}

func run(t *testing.T, opts Options, src *fakeSource) (string, error) {
	t.Helper()
	var out strings.Builder
	opts.Out = &out
	opts.Source = src
	if opts.Executable == "" {
		opts.Executable = filepath.Join(t.TempDir(), "autotun")
	}
	err := Run(context.Background(), opts)
	return out.String(), err
}

func TestUpdateInstallsANewerRelease(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v1.2.3")}
	out, err := run(t, Options{Current: "v1.0.0"}, src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if src.applyCalls != 1 {
		t.Errorf("Apply called %d times, want 1", src.applyCalls)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("output should name the new version:\n%s", out)
	}
}

func TestUpdateSkipsWhenAlreadyCurrent(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v1.0.0")}
	out, err := run(t, Options{Current: "v1.0.0"}, src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if src.applyCalls != 0 {
		t.Error("an up-to-date binary should not be replaced")
	}
	if !strings.Contains(out, "already the latest") {
		t.Errorf("output should say it is current:\n%s", out)
	}
}

func TestUpdateSkipsWhenReleaseIsOlder(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v0.9.0")}
	if _, err := run(t, Options{Current: "v1.0.0"}, src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if src.applyCalls != 0 {
		t.Error("a older release should not be installed over a newer build")
	}
}

func TestUpdateForceInstallsAnyway(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v1.0.0")}
	if _, err := run(t, Options{Current: "v1.0.0", Force: true}, src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if src.applyCalls != 1 {
		t.Error("--force should install regardless of version")
	}
}

func TestUpdateCheckOnlyDoesNotInstall(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v1.2.3")}
	out, err := run(t, Options{Current: "v1.0.0", CheckOnly: true}, src)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if src.applyCalls != 0 {
		t.Error("--check must not replace the binary")
	}
	if !strings.Contains(out, "available") {
		t.Errorf("--check should report availability:\n%s", out)
	}
}

func TestUpdateRefusesDevelopmentBuilds(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v1.2.3")}
	_, err := run(t, Options{Current: "dev"}, src)
	if err == nil || !strings.Contains(err.Error(), "development build") {
		t.Fatalf("Run = %v, want a development-build refusal", err)
	}
	if src.applyCalls != 0 {
		t.Error("a dev build should not be replaced without --force")
	}
}

func TestUpdateReportsNoReleaseFound(t *testing.T) {
	src := &fakeSource{}
	_, err := run(t, Options{Current: "v1.0.0"}, src)
	if err == nil || !strings.Contains(err.Error(), "no release found") {
		t.Fatalf("Run = %v, want a not-found error", err)
	}
}

func TestUpdatePropagatesDetectionErrors(t *testing.T) {
	boom := errors.New("github is having a day")
	src := &fakeSource{latestErr: boom}
	_, err := run(t, Options{Current: "v1.0.0"}, src)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want the underlying error", err)
	}
}

func TestUpdatePropagatesReplacementErrors(t *testing.T) {
	boom := errors.New("disk is full")
	src := &fakeSource{release: newRelease(t, "v1.2.3"), applyErr: boom}
	_, err := run(t, Options{Current: "v1.0.0"}, src)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want the underlying error", err)
	}
}

// Replacing a package-managed binary leaves the manager's metadata lying, and
// the next upgrade silently reverts it.
func TestUpdateRefusesPackageManagedInstalls(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		want string
	}{
		{"homebrew cellar", "/opt/homebrew/Cellar/autotun/1.0.0/bin/autotun", "brew upgrade"},
		{"homebrew caskroom", "/opt/homebrew/Caskroom/autotun/1.0.0/autotun", "brew upgrade"},
		{"linuxbrew", "/home/linuxbrew/.linuxbrew/Cellar/autotun/1.0.0/bin/autotun", "brew upgrade"},
		{"nix store", "/nix/store/abc123-autotun-1.0.0/bin/autotun", "nix profile"},
		{"snap", "/snap/autotun/current/bin/autotun", "snap refresh"},
		{"system path", "/usr/bin/autotun", "package manager"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &fakeSource{release: newRelease(t, "v1.2.3")}
			_, err := run(t, Options{Current: "v1.0.0", Executable: tt.exe}, src)
			if !errors.Is(err, ErrManagedInstall) {
				t.Fatalf("Run = %v, want ErrManagedInstall", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should suggest %q, got: %v", tt.want, err)
			}
			if src.applyCalls != 0 {
				t.Error("a managed binary must not be replaced")
			}
		})
	}
}

// --check is safe to run on a managed install; it changes nothing.
func TestUpdateCheckWorksOnManagedInstalls(t *testing.T) {
	src := &fakeSource{release: newRelease(t, "v1.2.3")}
	_, err := run(t, Options{
		Current:    "v1.0.0",
		CheckOnly:  true,
		Executable: "/opt/homebrew/Cellar/autotun/1.0.0/bin/autotun",
	}, src)
	if err != nil {
		t.Errorf("--check on a managed install = %v, want nil", err)
	}
}

func TestUpdateAllowsOrdinaryPaths(t *testing.T) {
	for _, exe := range []string{
		"/Users/jeff/go/bin/autotun",
		"/home/jeff/.local/bin/autotun",
		"/usr/local/bin/autotun",
		"C:\\Users\\jeff\\bin\\autotun.exe",
	} {
		if m, managed := packageManager(exe); managed {
			t.Errorf("packageManager(%q) = %+v, want unmanaged", exe, m)
		}
	}
}

func TestIsReleaseBuild(t *testing.T) {
	tests := map[string]bool{
		"v1.0.0":                          true,
		"1.0.0":                           true,
		"v0.1.0":                          true,
		"v1.2.3-rc1":                      true,
		"dev":                             false,
		"":                                false,
		"  ":                              false,
		"v0.0.0-dev":                      false,
		"v0.0.0-20260817120000-abcdef123": false,
	}
	for in, want := range tests {
		if got := isReleaseBuild(in); got != want {
			t.Errorf("isReleaseBuild(%q) = %v, want %v", in, got, want)
		}
	}
}
