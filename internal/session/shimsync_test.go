package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// scriptedClient answers Output from a function and records uploads.
type scriptedClient struct {
	mu        sync.Mutex
	reply     func(script string) (string, error)
	scripts   []string
	uploaded  []string
	uploadErr error
}

func (c *scriptedClient) Output(_ context.Context, script string) (string, error) {
	c.mu.Lock()
	c.scripts = append(c.scripts, script)
	c.mu.Unlock()
	if c.reply == nil {
		return "", nil
	}
	return c.reply(script)
}
func (c *scriptedClient) Run(context.Context, string, io.Writer) error { return nil }
func (c *scriptedClient) Upload(_ context.Context, local, remote string, _ os.FileMode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uploadErr != nil {
		return c.uploadErr
	}
	c.uploaded = append(c.uploaded, local+" -> "+remote)
	return nil
}
func (c *scriptedClient) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("not dialled in these tests")
}

func (c *scriptedClient) sawScript(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.scripts {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func facts() service.Facts {
	return service.Facts{Home: "/home/jsc", RuntimeDir: "/run/user/1000", OS: "linux", Arch: "amd64"}
}

func paths() shim.RemotePaths { return shim.PathsFor("/home/jsc", "/run/user/1000") }

// Re-uploading a megabyte on every reconnect over a hotel wifi is the kind of
// thing nobody notices until they are on a hotel wifi.
func TestCurrentShimIsNotReuploaded(t *testing.T) {
	client := &scriptedClient{reply: func(script string) (string, error) {
		if strings.Contains(script, shim.VersionFlag) {
			return "devtun-shim v1.2.3\n", nil
		}
		return "", nil
	}}
	syncer := &shimSyncer{Binary: "/tmp/whatever", Events: event.Discard}

	uploaded, err := syncer.sync(context.Background(), client, facts(), paths(), "v1.2.3")

	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if uploaded {
		t.Error("a shim already at the right version must not be re-uploaded")
	}
	if len(client.uploaded) != 0 {
		t.Errorf("nothing should have been uploaded, got %v", client.uploaded)
	}
}

func TestStaleShimIsReplaced(t *testing.T) {
	version := "v1.2.3"
	installed := "v1.0.0"
	client := &scriptedClient{}
	client.reply = func(script string) (string, error) {
		if strings.Contains(script, shim.VersionFlag) {
			// Report the old version until something has been uploaded.
			client.mu.Lock()
			done := len(client.uploaded) > 0
			client.mu.Unlock()
			if done {
				return "devtun-shim " + version + "\n", nil
			}
			return "devtun-shim " + installed + "\n", nil
		}
		return "", nil
	}
	syncer := &shimSyncer{Binary: "/tmp/devtun", Events: event.Discard}

	uploaded, err := syncer.sync(context.Background(), client, facts(), paths(), version)

	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !uploaded {
		t.Error("a stale shim should be replaced")
	}
	if len(client.uploaded) != 1 {
		t.Errorf("want exactly one upload, got %v", client.uploaded)
	}
}

// A binary built for the wrong architecture uploads perfectly and then fails
// with "cannot execute binary file" at the worst possible moment.
func TestUploadThatWillNotRunIsAnError(t *testing.T) {
	client := &scriptedClient{reply: func(string) (string, error) { return "", nil }}
	syncer := &shimSyncer{Binary: "/tmp/devtun", Events: event.Discard}

	_, err := syncer.sync(context.Background(), client, facts(), paths(), "v1.2.3")

	if err == nil {
		t.Fatal("a shim that will not run must be reported")
	}
	if !strings.Contains(err.Error(), "linux/amd64") {
		t.Errorf("the error should name the platform we tried to build for, got %v", err)
	}
}

// A stray binary that happens to accept the flag must not be mistaken for ours.
func TestHandshakePrefixIsRequired(t *testing.T) {
	client := &scriptedClient{reply: func(script string) (string, error) {
		if strings.Contains(script, shim.VersionFlag) {
			return "1Password CLI 2.30.0\n", nil
		}
		return "", nil
	}}
	syncer := &shimSyncer{Events: event.Discard}

	if _, ok := syncer.remoteVersion(context.Background(), client, "/home/jsc/.devtun/devtun-shim"); ok {
		t.Error("output without the devtun handshake must not be accepted as a version")
	}
}

// The links are what make a single PATH entry work. A box where somebody tidied
// ~/.devtun/bin should heal on the next connection rather than failing quietly
// for the rest of the week.
func TestLinksAreEnsuredEvenWhenNothingIsUploaded(t *testing.T) {
	client := &scriptedClient{reply: func(script string) (string, error) {
		if strings.Contains(script, shim.VersionFlag) {
			return "devtun-shim v1.2.3\n", nil
		}
		return "", nil
	}}
	syncer := &shimSyncer{Events: event.Discard}

	if _, err := syncer.sync(context.Background(), client, facts(), paths(), "v1.2.3"); err != nil {
		t.Fatalf("sync: %v", err)
	}

	if !client.sawScript("ln -sf") {
		t.Error("the symlinks should be ensured on every connection")
	}
	for _, name := range append([]string{"op"}, shim.OpenerNames...) {
		if !client.sawScript("/bin/" + name) {
			t.Errorf("no link was created for %q", name)
		}
	}
}

func TestLocalBinaryPrefersTheCrossBuiltDist(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	defer func() { _ = os.Chdir(wd) }()

	if err := os.MkdirAll("dist", 0o755); err != nil {
		t.Fatal(err)
	}
	remote := notThisPlatform()
	want := filepath.Join("dist", "devtun-"+remote.OS+"-"+remote.Arch)
	if err := os.WriteFile(want, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	syncer := &shimSyncer{}
	got, err := syncer.localBinary(context.Background(), remote)
	if err != nil {
		t.Fatalf("localBinary: %v", err)
	}
	if got != want {
		t.Errorf("want the cross-built binary %q, got %q", want, got)
	}
}

func TestLocalBinaryExplainsHowToBuildOne(t *testing.T) {
	t.Chdir(t.TempDir())
	syncer := &shimSyncer{}

	_, err := syncer.localBinary(context.Background(), service.Facts{OS: "plan9", Arch: "mips"})

	if err == nil {
		t.Fatal("an unbuildable platform should be an error")
	}
	if !strings.Contains(err.Error(), "build:all") {
		t.Errorf("the error should say how to fix it, got %v", err)
	}
}

// The failure this fixes was quiet in the way that matters: tunnels kept
// working, so devtun looked fine, while 1Password and the SSH agent never
// started — and the only clue was a line telling a Homebrew user to run a mise
// task in a repository they have never cloned.
func TestAHelperIsDownloadedWhenThereIsNoOtherWayToGetOne(t *testing.T) {
	t.Chdir(t.TempDir())
	remote := notThisPlatform()

	var askedOS, askedArch string
	syncer := &shimSyncer{
		Version: "v0.1.0",
		Events:  event.Discard,
		Fetch: func(_ context.Context, goos, goarch string) (string, error) {
			askedOS, askedArch = goos, goarch
			return "/tmp/fetched-devtun", nil
		},
	}

	got, err := syncer.localBinary(context.Background(), remote)
	if err != nil {
		t.Fatalf("localBinary: %v", err)
	}
	if got != "/tmp/fetched-devtun" {
		t.Errorf("want the downloaded helper, got %q", got)
	}
	if askedOS != remote.OS || askedArch != remote.Arch {
		t.Errorf("downloaded for %s/%s, want %s/%s", askedOS, askedArch, remote.OS, remote.Arch)
	}
}

// notThisPlatform names a remote that the workstation cannot simply upload
// itself to, which is the whole of what these two tests are about.
//
// It has to be computed rather than written down: linux/arm64 is a perfectly
// ordinary machine to run the suite on, and there the running test binary is a
// valid helper — so the download branch was never reached and the assertions
// passed on a Mac while failing in a container.
func notThisPlatform() service.Facts {
	if runtime.GOOS == "linux" && runtime.GOARCH == "arm64" {
		return service.Facts{OS: "linux", Arch: "amd64"}
	}
	return service.Facts{OS: "linux", Arch: "arm64"}
}

// A development build has no release to take a helper from, and should say the
// developer thing rather than reporting a failed download.
func TestNoFetcherStillGivesTheDeveloperMessage(t *testing.T) {
	t.Chdir(t.TempDir())
	syncer := &shimSyncer{Events: event.Discard}

	_, err := syncer.localBinary(context.Background(), notThisPlatform())

	if err == nil {
		t.Fatal("want an error when there is no way to get a helper")
	}
	if !strings.Contains(err.Error(), "build:all") {
		t.Errorf("a developer should be told how to build one, got %v", err)
	}
}

// An explicit --shim-binary must win over everything, including a download.
func TestAnExplicitBinaryIsNeverOverridden(t *testing.T) {
	syncer := &shimSyncer{
		Binary:  "/explicit/devtun",
		Version: "v0.1.0",
		Events:  event.Discard,
		Fetch: func(context.Context, string, string) (string, error) {
			t.Error("an explicit binary must not trigger a download")
			return "", nil
		},
	}

	got, err := syncer.localBinary(context.Background(), service.Facts{OS: "linux", Arch: "arm64"})
	if err != nil || got != "/explicit/devtun" {
		t.Errorf("localBinary = %q, %v", got, err)
	}
}
