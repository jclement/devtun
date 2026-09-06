package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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
	want := filepath.Join("dist", "devtun-linux-arm64")
	if err := os.WriteFile(want, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	syncer := &shimSyncer{}
	got, err := syncer.localBinary(service.Facts{OS: "linux", Arch: "arm64"})
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

	_, err := syncer.localBinary(service.Facts{OS: "plan9", Arch: "mips"})

	if err == nil {
		t.Fatal("an unbuildable platform should be an error")
	}
	if !strings.Contains(err.Error(), "build:all") {
		t.Errorf("the error should say how to fix it, got %v", err)
	}
}
