package shim

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPathsPreferTheRuntimeDirectory(t *testing.T) {
	p := PathsFor("/home/jsc", "/run/user/1000")
	if p.Socket != "/run/user/1000/devtun.sock" {
		t.Errorf("want the socket in $XDG_RUNTIME_DIR, got %q", p.Socket)
	}
	if p.Bin != "/home/jsc/.devtun/bin" {
		t.Errorf("unexpected bin dir %q", p.Bin)
	}
	if p.Binary != "/home/jsc/.devtun/devtun-shim" {
		t.Errorf("unexpected binary path %q", p.Binary)
	}
}

// Never /tmp: the private directory is the real defence, because the socket's
// own 0600 races with sshd creating it and a 0700 directory does not.
func TestPathsFallBackInsideHomeNotTmp(t *testing.T) {
	p := PathsFor("/home/jsc", "")
	if p.Socket != "/home/jsc/.devtun/devtun.sock" {
		t.Errorf("want the socket under home, got %q", p.Socket)
	}
}

func TestEveryOpenerNameDispatches(t *testing.T) {
	for _, name := range OpenerNames {
		svc, ok := ServiceFor(name)
		if !ok || svc != ServiceOpen {
			t.Errorf("%s should dispatch to the open service, got %q ok=%v", name, svc, ok)
		}
	}
}

func TestServiceForUsesTheBasename(t *testing.T) {
	svc, ok := ServiceFor("/home/jsc/.devtun/bin/op")
	if !ok || svc != ServiceOp {
		t.Errorf("a full path should still dispatch, got %q ok=%v", svc, ok)
	}
	if _, ok := ServiceFor("devtun"); ok {
		t.Error("devtun invoked by its own name must not be treated as a shim")
	}
}

func TestDiscoverSocketPrefersTheOverride(t *testing.T) {
	t.Setenv(SocketEnv, "/custom/devtun.sock")
	if got := DiscoverSocket(); got != "/custom/devtun.sock" {
		t.Errorf("want the override to win, got %q", got)
	}
}

func TestDiscoverSocketUsesTheRuntimeDir(t *testing.T) {
	t.Setenv(SocketEnv, "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := DiscoverSocket(); got != "/run/user/1000/devtun.sock" {
		t.Errorf("want the runtime dir, got %q", got)
	}
}

// The session chooses the socket's home from the shell it probed; the shim runs
// in a different one, which may not have the same environment. When they
// disagree the shim used to report "no devtun session" while devtun was running
// perfectly — so it looks in both places.
func TestDiscoverSocketFindsTheOneThatExists(t *testing.T) {
	home := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv(SocketEnv, "")
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	// Only the home-directory socket exists, as happens on a box with no
	// systemd user session in the shell that devtun probed.
	if err := os.MkdirAll(filepath.Join(home, RemoteDir), 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, RemoteDir, SocketName)
	listener, err := net.Listen("unix", want)
	if err != nil {
		t.Skipf("cannot create a unix socket here: %v", err)
	}
	defer listener.Close()

	if got := DiscoverSocket(); got != want {
		t.Errorf("want the socket that exists (%s), got %s", want, got)
	}
}

// A plain file where a socket should be is not a socket, and must not be
// mistaken for one.
func TestDiscoverSocketIgnoresANonSocket(t *testing.T) {
	home := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv(SocketEnv, "")
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	if err := os.MkdirAll(filepath.Join(home, RemoteDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, RemoteDir, SocketName), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := DiscoverSocket(); got != filepath.Join(runtimeDir, SocketName) {
		t.Errorf("a regular file must not be taken for a socket, got %s", got)
	}
}

// While a session is reconnecting neither socket exists, and the shim must
// still have somewhere to wait for one.
func TestDiscoverSocketFallsBackToThePreferredPath(t *testing.T) {
	t.Setenv(SocketEnv, "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	if got := DiscoverSocket(); got != "/run/user/1000/"+SocketName {
		t.Errorf("want the preferred path when nothing exists, got %s", got)
	}
}

// $XDG_RUNTIME_DIR is set by the remote box, and devtun chmods 700 whatever it
// names. Taking it on trust puts the control socket in a world-writable
// directory — and, as root, turns shared /tmp from 1777 into 0700 on the way.
func TestSharedDirectoriesAreNeverUsedForTheSocket(t *testing.T) {
	for _, dir := range []string{"/tmp", "/tmp/", "/var/tmp", "/dev/shm", "/", "/etc", "/tmp/user-1000", "relative/path", ""} {
		p := PathsFor("/home/jsc", dir)
		if p.Socket != "/home/jsc/.devtun/devtun.sock" {
			t.Errorf("XDG_RUNTIME_DIR=%q put the socket at %q; want the fallback under home", dir, p.Socket)
		}
	}
}

// A real per-user runtime directory is still preferred: it is mode 0700 and
// cleaned up on logout, which is better than anything under $HOME.
func TestARealRuntimeDirectoryIsStillUsed(t *testing.T) {
	for _, dir := range []string{"/run/user/1000", "/run/user/0", "/private/var/run/user/501"} {
		p := PathsFor("/home/jsc", dir)
		if p.Socket != dir+"/devtun.sock" {
			t.Errorf("XDG_RUNTIME_DIR=%q should be used, got %q", dir, p.Socket)
		}
	}
}
