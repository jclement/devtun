package shim

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Where things live on the remote box.
//
// These paths are fixed rather than negotiated per session, and that is the
// whole trick. A per-session environment variable can only reach shells started
// after the session began, which is exactly the wrong property for a tool you
// attach and reattach to all day: the terminal you already had open would never
// see it. A fixed path means one line in the user's shell rc, once, forever —
// and it is also why the shim can fall through harmlessly when no session is
// running, since it can always tell by looking.
const (
	// RemoteDir is devtun's directory in the remote user's home.
	RemoteDir = ".devtun"
	// BinDir holds the argv[0] symlinks, and is the single thing that has to
	// be on PATH.
	BinDir = "bin"
	// Binary is the shim itself.
	Binary = "devtun-shim"
	// SocketName is the control socket, published in $XDG_RUNTIME_DIR when
	// there is one.
	SocketName = "devtun.sock"
	// SocketEnv overrides socket discovery. It exists for tests and for the
	// unusual box where the conventions do not fit; ordinary use needs no
	// environment variable at all.
	SocketEnv = "DEVTUN_SOCK"
	// VersionFlag makes the shim identify itself, which is how the session
	// decides whether to re-upload. It is the only reliable way to tell the
	// shim apart from the real 1Password CLI it is pretending to be.
	VersionFlag = "--devtun-shim"
	// Handshake prefixes the version output, so a stray binary answering the
	// flag cannot be mistaken for ours.
	Handshake = "devtun-shim"
)

// ShimNames maps an argv[0] to the service a connection should announce. This
// is the entire dispatch table: the binary is one file, symlinked under several
// names, and the name it was invoked as decides what it does.
var ShimNames = map[string]string{
	"op":               ServiceOp,
	"op.exe":           ServiceOp,
	"xdg-open":         ServiceOpen,
	"sensible-browser": ServiceOpen,
	"x-www-browser":    ServiceOpen,
	"www-browser":      ServiceOpen,
	"open":             ServiceOpen,
	"gio":              ServiceOpen,
}

// OpenerNames are the argv[0] names that mean "open this URL", in the order
// they are symlinked. Kept separate from ShimNames so the install step and the
// dispatch table cannot drift apart.
var OpenerNames = []string{"xdg-open", "sensible-browser", "x-www-browser", "www-browser", "open", "gio"}

// ServiceFor reports which service an invocation as name belongs to.
func ServiceFor(name string) (string, bool) {
	svc, ok := ShimNames[filepath.Base(name)]
	return svc, ok
}

// RemotePaths are the resolved locations on a particular remote box.
type RemotePaths struct {
	Dir    string
	Bin    string
	Binary string
	Socket string
}

// PathsFor works out where everything belongs given the remote's home and
// runtime directories.
//
// The socket prefers $XDG_RUNTIME_DIR: it is per-user and mode 0700, which is
// the real defence — the socket's own 0600 is set after sshd creates it and so
// races with creation, while the directory does not. Never /tmp.
func PathsFor(home, runtimeDir string) RemotePaths {
	p := RemotePaths{
		Dir:    path.Join(home, RemoteDir),
		Bin:    path.Join(home, RemoteDir, BinDir),
		Binary: path.Join(home, RemoteDir, Binary),
	}
	if usableRuntimeDir(runtimeDir, home) {
		p.Socket = path.Join(runtimeDir, SocketName)
	} else {
		p.Socket = path.Join(p.Dir, SocketName)
	}
	return p
}

// usableRuntimeDir decides whether $XDG_RUNTIME_DIR can hold the socket.
//
// The value is set by the remote box, and devtun goes on to `chmod 700` the
// directory it names. Taking it on trust means `XDG_RUNTIME_DIR=/tmp` puts the
// control socket in a world-writable directory — and, for a root session, turns
// shared /tmp from 1777 into 0700 on the way. Neither is a thing to do because
// an environment variable asked.
//
// So it must be an absolute path and it must not be one of the shared
// directories. Anything else falls back to ~/.devtun, which devtun creates and
// chmods itself and is therefore always a safe answer.
func usableRuntimeDir(dir, home string) bool {
	if dir == "" || !path.IsAbs(dir) {
		return false
	}
	clean := path.Clean(dir)
	for _, shared := range []string{"/", "/tmp", "/var/tmp", "/dev/shm", "/usr", "/etc", "/var"} {
		if clean == shared {
			return false
		}
	}
	// A path under a world-writable temp directory is no better than the
	// directory itself.
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(clean+"/", prefix) {
			return false
		}
	}
	return true
}

// DiscoverSocket finds the control socket from inside the remote box, where
// the shim runs. It mirrors PathsFor but reads the environment, because that is
// all the shim has.
//
// It returns the first candidate that actually exists rather than the first
// that is merely plausible, and that distinction is the whole point. The
// session picks the socket's home from what $XDG_RUNTIME_DIR said in the shell
// it probed; the shim runs in a *different* shell, which may not have been
// given the same environment — a `docker exec`, a cron job, an editor's
// integrated terminal, any process started before the user's session was set
// up. When the two disagree the shim reports "no devtun session" while devtun
// is running perfectly a metre away, which is among the least debuggable
// messages a tool can produce. Looking in both places costs a stat.
func DiscoverSocket() string {
	if s := os.Getenv(SocketEnv); s != "" {
		return s
	}
	candidates := SocketCandidates()
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return path
		}
	}
	// Nothing exists yet, which is the ordinary case while a session is
	// reconnecting. Return the preferred path so the dial retry has somewhere
	// to wait for.
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// SocketCandidates lists where the control socket may live, most preferred
// first.
func SocketCandidates() []string {
	var paths []string
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		paths = append(paths, filepath.Join(dir, SocketName))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, RemoteDir, SocketName))
	}
	return paths
}
