package gpgagent

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
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

// fakeHost is the slice of service.Host this service uses: a label, a sink,
// paths, and a shell that records what it was asked to run.
type fakeHost struct {
	service.Host

	mu       sync.Mutex
	scripts  []string
	uploads  []string
	uploaded []byte
	failOn   string
	bus      *event.Bus
	facts    service.Facts
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		bus:   event.NewBus(16),
		facts: service.Facts{Tools: map[string]string{"gpg": "/usr/bin/gpg"}},
	}
}

func (h *fakeHost) Label() string        { return "bedev" }
func (h *fakeHost) Facts() service.Facts { return h.facts }
func (h *fakeHost) Events() event.Sink   { return h.bus.For("gpg-agent") }
func (h *fakeHost) ShimPath() string     { return "/home/dev/.devtun/devtun-shim" }
func (h *fakeHost) SocketPath() string   { return "/run/user/1000/devtun.sock" }

func (h *fakeHost) Output(_ context.Context, script string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scripts = append(h.scripts, script)
	if h.failOn != "" && strings.Contains(script, h.failOn) {
		return "no", errors.New("exit status 2")
	}
	return "", nil
}

func (h *fakeHost) Upload(_ context.Context, local, remote string, _ os.FileMode) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.uploads = append(h.uploads, remote)
	h.uploaded = data
	return nil
}

func (h *fakeHost) ran(fragment string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, script := range h.scripts {
		if strings.Contains(script, fragment) {
			return true
		}
	}
	return false
}

// listenUnix starts a local agent stand-in that upper-cases what it is sent,
// so a test can prove bytes went both ways.
func listenUnix(t *testing.T) (path string, ln net.Listener) {
	t.Helper()
	// A short path: a unix socket has about a hundred bytes to play with, and
	// a temp directory plus a long name overruns it on macOS.
	dir, err := os.MkdirTemp("", "gpg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path = filepath.Join(dir, "S.gpg-agent.extra")
	ln, err = net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listening on %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 512)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write([]byte(strings.ToUpper(string(buf[:n]))))
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return path, ln
}

// The bridge is a pipe: whatever the box sends reaches the agent, and whatever
// the agent answers goes back. Nothing in between reads the conversation.
func TestForwardedConnectionReachesTheLocalAgent(t *testing.T) {
	socket, _ := listenUnix(t)
	svc := New(Options{Socket: socket, Export: noKeys})
	host := newFakeHost()
	if _, err := svc.Attach(t.Context(), host); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	remote, ln := pairedListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = svc.ServeSocket(ctx, ln) }()

	if _, err := remote.Write([]byte("getinfo version\n")); err != nil {
		t.Fatalf("writing to the forwarded socket: %v", err)
	}
	reply := make([]byte, 64)
	_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := remote.Read(reply)
	if err != nil {
		t.Fatalf("reading the agent's answer: %v", err)
	}
	if got := string(reply[:n]); got != "GETINFO VERSION\n" {
		t.Errorf("the agent answered %q, so the bytes did not make the round trip", got)
	}
}

// Every connection to your signing key is a line in the security log, whether
// or not pinentry appears — a cached signature raises no dialog at all, and
// that is precisely the case where the log is the only record.
func TestEveryConnectionIsRecorded(t *testing.T) {
	socket, _ := listenUnix(t)
	svc := New(Options{Socket: socket, Export: noKeys})
	host := newFakeHost()
	if _, err := svc.Attach(t.Context(), host); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	remote, ln := pairedListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = svc.ServeSocket(ctx, ln) }()

	_, _ = remote.Write([]byte("x"))
	_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = remote.Read(make([]byte, 8))
	_ = remote.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		var found bool
		for _, e := range host.bus.History() {
			if e.Kind == "connected" && e.Class == event.Security {
				found = true
			}
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no security event for a forwarded connection: %+v", host.bus.History())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The remote gets a GNUPGHOME of devtun's own with the socket linked into it,
// because gpg computes its agent path and will not be told otherwise.
func TestAttachPreparesARemoteHome(t *testing.T) {
	socket, _ := listenUnix(t)
	svc := New(Options{Socket: socket, Export: noKeys})
	host := newFakeHost()
	if _, err := svc.Attach(t.Context(), host); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for _, want := range []string{
		"/home/dev/.devtun/gnupg",        // devtun's own directory, not the user's
		"chmod 700",                      // gpg refuses a homedir others can read
		"ln -sfn",                        // the socket is linked in, not bound there
		"/run/user/1000/devtun-gpg.sock", // ...from where the session published it
		"S.gpg-agent",
	} {
		if !host.ran(want) {
			t.Errorf("nothing in the setup mentioned %q:\n%v", want, host.scripts)
		}
	}

	// Once. A reconnect must not re-import keys or rewrite the directory.
	before := len(host.scripts)
	if _, err := svc.Attach(t.Context(), host); err != nil {
		t.Fatalf("second Attach: %v", err)
	}
	if len(host.scripts) != before {
		t.Errorf("a reconnect prepared the remote again: %v", host.scripts[before:])
	}
}

// The public half is uploaded and imported; the secret half is what the whole
// arrangement exists to keep at home.
func TestPublicKeysAreImported(t *testing.T) {
	socket, _ := listenUnix(t)
	svc := New(Options{
		Socket: socket,
		Export: func(context.Context) ([]byte, error) {
			return []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"), nil
		},
	})
	host := newFakeHost()
	if _, err := svc.Attach(t.Context(), host); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	if len(host.uploads) != 1 || !strings.HasSuffix(host.uploads[0], "devtun-pubkeys.asc") {
		t.Fatalf("the keys were not uploaded: %v", host.uploads)
	}
	if !strings.Contains(string(host.uploaded), "PUBLIC KEY") {
		t.Errorf("what was uploaded is not a public key block: %q", host.uploaded)
	}
	if !host.ran("gpg --batch --quiet --import") {
		t.Errorf("the keys were uploaded but never imported: %v", host.scripts)
	}
}

// Keys are a convenience; the socket is the service. Somebody whose box already
// has their public keys should not be told the whole thing failed.
func TestAFailedKeyExportIsNotFatal(t *testing.T) {
	socket, _ := listenUnix(t)
	svc := New(Options{
		Socket: socket,
		Export: func(context.Context) ([]byte, error) { return nil, errors.New("no gpg here") },
	})
	host := newFakeHost()
	if _, err := svc.Attach(t.Context(), host); err != nil {
		t.Fatalf("Attach failed over an export it could live without: %v", err)
	}
	var said bool
	for _, e := range host.bus.History() {
		if strings.Contains(e.Text, "public keys") {
			said = true
		}
	}
	if !said {
		t.Error("the export failed silently")
	}
}

// Both ends have to be right, and they fail differently: nothing to forward
// here, or nothing to use it there.
func TestProbeSaysWhichEndIsMissing(t *testing.T) {
	socket, _ := listenUnix(t)
	host := newFakeHost()

	if support := New(Options{Socket: socket}).Probe(t.Context(), host); !support.OK {
		t.Errorf("a working pair was refused: %s", support.Reason)
	}

	missing := New(Options{Socket: filepath.Join(t.TempDir(), "nope.sock")})
	if support := missing.Probe(t.Context(), host); support.OK {
		t.Error("a missing local agent was accepted")
	} else if !strings.Contains(support.Reason, "gpg-agent") {
		t.Errorf("the reason does not name the local agent: %q", support.Reason)
	}

	bare := newFakeHost()
	bare.facts = service.Facts{Tools: map[string]string{}}
	if support := New(Options{Socket: socket}).Probe(t.Context(), bare); support.OK {
		t.Error("a box with no gpg was accepted")
	} else if !strings.Contains(support.Reason, "bedev") {
		t.Errorf("the reason does not name the box: %q", support.Reason)
	}
}

// The line the remote shell needs names devtun's own GNUPGHOME, so unsetting
// one variable puts the box back exactly as it was.
func TestSetupLineNamesDevtunsOwnHome(t *testing.T) {
	svc := New(Options{})
	lines := svc.SetupLines(newFakeHost())
	if len(lines) != 1 || !strings.Contains(lines[0], `GNUPGHOME="/home/dev/.devtun/gnupg"`) {
		t.Errorf("setup lines = %q", lines)
	}
}

func noKeys(context.Context) ([]byte, error) { return nil, nil }

// pairedListener returns one end of a connection and a listener that will hand
// the other end to ServeSocket, which is what the session does with a
// reverse-forwarded socket.
func pairedListener(t *testing.T) (net.Conn, net.Listener) {
	t.Helper()
	client, server := net.Pipe()
	ln := &onceListener{conn: server, done: make(chan struct{})}
	t.Cleanup(func() { _ = client.Close() })
	return &deadlineConn{Conn: client}, ln
}

// onceListener hands out one connection and then blocks until it is closed.
type onceListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *onceListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *onceListener) Close() error {
	close(l.done)
	return nil
}

func (l *onceListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "pipe" }
func (dummyAddr) String() string  { return "pipe" }

// deadlineConn gives net.Pipe's ends the read deadline the tests rely on.
type deadlineConn struct{ net.Conn }

var _ io.ReadWriteCloser = (*deadlineConn)(nil)
