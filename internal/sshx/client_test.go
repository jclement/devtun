package sshx

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// connectTo dials a server that asks for no credentials, for the tests that
// are about what runs over the connection rather than how it was made.
func connectTo(t *testing.T, s *testServer) *Client {
	t.Helper()
	isolatedHome(t)
	client, err := dialServer(t, s, Overrides{}, Options{
		HostKeyMode:    HostKeyNone,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return client
}

func TestRunPipesTheScriptAndStreamsOutput(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	server.respond = func(string) string { return "hello from the remote\n" }

	client := connectTo(t, server)

	var out strings.Builder
	if err := client.Run(t.Context(), "echo hi\n", &out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := out.String(); got != "hello from the remote\n" {
		t.Errorf("stdout = %q", got)
	}
	// The script goes in on stdin, so quoting is never routed through the
	// remote login shell — which may be fish, csh or something stranger.
	if got := server.lastScript(); got != "echo hi\n" {
		t.Errorf("the remote received %q, want the script we passed", got)
	}
	if got := server.lastCommand(); got != "sh -s" {
		t.Errorf("the remote ran %q, want sh -s", got)
	}
}

func TestOutputCollectsStdout(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	server.respond = func(script string) string {
		if strings.Contains(script, "for p in") {
			return "42\t/usr/bin/node server.js\n"
		}
		return ""
	}

	client := connectTo(t, server)
	got, err := client.Output(t.Context(), "for p in 42; do :; done\n")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if got != "42\t/usr/bin/node server.js\n" {
		t.Errorf("Output = %q", got)
	}
}

func TestRunHonoursContextCancellation(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	// Never respond, so the session stays open until cancelled.
	server.respond = func(string) string { select {} }

	client := connectTo(t, server)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, "sleep forever\n", io.Discard) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestDialTCPForwardsThroughTheConnection(t *testing.T) {
	// A local "remote service" the SSH server will forward to.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()

	server := startServer(t, serverOptions{noAuth: true})
	server.echo = echo.Addr().String()
	client := connectTo(t, server)

	conn, err := client.DialTCP(t.Context(), "127.0.0.1:3000")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", buf)
	}

	// The dial address must be carried to the remote unchanged, since it is
	// what selects the service on the far side.
	if got := server.forwardTargets(); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("forward targets = %v, want the requested host", got)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	client := connectTo(t, server)

	client.Close()
	client.Close() // must not panic or double-close the transport
}

// An interrupted upload must never leave a half-written executable where a
// working one is expected, so the bytes land on a temporary name and are
// renamed into place only once they are all there.
func TestUploadWritesToATemporaryNameAndRenames(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	client := connectTo(t, server)

	local := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(local, []byte("binary contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.Upload(t.Context(), local, "/home/jeff/.local/bin/devtun", 0o755); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if got := server.lastScript(); got != "binary contents" {
		t.Errorf("the remote received %q, want the file's contents", got)
	}
	command := server.lastCommand()
	for _, want := range []string{
		"mkdir -p '/home/jeff/.local/bin'",
		"cat > '/home/jeff/.local/bin/devtun.upload'",
		"chmod 755 '/home/jeff/.local/bin/devtun.upload'",
		"mv '/home/jeff/.local/bin/devtun.upload' '/home/jeff/.local/bin/devtun'",
	} {
		if !strings.Contains(command, want) {
			t.Errorf("upload command %q is missing %q", command, want)
		}
	}
}

// x/crypto/ssh has no equivalent of StreamLocalBindUnlink, so the path has to
// be prepared and any stale socket removed before the bind — and when sshd
// refuses the forward anyway, the message has to name the settings that gate
// it, because neither one mentions unix sockets.
func TestListenSocketPreparesThePathAndExplainsARefusal(t *testing.T) {
	server := startServer(t, serverOptions{noAuth: true})
	client := connectTo(t, server)

	// takeOver, so the in-use probe is skipped: this test server has no shell
	// to answer it with, and the refusal being checked here is sshd's.
	_, err := client.ListenSocket(t.Context(), "/run/user/1000/devtun.sock", true)
	if err == nil {
		t.Fatal("this server forwards nothing; ListenSocket should have failed")
	}
	if !strings.Contains(err.Error(), "AllowStreamLocalForwarding") ||
		!strings.Contains(err.Error(), "AllowTcpForwarding") {
		t.Errorf("err = %v, want it to name the sshd_config settings that gate the forward", err)
	}

	script := server.lastScript()
	for _, want := range []string{
		"mkdir -p '/run/user/1000'",
		"chmod 700 '/run/user/1000'",
		"rm -f '/run/user/1000/devtun.sock'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("preparation script %q is missing %q", script, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"/run/user/1000/devtun.sock": `'/run/user/1000/devtun.sock'`,
		"/tmp/a b":                   `'/tmp/a b'`,
		"it's":                       `'it'\''s'`,
		"; rm -rf /":                 `'; rm -rf /'`,
	}
	for input, want := range tests {
		if got := shellQuote(input); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", input, got, want)
		}
	}
}

// A socket somebody is answering on is not a stale one, and taking it over is
// how two sessions quietly break each other: the newcomer binds the path and
// the session that had it keeps running — still calling itself connected,
// still listing its services as ready — while sshd routes nothing to it ever
// again. Neither side says a word.
//
// The script is run through a real shell here rather than through the test
// SSH server, which has no shell to run it in. The shell is where a mistake
// would live.
func TestTheSocketInUseScriptTellsLiveFromStale(t *testing.T) {
	// Linux only, and that is not a dodge: the remote devtun talks to is
	// always Linux, and macOS's nc answers `-z -U` differently — it reports a
	// socket with a listener behind it as free, which this test caught and
	// which would be a real bug if the remote were ever a Mac. Verified by
	// hand in a Debian container that both nc and socat get it right there.
	// e2e/ runs this against a real box.
	if runtime.GOOS != "linux" {
		t.Skip("the probe's semantics are Linux's; e2e covers the real thing")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		if _, err := exec.LookPath("socat"); err != nil {
			t.Skip("no nc or socat on this machine to answer the question with")
		}
	}

	// A short path: a unix socket has about a hundred bytes to play with.
	dir, err := os.MkdirTemp("", "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "d.sock")

	ask := func() string {
		out, err := exec.Command("sh", "-c", socketInUseScript(socketPath)).Output()
		if err != nil {
			t.Fatalf("running the probe: %v", err)
		}
		return strings.TrimSpace(string(out))
	}

	if got := ask(); got != "free" {
		t.Errorf("a path with no socket answered %q", got)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if got := ask(); got != "busy" {
		t.Errorf("a socket with a listener behind it answered %q, which puts the takeover back", got)
	}

	// A crashed session leaves the file behind, and that one must still be
	// clearable or it locks you out of your own box.
	_ = listener.Close()
	_ = os.Remove(socketPath)
	if got := ask(); got != "free" {
		t.Errorf("a socket whose listener has gone answered %q", got)
	}
}

// The answer is read strictly: a box that cannot run the probe says so rather
// than guessing "nobody is there", which would put the takeover back silently.
func TestAnUnanswerableProbeIsAnErrorNotAFalseNegative(t *testing.T) {
	if _, err := readSocketInUse("unknown\n"); err == nil {
		t.Error("a box with no nc or socat was read as a free socket")
	}
	if inUse, err := readSocketInUse("busy\n"); err != nil || !inUse {
		t.Errorf("busy = %v, %v", inUse, err)
	}
	if inUse, err := readSocketInUse("free\n"); err != nil || inUse {
		t.Errorf("free = %v, %v", inUse, err)
	}
}
