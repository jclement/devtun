package shim

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSession is an in-process stand-in for the devtun session: a unix socket
// that accepts one connection per request, reads the Hello every service
// begins with, and answers from a canned handler. No SSH, no real `op`, no
// browser.
type fakeSession struct {
	path string

	mu     sync.Mutex
	hellos []Hello
	ops    []opRequest
	opens  []openRequest
}

// opSession answers `op` requests with answer, recording what it was asked.
func opSession(t *testing.T, answer func(opRequest) opResponse) *fakeSession {
	t.Helper()
	f := &fakeSession{}
	f.listen(t, func(conn net.Conn) {
		var request opRequest
		if err := ReadFrame(conn, &request); err != nil {
			return
		}
		f.mu.Lock()
		f.ops = append(f.ops, request)
		f.mu.Unlock()
		_ = WriteFrame(conn, answer(request))
	})
	return f
}

// openSession answers open requests with answer.
func openSession(t *testing.T, answer func(openRequest) openResponse) *fakeSession {
	t.Helper()
	f := &fakeSession{}
	f.listen(t, func(conn net.Conn) {
		var request openRequest
		if err := ReadFrame(conn, &request); err != nil {
			return
		}
		f.mu.Lock()
		f.opens = append(f.opens, request)
		f.mu.Unlock()
		_ = WriteFrame(conn, answer(request))
	})
	return f
}

func (f *fakeSession) listen(t *testing.T, serve func(net.Conn)) {
	t.Helper()
	f.path = filepath.Join(shortTempDir(t), "devtun.sock")
	listener, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatalf("listening on %s: %v", f.path, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var hello Hello
				if err := ReadFrame(conn, &hello); err != nil {
					return
				}
				f.mu.Lock()
				f.hellos = append(f.hellos, hello)
				f.mu.Unlock()
				serve(conn)
			}()
		}
	}()
}

// client dials this session and makes a single attempt, so a test never sits
// in the reconnect grace window.
func (f *fakeSession) client() *Client {
	return &Client{SocketPath: f.path, Version: "test"}
}

func (f *fakeSession) opRequests() []opRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ops)
}

func (f *fakeSession) openRequests() []openRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.opens)
}

func (f *fakeSession) services() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var seen []string
	for _, hello := range f.hellos {
		seen = append(seen, hello.Service)
	}
	return seen
}

// piped builds streams whose stdin is a pipe rather than a terminal, which is
// what the shim sees when a script invokes it.
func piped(in string, out, errOut io.Writer) Streams {
	return Streams{In: strings.NewReader(in), Out: out, Err: errOut}
}

// shortTempDir keeps unix socket paths inside the 104-byte sun_path limit that
// macOS enforces; t.TempDir() embeds the test name and can exceed it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "devtun")
	if err != nil {
		t.Fatalf("creating a temporary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPassthroughForwardsTheCommandAndItsExitCode(t *testing.T) {
	session := opSession(t, func(opRequest) opResponse {
		return opResponse{Exit: 3, Stdout: []byte("a secret\n"), Stderr: []byte("a warning\n")}
	})

	var out, errOut bytes.Buffer
	code := session.client().DispatchOp(t.Context(), []string{"read", "op://V/I/F"}, piped("", &out, &errOut))

	if code != 3 {
		t.Errorf("exit = %d, want op's own 3", code)
	}
	if out.String() != "a secret\n" {
		t.Errorf("stdout = %q, want op's stdout verbatim", out.String())
	}
	if !strings.Contains(errOut.String(), "a warning\n") {
		t.Errorf("stderr = %q, want op's stderr verbatim", errOut.String())
	}

	requests := session.opRequests()
	if len(requests) != 1 {
		t.Fatalf("sent %d requests, want exactly one", len(requests))
	}
	if requests[0].Op != opExec || !slices.Equal(requests[0].Argv, []string{"read", "op://V/I/F"}) {
		t.Errorf("request = %+v, want the argv forwarded verbatim as an exec", requests[0])
	}
	if got := session.services(); !slices.Equal(got, []string{ServiceOp}) {
		t.Errorf("announced %v, want the connection to name the 1password service", got)
	}
}

// A devtun-level refusal is not op's own output, so it is labelled rather than
// mixed into the stream a script may be parsing.
func TestPassthroughLabelsADevtunError(t *testing.T) {
	session := opSession(t, func(opRequest) opResponse {
		return opResponse{Exit: 77, Error: "denied by devtun: refused at the prompt"}
	})

	var out, errOut bytes.Buffer
	code := session.client().DispatchOp(t.Context(), []string{"read", "op://V/I/F"}, piped("", &out, &errOut))

	if code != 77 {
		t.Errorf("exit = %d, want the refusal's 77", code)
	}
	if !strings.Contains(errOut.String(), "op (via devtun): denied by devtun") {
		t.Errorf("stderr = %q, want the error attributed to devtun", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing on the stream that carries secrets", out.String())
	}
}

// Reading stdin from an interactive invocation would block forever waiting for
// input nobody is going to type.
func TestStdinTravelsOnlyWhenItIsNotATerminal(t *testing.T) {
	for _, test := range []struct {
		name       string
		isTerminal bool
		want       string
	}{
		{name: "piped", isTerminal: false, want: "a document\n"},
		{name: "terminal", isTerminal: true, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := opSession(t, func(opRequest) opResponse { return opResponse{} })

			var out, errOut bytes.Buffer
			streams := piped("a document\n", &out, &errOut)
			streams.InIsTerminal = test.isTerminal
			session.client().DispatchOp(t.Context(), []string{"document", "create"}, streams)

			requests := session.opRequests()
			if len(requests) != 1 {
				t.Fatalf("sent %d requests, want exactly one", len(requests))
			}
			if got := string(requests[0].Stdin); got != test.want {
				t.Errorf("forwarded stdin %q, want %q", got, test.want)
			}
		})
	}
}

// A session that was never started must fail promptly rather than after the
// whole grace window, and say where it looked.
func TestDispatchOpGivesUpWhenNothingIsListening(t *testing.T) {
	c := &Client{
		SocketPath: filepath.Join(shortTempDir(t), "absent.sock"),
		Version:    "test",
		Wait:       200 * time.Millisecond,
	}

	var out, errOut bytes.Buffer
	started := time.Now()
	code := c.DispatchOp(t.Context(), []string{"read", "op://V/I/F"}, piped("", &out, &errOut))

	if code == 0 {
		t.Error("a shim with nowhere to send the request must not report success")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("took %s to give up on a %s wait", elapsed, c.Wait)
	}
	if !strings.Contains(errOut.String(), "no devtun session") {
		t.Errorf("stderr = %q, want it to say no session is listening", errOut.String())
	}
	if strings.Count(errOut.String(), "waiting up to") != 1 {
		t.Errorf("the wait should be announced exactly once, got:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", out.String())
	}
}

// The session identifies the remote shim by running it with this flag and
// parsing two fields out of the answer; internal/session/shimsync.go is the
// other half, and it runs the binary as ~/.devtun/devtun-shim rather than as
// one of the symlinked names — which is why the handshake is answered before
// the argv[0] lookup.
func TestRunAsShimAnswersTheVersionHandshake(t *testing.T) {
	captured := captureStdout(t, func() {
		code := RunAsShim(t.Context(), "/home/jsc/.devtun/"+Binary, []string{VersionFlag}, "1.2.3")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
	})

	fields := strings.Fields(strings.TrimSpace(captured))
	if len(fields) != 2 || fields[0] != Handshake || fields[1] != "1.2.3" {
		t.Errorf("handshake = %q, want %q and the version, and nothing else", captured, Handshake)
	}
}

// captureStdout collects what fn writes to the real os.Stdout, which is where
// the handshake has to go: the session reads it from a shell.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating a pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	collected := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		collected <- buf.String()
	}()

	fn()
	_ = w.Close()
	out := <-collected
	_ = r.Close()
	return out
}

func TestLeadingCommand(t *testing.T) {
	tests := []struct {
		argv []string
		want string
	}{
		{argv: []string{"read", "op://V/I/F"}, want: "read"},
		// A global option's *value* is not the subcommand. This case used to
		// assert "x", which is what the bug did rather than what is correct.
		{argv: []string{"--account", "x", "read", "op://V/I/F"}, want: "read"},
		{argv: []string{"inject", "-i", "t"}, want: "inject"},
		{argv: []string{"--version"}, want: ""},
		{argv: nil, want: ""},
	}
	for _, test := range tests {
		if got := leadingCommand(test.argv); got != test.want {
			t.Errorf("leadingCommand(%v) = %q, want %q", test.argv, got, test.want)
		}
	}
}

// `inject` and `run` act on files and processes on *this* machine, so they must
// be recognised however they are spelled. Missing one sends a command meant to
// run here to the workstation instead.
func TestLeadingCommandSkipsGlobalFlags(t *testing.T) {
	cases := map[string][]string{
		"run":    {"--account", "work", "run", "--", "deploy.sh"},
		"inject": {"--account=work", "inject", "-i", "in", "-o", "out"},
		"read":   {"--no-color", "read", "op://V/I/F"},
		"item":   {"--format", "json", "item", "get", "X"},
		"":       {"--version"},
	}
	for want, argv := range cases {
		if got := leadingCommand(argv); got != want {
			t.Errorf("leadingCommand(%v) = %q, want %q", argv, got, want)
		}
	}
}

// After `--` nothing is an op subcommand; it is the user's own command line.
func TestLeadingCommandStopsAtDoubleDash(t *testing.T) {
	if got := leadingCommand([]string{"--", "run"}); got != "" {
		t.Errorf("anything after -- is not a subcommand, got %q", got)
	}
}

// The subcommand's own arguments start after it, which is not argv[1:] when
// global options came first. Getting this wrong handed `run` the list
// "work run -- deploy.sh" and tried to execute "work".
func TestSplitCommandReturnsArgumentsAfterTheSubcommand(t *testing.T) {
	command, rest := splitCommand([]string{"--account", "work", "run", "--", "deploy.sh", "--flag"})

	if command != "run" {
		t.Fatalf("command = %q, want run", command)
	}
	if len(rest) != 3 || rest[0] != "--" || rest[1] != "deploy.sh" || rest[2] != "--flag" {
		t.Errorf("rest = %v, want the arguments after `run`", rest)
	}

	command, rest = splitCommand([]string{"inject", "-i", "in", "-o", "out"})
	if command != "inject" || len(rest) != 4 {
		t.Errorf("with no global flags: command=%q rest=%v", command, rest)
	}

	if command, rest := splitCommand([]string{"--version"}); command != "" || rest != nil {
		t.Errorf("a command-less invocation should yield nothing, got %q %v", command, rest)
	}
}
