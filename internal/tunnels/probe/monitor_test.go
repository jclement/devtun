package probe

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner replays a canned prober stream and records the scripts it is
// asked to run. It stands in for an SSH connection.
type fakeRunner struct {
	stream string
	// hold, when set, blocks Run until closed, simulating a live session.
	hold chan struct{}

	mu        sync.Mutex
	ranScript string
	outputs   map[string]string
	outputErr error
	nOutput   int
}

func (f *fakeRunner) Run(ctx context.Context, script string, stdout io.Writer) error {
	f.mu.Lock()
	f.ranScript = script
	f.mu.Unlock()

	if _, err := io.WriteString(stdout, f.stream); err != nil {
		return err
	}
	if f.hold == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.hold:
		return nil
	}
}

func (f *fakeRunner) Output(ctx context.Context, script string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nOutput++
	if f.outputErr != nil {
		return "", f.outputErr
	}
	for key, val := range f.outputs {
		if strings.Contains(script, key) {
			return val, nil
		}
	}
	return "", nil
}

func (f *fakeRunner) outputCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nOutput
}

// stream builds a framed prober transcript.
func stream(mode string, scans ...string) string {
	var b strings.Builder
	b.WriteString("@@DEVTUN-READY 1 " + mode + " Linux\n")
	for _, s := range scans {
		b.WriteString("@@DEVTUN-SCAN\n")
		b.WriteString(s)
		if !strings.HasSuffix(s, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("@@DEVTUN-END\n")
	}
	return b.String()
}

func TestMonitorParsesFramedScans(t *testing.T) {
	scan1 := "LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=42,fd=20))"
	scan2 := scan1 + "\nLISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:((\"python3\",pid=77,fd=3))"

	r := &fakeRunner{stream: stream("ss", scan1, scan2)}
	m := NewMonitor(r, time.Second)

	var infos []Info
	var results []Result
	err := m.Run(context.Background(),
		func(i Info) { infos = append(infos, i) },
		func(res Result) { results = append(results, res) })

	if !errors.Is(err, io.EOF) {
		t.Fatalf("Run() = %v, want io.EOF at end of stream", err)
	}
	if len(infos) != 1 || infos[0].Mode != ModeSS || infos[0].OS != "Linux" {
		t.Fatalf("onReady got %+v, want one ss/Linux info", infos)
	}
	if len(results) != 2 {
		t.Fatalf("got %d scans, want 2", len(results))
	}
	if len(results[0].Snapshot) != 1 {
		t.Errorf("first scan = %+v, want 1 service", results[0].Snapshot)
	}
	if got := results[1].Snapshot.Ports(); len(got) != 2 || got[0] != 3000 || got[1] != 8080 {
		t.Errorf("second scan ports = %v, want [3000 8080]", got)
	}
}

func TestMonitorRunsTheRenderedScript(t *testing.T) {
	r := &fakeRunner{stream: stream("ss")}
	m := NewMonitor(r, 5*time.Second)
	_ = m.Run(context.Background(), nil, nil)

	r.mu.Lock()
	script := r.ranScript
	r.mu.Unlock()

	if !strings.Contains(script, "sleep 5") {
		t.Errorf("script does not carry the configured interval:\n%s", script)
	}
}

func TestMonitorProcMode(t *testing.T) {
	scan := readFixture(t, "proc_net_tcp.txt") + "@@DEVTUN-SOCKMAP\n" + readFixture(t, "proc_sockmap.txt")
	r := &fakeRunner{stream: stream("proc", scan)}
	m := NewMonitor(r, time.Second)

	var results []Result
	_ = m.Run(context.Background(), nil, func(res Result) { results = append(results, res) })

	if len(results) != 1 {
		t.Fatalf("got %d scans, want 1", len(results))
	}
	svc, ok := results[0].Snapshot[3000]
	if !ok {
		t.Fatalf("port 3000 missing from %v", results[0].Snapshot.Ports())
	}
	if svc.PID != 14523 {
		t.Errorf("pid = %d, want 14523 (resolved through the sockmap section)", svc.PID)
	}
}

func TestMonitorReportsRemoteError(t *testing.T) {
	r := &fakeRunner{stream: "@@DEVTUN-ERROR no usable port discovery tool\n"}
	m := NewMonitor(r, time.Second)

	err := m.Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no usable port discovery tool") {
		t.Fatalf("Run() = %v, want the remote's error text", err)
	}
}

func TestMonitorRejectsSilentRemote(t *testing.T) {
	r := &fakeRunner{stream: ""}
	m := NewMonitor(r, time.Second)

	err := m.Run(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no output") {
		t.Fatalf("Run() = %v, want a no-output error", err)
	}
}

func TestMonitorRejectsUnknownMode(t *testing.T) {
	r := &fakeRunner{stream: "@@DEVTUN-READY 1 telepathy Linux\n"}
	m := NewMonitor(r, time.Second)

	if err := m.Run(context.Background(), nil, nil); err == nil {
		t.Fatal("want an error for an unknown discovery mode")
	}
}

func TestMonitorIgnoresTrailingGarbage(t *testing.T) {
	// A truncated final scan must not be delivered as an empty snapshot.
	s := stream("ss", "LISTEN 0 5 127.0.0.1:3000 0.0.0.0:*") + "@@DEVTUN-SCAN\nLISTEN 0 5 127.0.0.1:99"
	r := &fakeRunner{stream: s}
	m := NewMonitor(r, time.Second)

	var n int
	_ = m.Run(context.Background(), nil, func(Result) { n++ })
	if n != 1 {
		t.Errorf("delivered %d scans, want 1 (the unterminated one is dropped)", n)
	}
}

func TestMonitorStopsOnContextCancel(t *testing.T) {
	r := &fakeRunner{stream: stream("ss", "LISTEN 0 5 127.0.0.1:3000 0.0.0.0:*"), hold: make(chan struct{})}
	m := NewMonitor(r, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, nil, func(Result) { cancel() }) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestMonitorResolvesCommandLinesOncePerPID(t *testing.T) {
	scan := "LISTEN 0 5 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=42,fd=20))"
	r := &fakeRunner{
		stream:  stream("ss", scan, scan, scan),
		outputs: map[string]string{"for p in 42": "42\t/usr/bin/node  /app/server.js\n"},
	}
	m := NewMonitor(r, time.Second)
	_ = m.Run(context.Background(), nil, nil)

	// Resolution is asynchronous; give it a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := m.Cmdline(42); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cmd, ok := m.Cmdline(42)
	if !ok {
		t.Fatal("command line was never resolved")
	}
	if cmd != "/usr/bin/node /app/server.js" {
		t.Errorf("cmdline = %q, want whitespace-collapsed command", cmd)
	}
	if n := r.outputCalls(); n != 1 {
		t.Errorf("resolved %d times across 3 scans, want 1", n)
	}
}

func TestMonitorRetriesFailedResolution(t *testing.T) {
	scan := "LISTEN 0 5 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=42,fd=20))"
	r := &fakeRunner{stream: stream("ss", scan), outputErr: errors.New("boom")}
	m := NewMonitor(r, time.Second)

	_ = m.Run(context.Background(), nil, nil)

	// A failed resolution must clear the pending marker, otherwise the pid is
	// never retried for the rest of the session.
	if !waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.unknown) == 0
	}) {
		t.Fatal("pid stayed marked as pending after a failed resolution")
	}

	// A later scan should therefore try again.
	_ = m.Run(context.Background(), nil, nil)
	if !waitFor(t, func() bool { return r.outputCalls() >= 2 }) {
		t.Errorf("resolution attempted %d times, want a retry after failure", r.outputCalls())
	}
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestCmdlineScriptAndParse(t *testing.T) {
	script := CmdlineScript([]int{42, 0, -1, 77})
	if !strings.Contains(script, "for p in 42 77;") {
		t.Errorf("script should list only valid pids:\n%s", script)
	}

	got := ParseCmdlines("42\t/usr/bin/node   server.js \n77\tpython3 -m http.server\nnonsense\n99\t\n")
	want := map[string]string{"42": "/usr/bin/node server.js", "77": "python3 -m http.server"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d entries", got, len(want))
	}
	if got[42] != want["42"] || got[77] != want["77"] {
		t.Errorf("ParseCmdlines = %v", got)
	}
}

func TestScriptInterval(t *testing.T) {
	tests := map[time.Duration]string{
		2 * time.Second:        "sleep 2",
		500 * time.Millisecond: "sleep 0.5",
		time.Millisecond:       "sleep 0.1", // clamped to the floor
	}
	for d, want := range tests {
		if got := Script(d); !strings.Contains(got, want) {
			t.Errorf("Script(%v) does not contain %q", d, want)
		}
	}
}

func TestScriptIsPOSIX(t *testing.T) {
	s := Script(2 * time.Second)
	for _, bad := range []string{"[[", "local ", "declare ", "$'", "function "} {
		if strings.Contains(s, bad) {
			t.Errorf("prober script uses the non-POSIX construct %q", bad)
		}
	}
	for _, want := range []string{"@@DEVTUN-READY", "@@DEVTUN-SCAN", "@@DEVTUN-END", "ss -ltnp", "lsof", "netstat", "/proc/net/tcp"} {
		if !strings.Contains(s, want) {
			t.Errorf("prober script is missing %q", want)
		}
	}
}
