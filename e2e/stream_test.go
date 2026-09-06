//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// stream reads devtun's NDJSON output so a test can wait for an event rather
// than sleeping and hoping. Polling a log for a substring is how e2e suites
// become flaky; waiting for a named event is not.
type stream struct {
	t    *testing.T
	cmd  *exec.Cmd
	mu   sync.Mutex
	seen []evt
	errs strings.Builder
	done chan struct{}
}

type evt struct {
	Time    time.Time      `json:"time"`
	Service string         `json:"service"`
	Kind    string         `json:"kind"`
	Class   string         `json:"class"`
	Level   string         `json:"level"`
	Text    string         `json:"text"`
	Fields  map[string]any `json:"fields"`
}

func newStream(t *testing.T, cmd *exec.Cmd) *stream {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting devtun: %v", err)
	}

	s := &stream{t: t, cmd: cmd, done: make(chan struct{})}
	go s.consume(stdout)
	go func() {
		body, _ := io.ReadAll(stderr)
		s.mu.Lock()
		s.errs.Write(body)
		s.mu.Unlock()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-s.done
	})
	return s
}

func (s *stream) consume(r io.Reader) {
	defer close(s.done)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for scanner.Scan() {
		var e evt
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue // a non-JSON line is not an event; ignore rather than fail
		}
		s.mu.Lock()
		s.seen = append(s.seen, e)
		s.mu.Unlock()
	}
}

// await blocks until an event satisfies match, and fails with the whole stream
// if it does not arrive — the transcript is what makes an e2e failure
// diagnosable rather than merely red.
func (s *stream) await(what string, timeout time.Duration, match func(evt) bool) evt {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, e := range s.seen {
			if match(e) {
				s.mu.Unlock()
				return e
			}
		}
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("never saw %s within %s\n%s", what, timeout, s.transcript())
	return evt{}
}

// awaitNth waits for the nth event satisfying match, counting from one. It is
// how "this happened a second time" is asserted without racing the first.
func (s *stream) awaitNth(what string, timeout time.Duration, n int, match func(evt) bool) evt {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		seen := 0
		for _, e := range s.seen {
			if !match(e) {
				continue
			}
			if seen++; seen == n {
				s.mu.Unlock()
				return e
			}
		}
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("never saw %s (occurrence %d) within %s\n%s", what, n, timeout, s.transcript())
	return evt{}
}

// count reports how many recorded events satisfy match.
func (s *stream) count(match func(evt) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.seen {
		if match(e) {
			n++
		}
	}
	return n
}

// never asserts that an event does not appear within the window. Used for the
// things devtun must NOT do, which are as much a part of the contract as the
// things it must.
func (s *stream) never(what string, window time.Duration, match func(evt) bool) {
	s.t.Helper()
	time.Sleep(window)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.seen {
		if match(e) {
			s.t.Fatalf("expected never to see %s, but got: %+v\n%s", what, e, s.transcriptLocked())
		}
	}
}

// snapshot copies what has been seen so far, for assertions that scan rather
// than wait.
func (s *stream) snapshot() []evt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]evt(nil), s.seen...)
}

func (s *stream) transcript() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transcriptLocked()
}

func (s *stream) transcriptLocked() string {
	var b strings.Builder
	b.WriteString("--- devtun events ---\n")
	for _, e := range s.seen {
		b.WriteString(e.Time.Format("15:04:05") + " " + e.Service + " " + e.Kind + ": " + e.Text + "\n")
	}
	if s.errs.Len() > 0 {
		b.WriteString("--- stderr ---\n" + s.errs.String())
	}
	return b.String()
}

// opened matches a tunnel opening for a remote port.
//
// It matches the structured field rather than the rendered text, and that is
// not fussiness: substring-matching "80" against "remote 8080 → …" is true, so
// the text version of this quietly passed a test asserting that port 80 is
// NEVER forwarded. A matcher that can produce a false positive on the negative
// case is worse than no test.
func opened(remotePort int) func(evt) bool {
	return func(e evt) bool {
		if e.Service != "tunnels" || e.Kind != "opened" {
			return false
		}
		got, ok := e.Fields["remote"].(float64)
		return ok && int(got) == remotePort
	}
}

func kind(service, k string) func(evt) bool {
	return func(e evt) bool { return e.Service == service && e.Kind == k }
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
