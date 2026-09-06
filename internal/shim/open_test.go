package shim

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOpenSendsTheURL(t *testing.T) {
	session := openSession(t, func(openRequest) openResponse { return openResponse{OK: true} })

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOpen(t.Context(),
		[]string{"http://localhost:5173/"}, piped("", &stdout, &stderr))

	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	requests := session.openRequests()
	if len(requests) != 1 || requests[0].URL != "http://localhost:5173/" {
		t.Errorf("requests = %+v, want the URL sent once", requests)
	}
	if got := session.services(); !slices.Equal(got, []string{ServiceOpen}) {
		t.Errorf("announced %v, want the connection to name the browser service", got)
	}
}

// Some desktop stacks spell xdg-open as `gio open URL`, and the shim is
// symlinked as gio for exactly that. The subcommand is not part of the URL.
func TestOpenShiftsPastTheGioSubcommand(t *testing.T) {
	session := openSession(t, func(openRequest) openResponse { return openResponse{OK: true} })

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOpen(t.Context(),
		[]string{"open", "https://example.test/auth"}, piped("", &stdout, &stderr))

	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	requests := session.openRequests()
	if len(requests) != 1 || requests[0].URL != "https://example.test/auth" {
		t.Errorf("requests = %+v, want the URL after the subcommand", requests)
	}
}

// With no session there is nowhere to send the URL and no local opener to fall
// back to — ~/.devtun/bin is ahead of the real one on PATH, so exec'ing it
// would recurse into this binary. Printing the URL is the honest end of it.
func TestOpenPrintsTheURLWhenNothingIsListening(t *testing.T) {
	c := &Client{
		SocketPath: filepath.Join(shortTempDir(t), "absent.sock"),
		Version:    "test",
		Wait:       200 * time.Millisecond,
	}

	var stdout, stderr bytes.Buffer
	code := c.DispatchOpen(t.Context(), []string{"https://example.test/auth"}, piped("", &stdout, &stderr))

	if code == 0 {
		t.Error("a URL that was never opened must not report success")
	}
	if !strings.Contains(stderr.String(), "https://example.test/auth") {
		t.Errorf("stderr = %q, want the URL the user now has to open", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want the notice on stderr only", stdout.String())
	}
}

// A refusal from the workstation — an unforwarded loopback port, say — is the
// same outcome for the user as no session at all.
func TestOpenPrintsTheURLWhenTheWorkstationRefuses(t *testing.T) {
	session := openSession(t, func(openRequest) openResponse {
		return openResponse{Error: "port 5173 is not forwarded from this host"}
	})

	var stdout, stderr bytes.Buffer
	code := session.client().DispatchOpen(t.Context(),
		[]string{"http://localhost:5173/"}, piped("", &stdout, &stderr))

	if code == 0 {
		t.Error("a refused URL must not report success")
	}
	if !strings.Contains(stderr.String(), "not forwarded") {
		t.Errorf("stderr = %q, want the reason the workstation gave", stderr.String())
	}
	if !strings.Contains(stderr.String(), "http://localhost:5173/") {
		t.Errorf("stderr = %q, want the URL the user now has to open", stderr.String())
	}
}
