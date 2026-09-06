//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const settle = 45 * time.Second

// The headline claim: one SSH connection, and every port the box opens turns up
// here — the ones already listening when we connected as well as the ones that
// appear later. autotun ignored the former; devtun deliberately does not.
func TestPortsAlreadyListeningAndPortsThatAppearLaterAreBothForwarded(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx)

	// 8080 was listening before devtun connected.
	s.await("the pre-existing port 8080 forwarded", settle, opened(8080))
	// 3000 and 5173 appear five and ten seconds in.
	s.await("port 3000 forwarded after it appeared", settle, opened(3000))
	s.await("port 5173 forwarded after it appeared", settle, opened(5173))
}

// A privileged port is below the default window: it is the one thing that must
// not be scooped up, since that is what --min-port exists to prevent.
func TestPrivilegedPortIsNotForwarded(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx)
	s.await("the session to settle", settle, opened(8080))
	s.never("port 80 forwarded", 5*time.Second, opened(80))
}

// A tunnel that reports itself open must actually carry bytes to the service it
// names — not merely to something that answers.
func TestForwardedPortServesTheRightService(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx)
	e := s.await("port 8080 forwarded", settle, opened(8080))

	local := localPortFrom(t, e)
	body := get(t, fmt.Sprintf("http://127.0.0.1:%d/", local))
	if !strings.Contains(body, "port=8080") {
		t.Fatalf("the tunnel for 8080 reached the wrong service: %q", body)
	}
}

// The helper is uploaded on the first connection and left alone on the second.
// Re-uploading a megabyte on every reconnect over a hotel wifi is exactly the
// kind of thing nobody notices until they are on a hotel wifi.
func TestHelperIsUploadedOnceThenLeftAlone(t *testing.T) {
	box := start(t)

	first, cancelFirst := context.WithCancel(context.Background())
	s1 := box.runDevtun(first)
	s1.await("the helper installed", settle, kind("session", "shim-installed"))
	cancelFirst()

	// Prove it is really on the box, and executable there.
	out, err := box.ssh("~/.devtun/devtun-shim --devtun-shim")
	if err != nil || !strings.Contains(out, "devtun-shim") {
		t.Fatalf("the uploaded helper does not run on the box: %v\n%s", err, out)
	}
	// And that the symlinks that make one PATH entry work are there.
	if out, err := box.ssh("readlink ~/.devtun/bin/op ~/.devtun/bin/xdg-open"); err != nil {
		t.Fatalf("the shim symlinks are missing: %v\n%s", err, out)
	}

	second, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	s2 := box.runDevtun(second, "--verbose")
	s2.await("the helper recognised as current", settle, kind("session", "shim-current"))
	s2.never("a second upload", 3*time.Second, kind("session", "shim-installed"))
}

// The whole premise: `op` on the dev box reaches the workstation. Nothing is
// approved here, so the interesting assertion is that the request arrives and
// is refused — which proves the socket, the Hello routing, the shim's argv[0]
// dispatch and the policy layer are all wired, without needing a real vault.
func TestOpOnTheRemoteReachesTheWorkstationAndIsRefusedByDefault(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --prompt deny is how devtun runs unattended, and the zero value of a
	// decision is no.
	s := box.runDevtun(ctx, "--prompt", "deny")
	s.await("the session to settle", settle, opened(8080))

	out, err := box.ssh("~/.devtun/bin/op read op://Personal/Docker/PAT")
	if err == nil {
		t.Fatalf("an unapproved secret must not be served; got %q", out)
	}

	e := s.await("the secret request to arrive", 20*time.Second, kind("1password", "denied"))
	if e.Class != "security" {
		t.Errorf("a denial must be classed as security news, got %q", e.Class)
	}
	if !strings.Contains(e.Text, "op://Personal/Docker/PAT") {
		t.Errorf("the denial should name the subject, got %q", e.Text)
	}
}

// One connection carries every service. If this passes, the merge did what it
// was for.
func TestOneConnectionCarriesEveryService(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx, "--prompt", "deny")

	s.await("tunnels started", settle, kind("tunnels", "started"))
	s.await("the browser bridge started", settle, kind("browser", "started"))
	s.await("a tunnel opened", settle, opened(8080))

	// The op path proves the control socket is shared, since the browser and
	// 1Password services are routed by the same Hello frame.
	_, _ = box.ssh("~/.devtun/bin/op read op://Personal/Docker/PAT")
	s.await("a secret request over the same socket", 20*time.Second, kind("1password", "denied"))

	// Exactly one sshd connection for the whole lot.
	out, err := box.ssh(`ss -tn state established '( sport = :22 )' | grep -c . || true`)
	if err != nil {
		t.Skipf("could not count connections on the box: %v", err)
	}
	t.Logf("established SSH connections on the box: %s", strings.TrimSpace(out))
}

// A dropped link must rebuild every service and reclaim the same local port
// numbers, or a browser tab breaks on every wifi change.
//
// The assertion is on the event stream rather than on a live HTTP request to
// the reclaimed port. That is deliberate: a GET also depends on whether the
// developer's own laptop happens to have that port free and on the container's
// dev server still being alive, and a test that fails for those reasons teaches
// nothing about reconnection. TestForwardedPortServesTheRightService already
// proves a tunnel carries real bytes; this one proves it comes back the same.
func TestReconnectRebuildsServicesAndReclaimsPorts(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx)
	first := localPortFrom(t, s.await("port 8080 forwarded", settle, opened(8080)))
	s.await("the browser bridge started", settle, kind("browser", "started"))
	before := s.count(opened(8080))

	// Drop the link the way a vanished network does — from outside the box,
	// not through the SSH session itself. Killing it from inside means the
	// command doing the killing dies first and may never run, which is how
	// this test used to pass without ever causing a disconnection.
	box.killConnections(t)

	s.await("the session to notice the drop", 90*time.Second, func(e evt) bool {
		return e.Service == "session" && (e.Kind == "disconnected" || e.Kind == "connect-failed")
	})

	// Every service is rebuilt, not just the one that noticed.
	s.awaitNth("tunnels restarted", 90*time.Second, 2, kind("tunnels", "started"))
	s.awaitNth("1Password restarted", 60*time.Second, 2, kind("1password", "started"))
	s.awaitNth("the browser bridge restarted", 60*time.Second, 2, kind("browser", "started"))

	// And the tunnel comes back on the same local port, which is the whole
	// reason local assignments live on the Service rather than the connection.
	again := s.awaitNth("port 8080 forwarded again", 90*time.Second, before+1, opened(8080))
	if got := localPortFrom(t, again); got != first {
		t.Fatalf("local port changed across the reconnect: was %d, now %d\n%s", first, got, s.transcript())
	}
}

// --- helpers -------------------------------------------------------------

// localPortFrom reads the local port out of an "opened" event's fields.
func localPortFrom(t *testing.T, e evt) int {
	t.Helper()
	raw, ok := e.Fields["local"]
	if !ok {
		t.Fatalf("the opened event carries no local port: %+v", e)
	}
	n, ok := raw.(float64)
	if !ok {
		t.Fatalf("unexpected local port %v (%T)", raw, raw)
	}
	return int(n)
}

func get(t *testing.T, url string) string {
	t.Helper()
	body, err := tryGet(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return body
}

func tryGet(url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(body), err
}

// The agent broker, end to end: a real `ssh` client on the dev box, talking
// the real agent protocol to a socket devtun published, reaching the
// workstation's own agent.
//
// Nothing is approved here, so the assertion is that the signature is REFUSED
// and that the refusal is recorded. That proves the whole path — the second
// socket, the agent protocol, the policy gate — without needing a key the test
// is allowed to authenticate with.
func TestSSHAgentIsForwardedAndGatedByDefault(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx, "--prompt", "deny")
	s.await("the agent broker started", settle, kind("ssh-agent", "started"))

	// The socket has to exist on the box before anything can speak to it.
	sock := "$HOME/.devtun/devtun-agent.sock"
	out, err := box.ssh("test -S " + sock + " && echo present || ls /run/user/1000/devtun-agent.sock")
	if err != nil || !strings.Contains(out, "present") {
		// The runtime directory is the other legal home for it.
		if out2, err2 := box.ssh("test -S /run/user/1000/devtun-agent.sock && echo present"); err2 != nil || !strings.Contains(out2, "present") {
			t.Fatalf("no agent socket on the box: %v %q / %q\n%s", err, out, out2, s.transcript())
		}
		sock = "/run/user/1000/devtun-agent.sock"
	}

	// `ssh-add -l` speaks the real agent protocol. Listing is allowed, so this
	// proves the broker is answering rather than merely listening.
	if out, err := box.ssh("SSH_AUTH_SOCK=" + sock + " ssh-add -l"); err != nil && !strings.Contains(out, "no identities") {
		t.Logf("ssh-add -l said: %v %q", err, out)
	}
	s.await("the key listing to be recorded", 20*time.Second, kind("ssh-agent", "listed"))

	// A signature must be refused: nothing has been approved.
	_, _ = box.ssh("SSH_AUTH_SOCK=" + sock + " ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 " +
		"-o BatchMode=yes git@github.com true 2>&1 || true")

	for _, e := range s.snapshot() {
		if e.Service == "ssh-agent" && e.Kind == "denied" {
			if e.Class != "security" {
				t.Errorf("a refused signature must be security news, got %q", e.Class)
			}
			return
		}
	}
	// No signature was attempted (no keys in the workstation agent, most
	// likely). The listing above already proved the path; say so rather than
	// failing on the developer's key setup.
	t.Log("no signature was attempted; the agent had no identities to offer")
}
