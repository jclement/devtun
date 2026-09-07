//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
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

// The agent broker, end to end: a real `ssh-add` on the dev box, speaking the
// real agent protocol to a socket devtun published, reaching a real ssh-agent
// on the workstation and listing the key it holds.
//
// Listing rather than signing, deliberately. A signature only happens after a
// TCP connection and a host-key exchange with some real destination, which a CI
// runner has no business making — so exercising it here would test the network
// rather than devtun. That a key held on the workstation is visible through the
// forwarded socket proves every hop; the gate on signing is covered thoroughly
// by the unit tests, which can drive it without a network.
func TestSSHAgentIsForwardedToTheRemote(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx, "--prompt", "deny")
	s.await("the agent broker started", settle, kind("ssh-agent", "started"))

	sock := box.agentSocketPath(t, s)

	out, err := box.ssh("SSH_AUTH_SOCK=" + sock + " ssh-add -l")
	if err != nil {
		t.Fatalf("ssh-add -l through the forwarded agent failed: %v\n%s\n%s", err, out, s.transcript())
	}
	// The key the harness put in the workstation's agent must be the one the
	// box can see.
	want := box.keyFingerprint(t)
	if !strings.Contains(out, want) {
		t.Errorf("the box sees %q, want the workstation's key %s\n%s", strings.TrimSpace(out), want, s.transcript())
	}

	// And devtun recorded it, because a key listing reveals which keys exist.
	s.await("the listing to be recorded", 20*time.Second, kind("ssh-agent", "listed"))
}

// A mutating request must be refused outright — never prompted, never policy
// checked. `ssh-add -D` asks the agent to drop every key.
func TestSSHAgentRefusesToBeModifiedFromTheRemote(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := box.runDevtun(ctx, "--prompt", "deny")
	s.await("the agent broker started", settle, kind("ssh-agent", "started"))
	sock := box.agentSocketPath(t, s)

	// Whatever this reports, the workstation's agent must still hold the key.
	_, _ = box.ssh("SSH_AUTH_SOCK=" + sock + " ssh-add -D")

	out, err := box.ssh("SSH_AUTH_SOCK=" + sock + " ssh-add -l")
	if err != nil {
		t.Fatalf("listing after the delete attempt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, box.keyFingerprint(t)) {
		t.Fatalf("the remote deleted a key from the workstation's agent\n%s", s.transcript())
	}
	s.await("the refusal to be recorded", 20*time.Second, kind("ssh-agent", "refused"))
}

// The helper is downloaded when there is nothing local to upload — the path a
// release install always takes, and the one every other test here avoids by
// passing --shim-binary.
//
// That avoidance is why two releases shipped unable to install a helper at
// all. A test that supplies the thing under test proves only that the rest
// works, so this one deliberately supplies nothing and lets devtun go to the
// network for it.
func TestTheHelperIsDownloadedWhenThereIsNothingLocal(t *testing.T) {
	if os.Getenv("DEVTUN_E2E_NETWORK") == "" {
		t.Skip("set DEVTUN_E2E_NETWORK=1 to run the test that downloads from GitHub")
	}
	box := start(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Built the way a release is, because devtun refuses to download a helper
	// for a build with no release to take one from — and a cache directory of
	// its own, so a helper left by an earlier run cannot make this pass
	// without downloading anything.
	version := latestRelease(t, repoRoot(t))
	devtun := buildAs(t, repoRoot(t), runtime.GOOS, runtime.GOARCH, strings.TrimPrefix(version, "v"))

	s := box.runDevtunNoHelper(ctx, t.TempDir(), devtun)

	s.await("the helper to be downloaded", 90*time.Second, kind("session", "shim-fetching"))
	s.await("the helper to be installed", 90*time.Second, kind("session", "shim-installed"))

	out, err := box.ssh("~/.devtun/devtun-shim --devtun-shim")
	if err != nil || !strings.Contains(out, "devtun-shim") {
		t.Fatalf("the downloaded helper does not run on the box: %v\n%s\n%s", err, out, s.transcript())
	}
}

// doctor is the command people run when something is wrong, so it has to be
// right about a real box rather than about a mock of one: the same connection,
// the same probe, the same Probe call on each service.
//
// It must also change nothing. The box here has no helper installed and no
// devtun lines in its shell rc, and it must still have none afterwards — a
// diagnostic that fixes things while looking at them cannot be trusted to tell
// you what was wrong.
func TestDoctorReportsTheBoxWithoutChangingIt(t *testing.T) {
	box := start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if _, err := box.ssh("rm -rf ~/.devtun"); err != nil {
		t.Fatalf("clearing the helper: %v", err)
	}

	report := box.doctor(ctx, t)

	// The section is titled with the label decisions are recorded against —
	// the ssh_config alias where there is one, and host:port here.
	remote := report.remoteSection(t)
	for _, name := range []string{"ssh", "helper", "tunnels", "shell setup"} {
		if remote.find(name) == nil {
			t.Errorf("doctor did not check %q:\n%s", name, report.raw)
		}
	}
	if got := remote.find("ssh"); got.Status != "ok" {
		t.Errorf("ssh check = %+v", got)
	}
	// No helper on the box, and doctor says so rather than installing one.
	if got := remote.find("helper"); got.Status != "warn" || !strings.Contains(got.Detail, "not installed") {
		t.Errorf("helper check = %+v", got)
	}
	if out, err := box.ssh("test -e ~/.devtun/devtun-shim && echo present || echo absent"); err != nil ||
		!strings.Contains(out, "absent") {
		t.Errorf("doctor installed the helper: %v %q", err, out)
	}

	// And the local half is there too, since half the reasons 1Password does
	// not work are on this side.
	local := report.section("this machine")
	if local == nil || local.find("1password") == nil {
		t.Errorf("no local checks in the report:\n%s", report.raw)
	}
}
