//go:build e2e

// Package e2e drives devtun against a real dev box in Docker: a real sshd, a
// real reverse-forwarded socket, real dev servers appearing on a delay.
//
// It exists because the interesting failures are all at the seams. Every unit
// test here uses an in-process SSH server or no network at all, which is the
// right trade for speed — but it means nothing in the unit suite proves that
// sshd actually permits the stream-local forward, that a cross-built helper
// runs on the target, or that one connection really does carry three services
// at once.
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	image     = "devtun-e2e:latest"
	container = "devtun-e2e"
	// bootTimeout is generous: the image builds on a cold CI runner.
	bootTimeout = 3 * time.Minute
)

// box is a running dev box plus the credentials to reach it.
type box struct {
	t       *testing.T
	port    string
	keyPath string
	devtun  string
	helper  string
	// stubBin holds the workstation-side commands devtun looks for. The suite
	// supplies its own rather than borrowing the developer's, so it tests
	// devtun and not whatever happens to be installed: a CI runner has no `op`
	// and no agent, and without these four tests silently became assertions
	// about somebody's laptop.
	stubBin string
	// agentSock is a real ssh-agent started for this test.
	agentSock string
}

// start builds the image, generates a throwaway key, and boots the box.
func start(t *testing.T) *box {
	t.Helper()
	requireDocker(t)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	run(t, "ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", keyPath)
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("reading the generated public key: %v", err)
	}

	root := repoRoot(t)
	run(t, "docker", "build", "-q", "-t", image, "-f",
		filepath.Join(root, "e2e", "Dockerfile"), filepath.Join(root, "e2e"))

	_ = exec.Command("docker", "rm", "-f", container).Run()
	run(t, "docker", "run", "-d", "--name", container, "-P",
		"-e", "AUTHORIZED_KEYS="+string(pub), image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })

	out := run(t, "docker", "port", container, "22")
	_, port, ok := strings.Cut(strings.TrimSpace(strings.Split(out, "\n")[0]), ":")
	if !ok {
		t.Fatalf("could not read the mapped SSH port from %q", out)
	}

	b := &box{
		t: t, port: port, keyPath: keyPath,
		stubBin:   stubTools(t),
		agentSock: startAgent(t, keyPath),
		devtun:    build(t, root, runtime.GOOS, runtime.GOARCH),
		// The helper that gets uploaded has to be built for the container, not
		// for this laptop. Without it devtun reports, correctly, that it has no
		// binary for that platform — which is a real message a user can hit,
		// but not what these tests are here to exercise.
		helper: build(t, root, "linux", runtime.GOARCH),
	}
	b.waitForSSH()
	return b
}

// build compiles the binary under test for one platform. It is built rather
// than assumed so the suite tests this working tree, not whatever is on PATH.
func build(t *testing.T, root, goos, goarch string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "devtun-"+goos+"-"+goarch)
	cmd := exec.Command("go", "build", "-o", out, "./cmd/devtun")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building devtun for %s/%s: %v\n%s", goos, goarch, err, output)
	}
	return out
}

// waitForSSH blocks until sshd is answering, so a slow container start is not
// mistaken for a connection bug.
func (b *box) waitForSSH() {
	b.t.Helper()
	deadline := time.Now().Add(bootTimeout)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", container, "true").Run(); err == nil {
			if out, err := b.ssh("echo ready"); err == nil && strings.Contains(out, "ready") {
				return
			}
		}
		time.Sleep(time.Second)
	}
	b.t.Fatal("the dev box never became reachable over SSH")
}

// ssh runs a command on the box with the real ssh client, which is the
// independent check: it proves the box works without going through devtun.
func (b *box) ssh(command string) (string, error) {
	cmd := exec.Command("ssh",
		"-i", b.keyPath, "-p", b.port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"dev@127.0.0.1", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// devtunArgs is the common flag set: a throwaway config directory so a test
// never reads or writes the developer's own settings, and no host-key
// checking, because the container's key is new every run.
func (b *box) devtunArgs(extra ...string) []string {
	return append([]string{
		"--host-key", "no",
		"-i", b.keyPath,
		"-p", b.port,
		"--json",
		"--setup", "never",
		"--shim-binary", b.helper,
	}, extra...)
}

// runDevtun starts devtun against the box and returns a handle for reading its
// event stream.
func (b *box) runDevtun(ctx context.Context, extra ...string) *stream {
	b.t.Helper()
	args := append(b.devtunArgs(extra...), "dev@127.0.0.1")
	cmd := exec.CommandContext(ctx, b.devtun, args...)
	cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+b.t.TempDir(),
		"DEVTUN_E2E=1",
		// The stubs come first so devtun finds them rather than a real `op`
		// that may or may not be installed and signed in.
		"PATH="+b.stubBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSH_AUTH_SOCK="+b.agentSock,
	)
	return newStream(b.t, cmd)
}

// killConnections drops every established SSH session on the box while leaving
// the listener alive, so a reconnect has something to reconnect to.
//
// The patterns are tried in order because the process name depends on the
// OpenSSH version: 9.8 split the per-session work out into a separate
// `sshd-session` binary, so the older `sshd: user@…` title matches nothing on a
// current Debian. Getting this wrong does not fail loudly — it silently kills
// nothing, and the test then waits out its timeout for a disconnection that was
// never caused.
func (b *box) killConnections(t *testing.T) {
	t.Helper()
	patterns := []string{"sshd-session", "sshd: dev", "sshd:.*@"}
	for _, pattern := range patterns {
		if err := exec.Command("docker", "exec", container, "pkill", "-f", pattern).Run(); err == nil {
			return // pkill exits 0 only when it matched something
		}
	}
	t.Fatalf("no SSH session matched any of %v on the box, so nothing was disconnected; "+
		"check what sshd calls its per-connection processes here", patterns)
}

// stubTools builds a directory of the workstation-side commands devtun probes
// for, and returns it for prepending to PATH.
//
// Only `op --version` needs to succeed: it is what the 1Password service's
// Probe runs to prove the CLI works before anything remote is wired up. No
// test here approves a secret, so the stub never has to produce one — and it
// refuses loudly if asked, since a stub that silently returned something would
// make a passing test meaningless.
func stubTools(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
  --version) echo "2.30.0"; exit 0 ;;
esac
echo "op stub: refusing to produce a secret for: $*" >&2
exit 1
`
	if err := os.WriteFile(filepath.Join(dir, "op"), []byte(script), 0o755); err != nil {
		t.Fatalf("writing the op stub: %v", err)
	}
	return dir
}

// startAgent runs a real ssh-agent holding one real key, and returns its
// socket.
//
// A real agent rather than a fake one because the point of these tests is that
// a real `ssh` client on the box can talk, through devtun, to a real agent
// here. Faking either end would leave the interesting seam untested.
func startAgent(t *testing.T, keyPath string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent is not available")
	}

	// The socket goes in a short path: a unix socket path is capped near 104
	// characters, and a t.TempDir() under a long test name can exceed it.
	dir, err := os.MkdirTemp("", "devtun-agent")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	cmd := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting ssh-agent: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ssh-agent never created its socket")
		}
		time.Sleep(50 * time.Millisecond)
	}

	add := exec.Command("ssh-add", keyPath)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}
	return sock
}

// agentSocketPath finds where devtun published the agent socket on the box. It
// may be in the runtime directory or under the home directory, and which one
// depends on the container rather than on devtun.
func (b *box) agentSocketPath(t *testing.T, s *stream) string {
	t.Helper()
	for _, candidate := range []string{"$HOME/.devtun/devtun-agent.sock", "/run/user/1000/devtun-agent.sock"} {
		if out, err := b.ssh("test -S " + candidate + " && echo present"); err == nil && strings.Contains(out, "present") {
			return candidate
		}
	}
	t.Fatalf("devtun published no agent socket on the box\n%s", s.transcript())
	return ""
}

// keyFingerprint is the SHA256 fingerprint of the key the harness generated,
// which is what ssh-add -l prints.
func (b *box) keyFingerprint(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("ssh-keygen", "-lf", b.keyPath+".pub").Output()
	if err != nil {
		t.Fatalf("ssh-keygen -lf: %v", err)
	}
	for _, field := range strings.Fields(string(out)) {
		if strings.HasPrefix(field, "SHA256:") {
			return field
		}
	}
	t.Fatalf("no fingerprint in %q", out)
	return ""
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		// Not a git checkout: fall back to the parent of this package.
		wd, _ := os.Getwd()
		return filepath.Dir(wd)
	}
	return strings.TrimSpace(string(out))
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}
