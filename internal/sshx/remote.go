// Operations performed on the far end of the connection: running shell
// scripts, forwarding TCP, opening the reverse-forwarded unix socket, pushing a
// binary across, and noticing when the link has died.
//
// The reverse forward is the mechanism the socket-based features are built on.
// ListenSocket asks sshd to create a unix socket on the remote box and hand
// every connection back down this SSH connection, exactly as agent forwarding
// does for SSH_AUTH_SOCK. Nothing listens on a port, nothing runs as a daemon
// over there, and the socket dies with the connection.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Run pipes a script into the remote `sh -s` and streams its stdout. It returns
// when the command exits or ctx is done.
func (c *Client) Run(ctx context.Context, script string, w io.Writer) error {
	session, err := c.ssh.NewSession()
	if err != nil {
		return fmt.Errorf("opening remote session: %w", err)
	}
	defer func() { _ = session.Close() }()

	session.Stdin = strings.NewReader(script)
	session.Stdout = w
	var stderr bytes.Buffer
	session.Stderr = &stderr

	// `sh -s` is chosen over embedding the script in the command string so that
	// quoting is never routed through the remote login shell, which may be
	// fish, csh or something stranger.
	if err := session.Start("sh -s"); err != nil {
		return fmt.Errorf("starting remote shell: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		<-done
		return ctx.Err()
	case err := <-done:
		if err != nil {
			if message := strings.TrimSpace(stderr.String()); message != "" {
				return fmt.Errorf("remote command failed: %w (%s)", err, message)
			}
			return fmt.Errorf("remote command failed: %w", err)
		}
		return nil
	}
}

// Output runs a short-lived script and returns its stdout.
func (c *Client) Output(ctx context.Context, script string) (string, error) {
	var buffer bytes.Buffer
	err := c.Run(ctx, script, &buffer)
	return buffer.String(), err
}

// DialTCP opens a connection *from* the remote host to address, which is what
// every forwarded tunnel is made of.
func (c *Client) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	conn, err := c.ssh.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("opening a connection to %s from %s: %w", address, c.dest.Label(), err)
	}
	return conn, nil
}

// ListenSocket prepares the remote path and starts the reverse forward.
//
// x/crypto/ssh has no equivalent of OpenSSH's StreamLocalBindUnlink, so a
// socket left behind by a previous run would make the bind fail, and removing
// it first is what makes a second run work at all.
//
// But a socket somebody is *answering* on is a different thing from one left
// behind, and taking that one over is how two sessions quietly break each
// other: the newcomer binds the path, and the session that had it keeps
// running — still reporting itself connected, its services still ready —
// while sshd routes nothing to it ever again. Nothing on either side says so.
// The first session is simply dead and does not know.
//
// So a live socket is refused rather than displaced. ErrSocketInUse is what
// the caller turns into an explanation, and takeOver is the escape hatch for
// the case that makes refusal dangerous: a session on a laptop that has been
// closed still holds the socket until sshd reaps it, and without a way through
// you could not reconnect to your own box.
func (c *Client) ListenSocket(ctx context.Context, socketPath string, takeOver bool) (net.Listener, error) {
	if !takeOver {
		// A probe that could not answer is not permission to take the socket.
		// Reading an error as "nobody is there" is exactly how the first
		// version of this let the takeover through on a box with no nc.
		switch inUse, err := c.socketInUse(ctx, socketPath); {
		case err != nil:
			return nil, fmt.Errorf("%w: cannot tell whether %s is in use: %w",
				ErrSocketUnknown, socketPath, err)
		case inUse:
			return nil, fmt.Errorf("%w: %s", ErrSocketInUse, socketPath)
		}
	}

	directory := path.Dir(socketPath)
	prepare := fmt.Sprintf("mkdir -p %s && chmod 700 %s && rm -f %s",
		shellQuote(directory), shellQuote(directory), shellQuote(socketPath))
	if _, err := c.Output(ctx, prepare); err != nil {
		return nil, fmt.Errorf("preparing %s on the remote host: %w", socketPath, err)
	}

	listener, err := c.ssh.ListenUnix(socketPath)
	if err != nil {
		// Both settings gate this: OpenSSH refuses remote forwards of any kind
		// when AllowTcpForwarding is off, which is easy to miss because no TCP
		// is involved here.
		return nil, fmt.Errorf(
			"sshd refused to forward %s: %w\nCheck AllowStreamLocalForwarding and AllowTcpForwarding in the server's sshd_config",
			socketPath, err)
	}

	// The containing directory is already 0700, so this is belt and braces
	// rather than the primary defence.
	if _, err := c.Output(ctx, fmt.Sprintf("chmod 600 %s", shellQuote(socketPath))); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restricting permissions on %s: %w", socketPath, err)
	}
	return listener, nil
}

// ErrSocketInUse says another devtun already holds the remote socket.
var ErrSocketInUse = errors.New("another devtun session is already attached to this host")

// ErrSocketUnknown says the box could not be asked. It is separate from
// ErrSocketInUse because the two need different advice: one means quit the
// other session, the other means devtun cannot check and you decide.
var ErrSocketUnknown = errors.New("cannot check whether another devtun is attached")

// socketInUse reports whether something is answering on the socket.
//
// A connect attempt is the only thing that separates a live socket from a file
// left behind by a session that died — and the distinction decides between
// refusing to start and clearing up after a crash, which are opposite actions.
// A box with neither nc nor socat cannot answer the question, and says so with
// an error rather than a false negative: guessing "nobody is there" would put
// the takeover back.
func (c *Client) socketInUse(ctx context.Context, socketPath string) (bool, error) {
	out, err := c.Output(ctx, socketInUseScript(socketPath))
	if err != nil {
		return false, err
	}
	return readSocketInUse(out)
}

// socketInUseScript asks the remote shell the question. Split out so the shell
// itself can be tested, which is where a mistake would actually live.
//
// /proc/net/unix first, and it is the answer rather than a nicety: it is a file
// the kernel maintains, present on every Linux box, needing no tool at all. The
// first version of this asked nc and then socat, and the devtun test container
// has neither — so the probe could not answer, the caller read "cannot tell" as
// "go ahead", and the takeover this exists to prevent happened anyway. Plenty
// of real dev boxes are that bare.
//
// A listening socket appears there as a named entry whose last field is the
// path; a file left behind by a dead process has no entry at all, because the
// inode is gone. awk compares the last field literally, so a path with regex
// characters in it cannot be mismatched.
//
// nc and socat stay as the fallback for a remote that is not Linux. devtun's
// remote is always Linux today, and that is a statement about today.
func socketInUseScript(socketPath string) string {
	quoted := shellQuote(socketPath)
	return fmt.Sprintf(`if [ ! -S %s ]; then echo free
elif [ -r /proc/net/unix ]; then
  awk -v p=%s '$NF==p{f=1} END{exit !f}' /proc/net/unix && echo busy || echo free
elif command -v nc >/dev/null 2>&1; then
  nc -z -U %s >/dev/null 2>&1 && echo busy || echo free
elif command -v socat >/dev/null 2>&1; then
  socat -u OPEN:/dev/null UNIX-CONNECT:%s >/dev/null 2>&1 && echo busy || echo free
else echo unknown
fi`, quoted, quoted, quoted, quoted)
}

// readSocketInUse interprets the script's answer.
func readSocketInUse(out string) (bool, error) {
	switch strings.TrimSpace(out) {
	case "busy":
		return true, nil
	case "free":
		return false, nil
	default:
		return false, errors.New("cannot tell whether the socket is in use (no nc or socat)")
	}
}

// RemoveSocket cleans up on shutdown, and only if the socket is still ours.
//
// It used to be an unconditional `rm -f`, and that is a foot-gun the moment two
// devtun sessions point at the same box: the second takes the path over — which
// ListenSocket does deliberately — and then the *first* one's shutdown deletes
// the second's socket. The survivor is left running, believing it is serving,
// while every `op` on the remote says there is no session at all.
//
// So the check is "is anything listening here now?". If something is, it is not
// us — our listener closed a moment ago — and the file belongs to whoever took
// over. Leaving a stale socket behind costs nothing: ListenSocket removes one
// on the way in, and a shim that finds a socket with nobody behind it reports a
// refused connection, which is a truer description of "devtun was here and is
// not running now" than a missing file.
//
// Failures are not worth reporting: the socket is unusable the moment the SSH
// connection drops either way.
func (c *Client) RemoveSocket(ctx context.Context, socketPath string) {
	_, _ = c.Output(ctx, removeIfUnusedScript(socketPath))
}

// removeIfUnusedScript deletes the socket unless somebody is listening on it.
//
// The test is a connect attempt, because that is the only thing that
// distinguishes a socket with a live peer from an abandoned file, and it is
// done with whichever of these the box has rather than requiring any of them.
// A box with none of them keeps its stale socket, which is the safe way to be
// wrong: a socket nobody removed is a confusing error, a socket removed out
// from under a live session is a broken one.
func removeIfUnusedScript(socketPath string) string {
	quoted := shellQuote(socketPath)
	return fmt.Sprintf(`if [ -S %s ]; then
  if command -v nc >/dev/null 2>&1; then
    nc -z -U %s >/dev/null 2>&1 || rm -f %s
  elif command -v socat >/dev/null 2>&1; then
    socat -u OPEN:/dev/null UNIX-CONNECT:%s >/dev/null 2>&1 || rm -f %s
  fi
fi`, quoted, quoted, quoted, quoted, quoted)
}

// Upload writes a local file to the remote host with the given mode. It writes
// to a temporary name and renames, so an interrupted upload can never leave a
// half-written executable where a working one is expected.
func (c *Client) Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", localPath, err)
	}
	defer func() { _ = file.Close() }()

	session, err := c.ssh.NewSession()
	if err != nil {
		return fmt.Errorf("opening remote session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// The payload is on stdin, so the script cannot be piped in the way Run
	// does it; this one is spelled out in the command instead.
	temporary := remotePath + ".upload"
	command := fmt.Sprintf("mkdir -p %s && cat > %s && chmod %o %s && mv %s %s",
		shellQuote(path.Dir(remotePath)),
		shellQuote(temporary), mode.Perm(), shellQuote(temporary),
		shellQuote(temporary), shellQuote(remotePath))

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("opening remote stdin: %w", err)
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr

	if err := session.Start(command); err != nil {
		return fmt.Errorf("starting remote write: %w", err)
	}
	if _, err := io.Copy(stdin, file); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("sending %s: %w", localPath, err)
	}
	_ = stdin.Close()

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("writing %s on the remote host: %w (%s)", remotePath, err, strings.TrimSpace(stderr.String()))
		}
		return nil
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return ctx.Err()
	}
}

// KeepAlive pings the server on an interval and returns when a ping fails, goes
// unanswered, or the context is cancelled. A dropped connection otherwise shows
// up only when somebody tries to use a tunnel, which is the worst possible
// moment to discover it.
//
// The timeout is the load-bearing part. A connection that is *black-holed*
// rather than reset — a laptop lid closing, wifi vanishing, a NAT that forgot —
// leaves the TCP session open as far as both ends are concerned, and a
// keepalive sent into it simply never gets an answer. Without a deadline this
// loop would block in SendRequest forever, so nothing would ever return, so the
// caller's reconnect loop would never run: devtun would sit there looking
// healthy and dead.
func (c *Client) KeepAlive(ctx context.Context, interval, timeout time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.ping(ctx, timeout); err != nil {
				return fmt.Errorf("connection to %s lost: %w", c.dest.Label(), err)
			}
		}
	}
}

// ping sends one keepalive and waits at most timeout for the reply.
//
// x/crypto/ssh has no deadline on SendRequest, so the call is made from a
// goroutine. It can outlive this function — on a black-holed connection it will
// — but only until the connection is closed, which the caller does as soon as
// KeepAlive returns. The channel is buffered so the goroutine never blocks on a
// send nobody is waiting for.
func (c *Client) ping(ctx context.Context, timeout time.Duration) error {
	answered := make(chan error, 1)
	go func() {
		_, _, err := c.ssh.SendRequest("keepalive@openssh.com", true, nil)
		answered <- err
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-answered:
		return err
	case <-timer.C:
		return fmt.Errorf("no reply to a keepalive within %s", timeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// shellQuote wraps a value in single quotes for the remote shell.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
