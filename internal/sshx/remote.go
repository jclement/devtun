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
// socket left behind by a previous run would make the bind fail. Removing it
// first is safe: if another devtun really is live on that path, its own socket
// is gone but its SSH connection is not, and the second listener will simply
// take over new connections.
func (c *Client) ListenSocket(ctx context.Context, socketPath string) (net.Listener, error) {
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

// RemoveSocket cleans up on shutdown. Failures are not worth reporting to the
// user: the socket is unusable the moment the SSH connection drops.
func (c *Client) RemoveSocket(ctx context.Context, socketPath string) {
	_, _ = c.Output(ctx, fmt.Sprintf("rm -f %s", shellQuote(socketPath)))
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
