package shim

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jclement/devtun/internal/service"
)

const (
	dialTimeout = 10 * time.Second
	// WaitForSession is how long a shim keeps trying before giving up.
	//
	// The socket does not exist while the session is re-establishing its SSH
	// connection, so a first dial failure is not evidence that nothing is
	// listening — it is the most likely thing to see during an ordinary
	// network blip. Waiting means a script rides over a reconnect instead of
	// failing on it, while a session that was never started still reports
	// promptly.
	WaitForSession    = 15 * time.Second
	dialRetryInterval = 250 * time.Millisecond
)

// Client is the remote half: it dials the control socket and announces which
// service it wants.
type Client struct {
	SocketPath string
	Version    string
	// Wait is how long to keep retrying a refused dial. Zero means one
	// attempt, which is what tests want.
	Wait time.Duration
	// Notify receives the one-line "waiting for devtun" notice, normally the
	// shim's stderr.
	Notify io.Writer
}

// NewClient builds a client. An empty socketPath is discovered from the
// environment and the path conventions.
func NewClient(socketPath, version string) (*Client, error) {
	if socketPath == "" {
		socketPath = DiscoverSocket()
	}
	if socketPath == "" {
		return nil, fmt.Errorf("cannot find the devtun socket: set %s, or start `devtun` on your workstation", SocketEnv)
	}
	return &Client{SocketPath: socketPath, Version: version, Wait: WaitForSession}, nil
}

// Open dials the socket and sends the Hello for the named service. The caller
// owns the returned connection and must close it.
func (c *Client) Open(ctx context.Context, svc string) (net.Conn, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	hello := Hello{V: Version, Service: svc, Caller: DescribeCaller(c.Version)}
	if err := WriteFrame(conn, hello); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("greeting devtun: %w", err)
	}
	return conn, nil
}

// dial connects, retrying a refused connection for up to Wait.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	deadline := time.Now().Add(c.Wait)
	dialer := net.Dialer{Timeout: dialTimeout}
	announced := false

	for {
		conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
		if err == nil {
			if announced {
				c.notify("devtun: session is back")
			}
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("no devtun session on %s: %w", c.SocketPath, err)
		}
		if !announced {
			c.notify(fmt.Sprintf("devtun: waiting up to %s for the session…", c.Wait))
			announced = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(dialRetryInterval):
		}
	}
}

func (c *Client) notify(message string) {
	if c.Notify != nil {
		fmt.Fprintln(c.Notify, message)
	}
}

// DescribeCaller gathers what the shim can say about itself. Every field is
// self-reported and is displayed rather than trusted; see Hello.Caller.
//
// Failures are silent on purpose. A missing hostname makes an approval prompt
// slightly less informative; it must never make a secret unavailable.
func DescribeCaller(version string) service.Caller {
	caller := service.Caller{Version: version, PID: os.Getpid()}
	if u, err := user.Current(); err == nil {
		caller.User = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		caller.Host = h
	}
	if cwd, err := os.Getwd(); err == nil {
		caller.CWD = cwd
	}
	caller.Program = parentProgram()
	return caller
}

// parentProgram names the process that invoked the shim — "deploy.sh" rather
// than "op" — which is the single most useful line in an approval prompt.
// /proc is the only portable-enough place to find it, and its absence is not
// worth reporting.
func parentProgram() string {
	ppid := os.Getppid()
	if ppid <= 1 {
		return ""
	}
	for _, name := range []string{"comm", "cmdline"} {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(ppid), name))
		if err != nil || len(data) == 0 {
			continue
		}
		// cmdline is NUL-separated; comm has a trailing newline.
		for i, b := range data {
			if b == 0 || b == '\n' {
				data = data[:i]
				break
			}
		}
		if s := filepath.Base(string(data)); s != "" && s != "." {
			return s
		}
	}
	return ""
}
