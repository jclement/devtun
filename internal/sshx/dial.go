// Establishing the SSH connection, including any ProxyJump chain.
//
// Each hop is a full SSH connection whose transport is a channel on the
// previous one, which is what `ssh -J` does. They are tracked so Close can tear
// the chain down from the far end back, rather than leaking jump connections
// every time devtun reconnects.
package sshx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jclement/devtun/internal/buildinfo"
)

// DefaultConnectTimeout bounds the TCP connect and SSH handshake for one hop.
const DefaultConnectTimeout = 30 * time.Second

// tokenHintDelay is how long a handshake may take before we explain the wait.
// Anything shorter fires on every ordinary connection; anything longer and the
// user has already decided the tool has hung. It only applies when the agent
// actually offered keys, which is when a PIN prompt or a touch is plausible.
const tokenHintDelay = 2 * time.Second

// Backoff for Options.Wait. It starts short because the common case is a box
// that is thirty seconds from finishing its boot, and caps well below the
// patience of anyone watching.
const (
	waitBackoffStart = 1 * time.Second
	waitBackoffMax   = 30 * time.Second
)

// Options configures Dial.
type Options struct {
	// Prompter answers for passphrases, passwords and unknown host keys. Nil
	// is an unattended run: anything needing an answer fails instead.
	Prompter Prompter
	// Config resolves ProxyJump hops against ssh_config.
	Config *Config
	// AuthSock overrides which SSH agent to use. Empty means ssh_config's
	// IdentityAgent, then SSH_AUTH_SOCK, then the platform default.
	AuthSock string
	// KnownHostsFiles defaults to the user's own.
	KnownHostsFiles []string
	// HostKeyMode overrides the destination's StrictHostKeyChecking. Empty
	// means take it from ssh_config, which defaults to asking.
	HostKeyMode HostKeyMode
	// ConnectTimeout bounds each hop.
	ConnectTimeout time.Duration
	// ClientVersion is advertised in the SSH banner. Defaults to this build.
	ClientVersion string
	// Wait keeps retrying, with backoff, until the connection succeeds or ctx
	// is done — for a dev box that is still booting. Without it the first
	// failure is returned.
	Wait bool
}

// Client is a live SSH connection plus the jump hosts it was reached through.
type Client struct {
	ssh  *ssh.Client
	dest *Destination

	jumps     []*ssh.Client
	closeOnce sync.Once
}

// Dial connects to the destination, following any ProxyJump chain.
func Dial(ctx context.Context, d *Destination, o Options) (*Client, error) {
	backoff := waitBackoffStart
	for attempt := 1; ; attempt++ {
		client, err := dialChain(ctx, d, o)
		if err == nil {
			return client, nil
		}
		if !o.Wait || ctx.Err() != nil {
			return nil, err
		}
		notify(o.Prompter, fmt.Sprintf("%v; retrying in %s (attempt %d)", err, backoff, attempt))
		if !sleepContext(ctx, backoff) {
			return nil, ctx.Err()
		}
		if backoff *= 2; backoff > waitBackoffMax {
			backoff = waitBackoffMax
		}
	}
}

// dialChain is one whole attempt: every jump host, then the destination.
func dialChain(ctx context.Context, d *Destination, o Options) (*Client, error) {
	mode := o.HostKeyMode
	if mode == "" {
		mode = ParseHostKeyMode(d.StrictHostKey)
	}
	knownHosts := o.KnownHostsFiles
	if len(knownHosts) == 0 && mode != HostKeyNone {
		var err error
		if knownHosts, err = DefaultKnownHostsFiles(); err != nil {
			return nil, err
		}
	}
	verifier, err := HostKeyPolicy{Mode: mode, Files: knownHosts, Prompter: o.Prompter}.Verifier()
	if err != nil {
		return nil, err
	}

	var jumps []*ssh.Client
	var through *ssh.Client
	for _, hop := range parseJumpChain(d.ProxyJump) {
		jumpDestination, err := Resolve(hop, o.Config, Overrides{})
		if err != nil {
			closeAll(jumps)
			return nil, fmt.Errorf("resolving jump host %q: %w", hop, err)
		}
		client, err := dialHop(ctx, jumpDestination, through, verifier, o)
		if err != nil {
			closeAll(jumps)
			return nil, fmt.Errorf("connecting to jump host %s: %w", jumpDestination.Label(), err)
		}
		jumps = append(jumps, client)
		through = client
	}

	client, err := dialHop(ctx, d, through, verifier, o)
	if err != nil {
		closeAll(jumps)
		return nil, fmt.Errorf("connecting to %s: %w", d.Label(), err)
	}
	return &Client{ssh: client, dest: d, jumps: jumps}, nil
}

// dialHop opens one SSH connection, either directly or tunnelled through an
// earlier hop.
func dialHop(ctx context.Context, d *Destination, through *ssh.Client, verifier *HostKeyVerifier, o Options) (*ssh.Client, error) {
	timeout := o.ConnectTimeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var conn net.Conn
	var err error
	if through == nil {
		dialer := net.Dialer{Timeout: timeout}
		conn, err = dialer.DialContext(ctx, "tcp", d.Addr())
	} else {
		conn, err = through.DialContext(ctx, "tcp", d.Addr())
	}
	if err != nil {
		return nil, fmt.Errorf("dialling %s: %w", d.Addr(), err)
	}

	// ssh.NewClientConn has no context, so the deadline is enforced on the
	// socket instead; it is cleared once the handshake is done because the
	// connection then has to stay open indefinitely.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// The authenticator holds the agent connection open for the handshake and
	// no longer: signers are never used again once authentication is done, and
	// a session that reconnects on every network hiccup would otherwise leak a
	// descriptor per attempt.
	auth := newAuthenticator(d, o)
	defer func() { _ = auth.Close() }()

	clientVersion := o.ClientVersion
	if clientVersion == "" {
		clientVersion = buildinfo.UserAgent()
	}

	config := &ssh.ClientConfig{
		User:            d.User,
		Auth:            auth.methods(),
		HostKeyCallback: verifier.Check,
		// Prefer the host key types known_hosts already records for this host,
		// the way OpenSSH does. Without it the server may offer a perfectly
		// valid key of a type this host has never been seen using, and the
		// check would report it as a changed key.
		HostKeyAlgorithms: verifier.AlgorithmsFor(d.Addr()),
		Timeout:           timeout,
		ClientVersion:     clientVersion,
	}

	// A smartcard or FIDO key blocks here until its PIN is entered or the token
	// is touched, with nothing on screen to say so.
	hint := time.AfterFunc(tokenHintDelay, func() {
		if auth.usesAgent() {
			notify(o.Prompter, "waiting for the SSH agent — enter your PIN, or touch your security key if it is blinking")
		}
	})
	connection, channels, requests, err := ssh.NewClientConn(conn, d.Addr(), config)
	hint.Stop()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w%s", err, authHint(err, d, auth.offeredCredentials()))
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(connection, channels, requests), nil
}

// Dest returns the resolved destination this client is connected to.
func (c *Client) Dest() *Destination { return c.dest }

// Close shuts the connection and every jump behind it, far end first.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.ssh.Close()
		closeAll(c.jumps)
	})
	return err
}

// parseJumpChain splits a ProxyJump value, which may name several hops
// separated by commas, into hops nearest first. The literal "none" disables
// jumping, as in ssh_config, and is already stripped by Resolve.
func parseJumpChain(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") {
		return nil
	}
	var hops []string
	for _, hop := range strings.Split(value, ",") {
		if hop = strings.TrimSpace(hop); hop != "" {
			hops = append(hops, hop)
		}
	}
	return hops
}

// sleepContext waits for d, reporting false if the context ended first.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func closeAll(clients []*ssh.Client) {
	for i := len(clients) - 1; i >= 0; i-- {
		_ = clients[i].Close()
	}
}
