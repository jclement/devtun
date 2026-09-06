package sshx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// The shared harness: a real in-process SSH server and a real in-process
// agent, because the failure modes this package exists to prevent — a method
// that is silently never attempted, a key offered in the wrong order, an
// algorithm the server refuses, a keepalive that never comes back — all look
// like a plain "unable to authenticate" or a hang from anywhere shallower.

// serverOptions configures the test server. The zero value is a server that
// accepts anyone and offers a fresh Ed25519 host key.
type serverOptions struct {
	// authorized is the only public key accepted; nil rejects every key, which
	// is how the full set of offered keys is made observable.
	authorized ssh.PublicKey
	// noAuth accepts the "none" method, for tests about something other than
	// authentication.
	noAuth bool
	// pubKeyAlgorithms restricts which signature algorithms are accepted — the
	// lever that makes the rsa-sha2 assertion possible, since a modern sshd
	// refuses the SHA-1 ssh-rsa algorithm outright.
	pubKeyAlgorithms []string
	// maxAuthTries is the budget a real sshd enforces, and what makes the
	// ordering of offered keys observable.
	maxAuthTries int
	// hostSigners lets a server hold several host keys of different types,
	// which is the normal state of a real sshd.
	hostSigners []ssh.Signer
	// silent authenticates and then never answers a global request. That is
	// what a black-holed connection looks like from the client: the TCP
	// session is open, the SSH session is established, and a keepalive sent
	// into it simply never comes back.
	silent bool
}

type testServer struct {
	listener net.Listener
	hostKeys []ssh.PublicKey

	// respond, when set, is what an exec session writes back to the client.
	respond func(script string) string
	// echo, when set, is the address direct-tcpip channels are forwarded to.
	echo string

	// live counts the SSH connections currently established, which is how the
	// ProxyJump test observes that Close reached the far end of the chain.
	live atomic.Int32

	mu            sync.Mutex
	scripts       []string
	commands      []string
	forwards      []string
	offered       []string
	clientVersion string
}

func startServer(t *testing.T, o serverOptions) *testServer {
	t.Helper()

	signers := o.hostSigners
	if len(signers) == 0 {
		signers = []ssh.Signer{newHostSigner(t, "ed25519")}
	}

	s := &testServer{}
	config := &ssh.ServerConfig{
		PublicKeyAuthAlgorithms: o.pubKeyAlgorithms,
		MaxAuthTries:            o.maxAuthTries,
		NoClientAuth:            o.noAuth,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			s.offered = append(s.offered, string(key.Marshal()))
			s.mu.Unlock()
			if o.authorized != nil && string(key.Marshal()) == string(o.authorized.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	for _, signer := range signers {
		config.AddHostKey(signer)
		s.hostKeys = append(s.hostKeys, signer.PublicKey())
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	s.listener = listener

	var connections sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer conn.Close()
				s.handle(t, conn, config, o.silent)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		connections.Wait()
	})
	return s
}

func (s *testServer) handle(t *testing.T, conn net.Conn, config *ssh.ServerConfig, silent bool) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer serverConn.Close()

	s.live.Add(1)
	defer s.live.Add(-1)

	s.mu.Lock()
	s.clientVersion = string(serverConn.ClientVersion())
	s.mu.Unlock()

	if silent {
		// Drain both without ever replying.
		go func() {
			for range requests {
			}
		}()
		go func() {
			for newChannel := range channels {
				_ = newChannel.Reject(ssh.Prohibited, "none")
			}
		}()
		<-t.Context().Done()
		return
	}

	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		switch newChannel.ChannelType() {
		case "session":
			go s.handleSession(newChannel)
		case "direct-tcpip":
			go s.handleDirect(newChannel)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func (s *testServer) handleSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		_ = request.Reply(true, nil)

		var payload struct{ Command string }
		_ = ssh.Unmarshal(request.Payload, &payload)

		// The client pipes the script in on stdin; read it to EOF.
		script, _ := io.ReadAll(channel)
		s.mu.Lock()
		s.scripts = append(s.scripts, string(script))
		s.commands = append(s.commands, payload.Command)
		respond := s.respond
		s.mu.Unlock()

		if respond != nil {
			_, _ = io.WriteString(channel, respond(string(script)))
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

// directTCPIP is the payload of a direct-tcpip channel open request.
type directTCPIP struct {
	DestAddr string
	DestPort uint32
	OrigAddr string
	OrigPort uint32
}

func (s *testServer) handleDirect(newChannel ssh.NewChannel) {
	var payload directTCPIP
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}

	s.mu.Lock()
	s.forwards = append(s.forwards, payload.DestAddr)
	echo := s.echo
	s.mu.Unlock()

	if echo == "" {
		_ = newChannel.Reject(ssh.ConnectionFailed, "nothing to forward to")
		return
	}
	upstream, err := net.Dial("tcp", echo)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	go func() { defer upstream.Close(); _, _ = io.Copy(upstream, channel) }()
	go func() { defer channel.Close(); _, _ = io.Copy(channel, upstream) }()
}

func (s *testServer) addr() string { return s.listener.Addr().String() }

// hostKey is the first host key the server holds, which is the one a
// single-key server is recorded by.
func (s *testServer) hostKey() ssh.PublicKey { return s.hostKeys[0] }

func (s *testServer) lastScript() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.scripts) == 0 {
		return ""
	}
	return s.scripts[len(s.scripts)-1]
}

// lastCommand is the command string of the most recent exec request, as
// opposed to whatever was piped into it.
func (s *testServer) lastCommand() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.commands) == 0 {
		return ""
	}
	return s.commands[len(s.commands)-1]
}

// bannerSeen is the client version string the last connection announced.
func (s *testServer) bannerSeen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientVersion
}

// liveConnections reports how many SSH connections are still established.
func (s *testServer) liveConnections() int { return int(s.live.Load()) }

func (s *testServer) forwardTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forwards...)
}

// offeredKeys returns the public keys presented to the server, in order.
func (s *testServer) offeredKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.offered...)
}

// dialServer resolves the server's address and connects to it, with no
// ssh_config in the way.
func dialServer(t *testing.T, s *testServer, ov Overrides, o Options) (*Client, error) {
	t.Helper()
	if ov.User == "" {
		ov.User = "tester"
	}
	d, err := Resolve(s.addr(), nil, ov)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	client, err := Dial(t.Context(), d, o)
	if client != nil {
		t.Cleanup(func() { client.Close() })
	}
	return client, err
}

// testAgent is an in-process SSH agent on a unix socket, which is exactly what
// gpg-agent, yubikey-agent and ssh-agent all present.
type testAgent struct {
	path string
	open atomic.Int32
}

func startTestAgent(t *testing.T, keys ...any) *testAgent {
	t.Helper()

	keyring := agent.NewKeyring()
	for _, key := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: key, Comment: "test key"}); err != nil {
			t.Fatalf("adding key to the test agent: %v", err)
		}
	}

	socketPath := filepath.Join(shortTempDir(t), "agent")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}

	fake := &testAgent{path: socketPath}
	var serving sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fake.open.Add(1)
			serving.Add(1)
			go func() {
				defer serving.Done()
				defer fake.open.Add(-1)
				_ = agent.ServeAgent(keyring, conn)
				conn.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		serving.Wait()
	})
	return fake
}

// openConnections reports how many agent connections are still live, which is
// how the leak test observes whether the handshake cleaned up after itself.
func (a *testAgent) openConnections() int { return int(a.open.Load()) }

// agentHolding starts an agent holding the key stored at path.
func agentHolding(t *testing.T, path string) *testAgent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return startTestAgent(t, key)
}

// generateKey makes a throwaway private key of the given kind.
func generateKey(t *testing.T, kind string) any {
	t.Helper()
	switch kind {
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating ed25519 key: %v", err)
		}
		return key
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating ecdsa key: %v", err)
		}
		return key
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating rsa key: %v", err)
		}
		return key
	default:
		t.Fatalf("unknown key kind %q", kind)
		return nil
	}
}

func signerFor(t *testing.T, key any) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}
	return signer
}

func newHostSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	return signerFor(t, generateKey(t, kind))
}

func newPublicKey(t *testing.T, kind string) ssh.PublicKey {
	t.Helper()
	return newHostSigner(t, kind).PublicKey()
}

// writeKeyPair puts a private key and its .pub beside it, returning the path
// and the public half.
func writeKeyPair(t *testing.T, dir, name string) (string, ssh.PublicKey) {
	t.Helper()
	key := generateKey(t, "ed25519")
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, marshalPrivateKey(t, key), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	public := signerFor(t, key).PublicKey()
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(public), 0o644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}
	return path, public
}

// marshalPrivateKey writes a key in the OpenSSH private key format that
// ssh.ParsePrivateKey reads.
func marshalPrivateKey(t *testing.T, key any) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// isolatedHome points HOME at a fresh directory with an empty ~/.ssh, keeping
// every test away from the developer's own keys, known_hosts and agent.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("creating .ssh: %v", err)
	}
	return home
}

// homeWithKey gives the test a HOME whose ~/.ssh holds one default identity.

// writeKnownHosts writes a known_hosts file trusting the given keys for one
// address.
func writeKnownHosts(t *testing.T, address string, keys ...ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	var lines strings.Builder
	for _, key := range keys {
		lines.WriteString(knownhosts.Line([]string{knownhosts.Normalize(address)}, key) + "\n")
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}
	return path
}

// shortTempDir returns a directory whose path is short enough for a unix
// socket: t.TempDir() embeds the test name, and macOS caps sun_path at 104.
func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "dt")
	if err != nil {
		t.Fatalf("creating temporary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// stubPrompter answers questions from a script.
type stubPrompter struct {
	confirm    bool
	confirmErr error
	secret     string
	line       string
	notices    []string
	asked      []string
}

func (p *stubPrompter) Confirm(q string) (bool, error) {
	p.asked = append(p.asked, q)
	return p.confirm, p.confirmErr
}

func (p *stubPrompter) Secret(q string) (string, error) {
	p.asked = append(p.asked, q)
	return p.secret, nil
}

func (p *stubPrompter) Line(q string) (string, error) {
	p.asked = append(p.asked, q)
	return p.line, nil
}

func (p *stubPrompter) Notice(m string) { p.notices = append(p.notices, m) }
