package sshagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// The whole suite runs against an in-process agent: a keyring served over a
// net.Pipe. There is no real ssh, no real agent socket, and no key material on
// disk — which is the only way a test of this service can be run anywhere
// without either being useless or being dangerous.

// harness is a started service with an agent behind it and a listener in front.
type harness struct {
	t        *testing.T
	svc      *Service
	host     *fakeHost
	prompter *scriptedPrompter
	ring     agent.Agent
	signer   ssh.Signer
	listener *pipeListener
}

// start builds the service, attaches it to a host with no SSH connection behind
// it, and serves its socket the way the session does — so the tests exercise
// the accept loop, the agent protocol and the decision logic together.
func start(t *testing.T, opts Options) *harness {
	t.Helper()

	ring := agent.NewKeyring()
	signer := addKey(t, ring)

	scripted, _ := opts.Prompter.(*scriptedPrompter)
	if opts.Prompter == nil {
		// Deny is the default answer, so a test that expects a signature has to
		// say so.
		scripted = &scriptedPrompter{}
		opts.Prompter = scripted
	}
	if opts.Dial == nil {
		opts.Dial = serveKeyring(t, ring)
	}

	svc := New(opts)
	host := newFakeHost("bedev")
	ctx, cancel := context.WithCancel(t.Context())
	if _, err := svc.Attach(ctx, host); err != nil {
		t.Fatalf("attaching: %v", err)
	}

	listener := newPipeListener()
	served := make(chan error, 1)
	go func() { served <- svc.ServeSocket(ctx, listener) }()

	// Every test therefore also asserts that cancellation tears the whole thing
	// down, which is the property a session reconnecting fifty times depends
	// on.
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("ServeSocket returned %v, want nil after cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("ServeSocket did not return after the context was cancelled")
		}
	})

	return &harness{t: t, svc: svc, host: host, prompter: scripted, ring: ring, signer: signer, listener: listener}
}

// client opens a forwarded agent connection, as `ssh` on the remote box would.
func (h *harness) client() agent.ExtendedAgent {
	h.t.Helper()
	conn, err := h.listener.dial()
	if err != nil {
		h.t.Fatalf("connecting to the agent socket: %v", err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return agent.NewClient(conn)
}

// gate builds a gate directly onto the local agent, for the parts of the
// interface the wire protocol has no message for — Signers, which no client can
// ask for and which must be refused all the same.
func (h *harness) gate() *gate {
	h.t.Helper()
	conn, err := h.svc.dial(h.t.Context())
	if err != nil {
		h.t.Fatalf("dialling the local agent: %v", err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return &gate{
		ctx:      h.t.Context(),
		svc:      h.svc,
		upstream: agent.NewClient(conn),
		link:     &link{host: h.host.Label(), events: h.host.events},
	}
}

// key is the public key loaded in the agent, as a client would name it.
func (h *harness) key() ssh.PublicKey { return h.signer.PublicKey() }

// addKey generates a key and loads it into the keyring.
func addKey(t *testing.T, ring agent.Agent) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if err := ring.Add(agent.AddedKey{PrivateKey: private, Comment: "devtun test key"}); err != nil {
		t.Fatalf("loading the key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("building a signer: %v", err)
	}
	return signer
}

// newHostKey returns a key standing in for a destination's host key.
func newHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("building a host signer: %v", err)
	}
	return signer
}

// serveKeyring answers dials with an in-process agent, and waits for those
// goroutines at the end of the test so a leaked connection is a failure rather
// than a mystery.
func serveKeyring(t *testing.T, ring agent.Agent) func(context.Context) (net.Conn, error) {
	var serving sync.WaitGroup
	t.Cleanup(serving.Wait)
	return func(context.Context) (net.Conn, error) {
		mine, theirs := net.Pipe()
		serving.Add(1)
		go func() {
			defer serving.Done()
			defer func() { _ = theirs.Close() }()
			_ = agent.ServeAgent(ring, theirs)
		}()
		return mine, nil
	}
}

// bindTo builds a session-bind@openssh.com payload the way OpenSSH does: the
// destination's host key, a session identifier, and that host key's signature
// over the identifier.
func bindTo(t *testing.T, hostKey ssh.Signer, forwarding bool) []byte {
	t.Helper()
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatalf("making a session id: %v", err)
	}
	signature, err := hostKey.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatalf("signing the session id: %v", err)
	}
	return ssh.Marshal(sessionBind{
		HostKey:      hostKey.PublicKey().Marshal(),
		SessionID:    sessionID,
		Signature:    ssh.Marshal(signature),
		IsForwarding: forwarding,
	})
}

// forgedBind claims one host key while signing with another, which is what a
// process trying to spend somebody else's grant would have to do.
func forgedBind(t *testing.T, claimed ssh.PublicKey, actual ssh.Signer) []byte {
	t.Helper()
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatalf("making a session id: %v", err)
	}
	signature, err := actual.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatalf("signing the session id: %v", err)
	}
	return ssh.Marshal(sessionBind{
		HostKey:   claimed.Marshal(),
		SessionID: sessionID,
		Signature: ssh.Marshal(signature),
	})
}

// writeKnownHosts writes a known_hosts file naming each host key, and returns
// its path.
func writeKnownHosts(t *testing.T, entries map[string]ssh.PublicKey) string {
	t.Helper()
	var body []byte
	for name, key := range entries {
		body = append(body, []byte(name+" "+string(ssh.MarshalAuthorizedKey(key)))...)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}
	return path
}

// pipeListener hands out in-process connections, so the accept loop is
// exercised without a filesystem socket — which on macOS would also be a fight
// with the 104-character path limit.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// dial is the client half: it blocks until the accept loop takes the
// connection, so a test that connects has proved the loop is running.
func (l *pipeListener) dial() (net.Conn, error) {
	mine, theirs := net.Pipe()
	select {
	case l.conns <- theirs:
		return mine, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// scriptedPrompter answers with a fixed choice and records what it was asked,
// which is how the tests check both that grants suppress prompting and that the
// human is shown the right subject.
type scriptedPrompter struct {
	mu       sync.Mutex
	choice   prompt.Choice
	err      error
	delay    time.Duration
	asked    int
	requests []prompt.Request
}

// Ask deliberately ignores the context: a Prompter is supposed to abandon its
// question when the deadline fires, and the point of the timeout test is that
// devtun does not depend on it having done so.
func (s *scriptedPrompter) Ask(_ context.Context, request prompt.Request) (prompt.Choice, error) {
	s.mu.Lock()
	s.asked++
	s.requests = append(s.requests, request)
	choice, err, delay := s.choice, s.err, s.delay
	s.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	return choice, err
}

func (s *scriptedPrompter) answer(choice prompt.Choice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.choice = choice
}

func (s *scriptedPrompter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

// subjects returns what the human was asked about, in order.
func (s *scriptedPrompter) subjects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.requests))
	for i, request := range s.requests {
		out[i] = request.Subject
	}
	return out
}

func (s *scriptedPrompter) lastSubject(t *testing.T) string {
	t.Helper()
	subjects := s.subjects()
	if len(subjects) == 0 {
		t.Fatal("nobody was asked to approve anything")
	}
	return subjects[len(subjects)-1]
}

// fakeHost is a host with no SSH connection behind it. Everything the
// authorisation pipeline uses — the label decisions are keyed to, the event
// sink, the config document — is real; everything that would touch a network
// refuses, so a test that starts using one fails loudly rather than hanging.
type fakeHost struct {
	label  string
	events *recorder
	config *fakeConfig
}

func newFakeHost(label string) *fakeHost {
	return &fakeHost{label: label, events: &recorder{}, config: newFakeConfig()}
}

func (h *fakeHost) Label() string { return h.label }
func (h *fakeHost) Facts() service.Facts {
	return service.Facts{User: "jsc", Hostname: h.label, OS: "linux"}
}
func (h *fakeHost) Events() event.Sink     { return h.events }
func (h *fakeHost) Config() service.Config { return h.config }

func (h *fakeHost) Run(context.Context, string, io.Writer) error { return errNoRemote }
func (h *fakeHost) Output(context.Context, string) (string, error) {
	return "", errNoRemote
}
func (h *fakeHost) Upload(context.Context, string, string, os.FileMode) error { return errNoRemote }
func (h *fakeHost) DialTCP(context.Context, string) (net.Conn, error)         { return nil, errNoRemote }
func (h *fakeHost) ShimPath() string                                          { return "/home/jsc/.devtun/bin/devtun-shim" }
func (h *fakeHost) SocketPath() string                                        { return "/run/user/1000/devtun.sock" }

// errNoRemote is what the fake host answers with. This service needs nothing
// from the remote box but a socket, so reaching for it in a test is the bug.
var errNoRemote = errors.New("the SSH agent service should not need anything from the remote box")

// fakeConfig is the service's slice of the host config file, kept as marshalled
// documents so a round trip through YAML is exercised the way the real one is.
type fakeConfig struct {
	mu   sync.Mutex
	docs map[string][]byte
}

func newFakeConfig() *fakeConfig { return &fakeConfig{docs: make(map[string][]byte)} }

// GetLocal behaves as Get here: these fakes hold no shared layer for a local
// read to differ from.
func (c *fakeConfig) GetLocal(key string, v any) (bool, error) { return c.Get(key, v) }

func (c *fakeConfig) Get(key string, v any) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, ok := c.docs[key]
	if !ok {
		return false, nil
	}
	return true, yaml.Unmarshal(data, v)
}

func (c *fakeConfig) Set(key string, v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	c.docs[key] = data
	return nil
}

// recorder keeps every event, because what was reported about a decision is
// part of the decision: the security record is the point.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Emit(e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) all() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event.Event, len(r.events))
	copy(out, r.events)
	return out
}

// kinds returns the Kind of every event, in order.
func (r *recorder) kinds() []string {
	out := []string{}
	for _, e := range r.all() {
		out = append(out, e.Kind)
	}
	return out
}

// count reports how many events of a kind were recorded.
func (r *recorder) count(kind string) int {
	n := 0
	for _, e := range r.all() {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// find returns the first event of a kind.
func (r *recorder) find(t *testing.T, kind string) event.Event {
	t.Helper()
	for _, e := range r.all() {
		if e.Kind == kind {
			return e
		}
	}
	t.Fatalf("no %q event; got %v", kind, r.kinds())
	return event.Event{}
}
