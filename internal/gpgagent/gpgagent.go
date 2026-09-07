// Package gpgagent forwards the workstation's gpg-agent to a remote box, so a
// commit signed there is signed by the key on your laptop.
//
// `git commit -S` and `gpg --decrypt` on a dev box need a private key. The
// choices without this are to copy the key there — which is the thing a
// hardware token exists to make impossible — or to not sign, which is the
// choice most people quietly make. GnuPG's own answer is its *extra socket*, a
// deliberately restricted variant of the agent socket meant to be forwarded to
// somewhere less trusted, and this service is that arrangement with the SSH
// connection devtun already has.
//
// # Why this one does not prompt
//
// Every other gated service in devtun asks a human because nothing else would.
// gpg-agent already does: a signature that is not cached raises pinentry on
// your machine, showing what is being signed, and the passphrase or the touch
// on a YubiKey *is* the approval. A second prompt in front of it would ask the
// same question twice and teach people to click through both.
//
// So devtun's job here is transport and accounting: forward the socket, and put
// a line in the security log for every connection the box makes to your agent,
// so "what has that machine been doing with my key" has an answer. The dial is
// the service itself — off for a host you do not want signing as you.
//
// # What the remote needs
//
// gpg finds its agent at a path it computes; it cannot be told to use a socket
// elsewhere by an environment variable. So devtun gives the remote a GNUPGHOME
// of its own under ~/.devtun/gnupg, links the forwarded socket in as
// S.gpg-agent, and imports your public keys there — gpg needs the public half
// present to know what it is signing with, and the public half is public.
//
// A GNUPGHOME of devtun's own rather than the user's is deliberate: it means
// devtun never writes into a directory somebody else's keys live in, and
// unsetting one variable puts the box back exactly as it was.
package gpgagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

var (
	_ service.Service       = (*Service)(nil)
	_ service.SocketService = (*Service)(nil)
	_ service.Advisor       = (*Service)(nil)
	_ service.Instance      = (*instance)(nil)
)

const (
	// socketName is what the forwarded socket is called beside the control
	// socket. The link gpg actually opens is made in the remote GNUPGHOME.
	socketName = "devtun-gpg.sock"
	// homeDir is the GNUPGHOME devtun manages on the remote, under ~/.devtun.
	homeDir = "gnupg"
	// keyFile is where the exported public keys are put before importing.
	keyFile = "devtun-pubkeys.asc"
	// dialTimeout bounds reaching the local agent.
	dialTimeout = 5 * time.Second
	// setupTimeout bounds preparing the remote GNUPGHOME. It is generous:
	// importing keys runs gpg on the far side.
	setupTimeout = 30 * time.Second
)

// Options is everything the caller decides.
type Options struct {
	// Socket is the local gpg-agent socket to forward. Empty means ask gpgconf
	// for the extra socket, which is the one meant to be forwarded.
	Socket string
	// GPG is the gpg binary used to export public keys. Empty means "gpg".
	GPG string
	// Conf is the gpgconf binary used to locate the socket. Empty means
	// "gpgconf".
	Conf string
	// Dial replaces the connection to the local agent, for tests.
	Dial func(ctx context.Context) (net.Conn, error)
	// Export replaces reading the local public keys, for tests.
	Export func(ctx context.Context) ([]byte, error)
}

// Service is the gpg-agent bridge.
type Service struct {
	opts Options

	mu       sync.Mutex
	host     service.Host
	socket   string // the local socket, resolved once
	prepared bool   // the remote GNUPGHOME is in place
}

// New returns a service. It touches nothing until Probe.
func New(opts Options) *Service { return &Service{opts: opts} }

// Meta identifies the service.
func (s *Service) Meta() service.Meta {
	return service.Meta{
		ID:    "gpg-agent",
		Title: "GPG Agent",
		Glyph: "✎",
		Class: event.Security,
		Short: "sign and decrypt on the remote box with the key on this one",
		// Off until asked for. This is the one service that changes how other
		// tools on the box behave — GNUPGHOME is obeyed by every gpg there —
		// and that should be a decision somebody made.
		OptIn: true,
	}
}

// Probe reports whether the bridge can work.
//
// Both ends have to be right and they fail differently: no agent here means
// there is nothing to forward, and no gpg there means nothing would ever use
// it. Saying which is which is the whole value of a probe.
func (s *Service) Probe(ctx context.Context, h service.Host) service.Support {
	socket, err := s.localSocket(ctx)
	if err != nil {
		return service.Unsupported(err.Error())
	}
	conn, err := s.dial(ctx, socket)
	if err != nil {
		return service.Unsupported("nothing is listening on " + socket +
			" — is gpg-agent running with an extra socket?")
	}
	_ = conn.Close()

	if !h.Facts().Has("gpg") {
		return service.Unsupported("no gpg on " + h.Label() + ", so a forwarded agent would have no user")
	}
	return service.Support{OK: true, Detail: "forwarding " + socket}
}

// localSocket resolves which socket to forward, once.
//
// The *extra* socket is the right one and not merely the convenient one: it is
// gpg-agent's restricted variant, which refuses the commands that manage keys
// rather than use them. Forwarding the ordinary socket would hand a box the
// ability to delete the key it is asking to sign with.
func (s *Service) localSocket(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.socket != "" {
		defer s.mu.Unlock()
		return s.socket, nil
	}
	s.mu.Unlock()

	socket := s.opts.Socket
	if socket == "" {
		out, err := s.run(ctx, s.conf(), "--list-dirs", "agent-extra-socket")
		if err != nil {
			return "", errors.New("no gpg-agent on this machine (gpgconf would not answer)")
		}
		socket = strings.TrimSpace(out)
	}
	if socket == "" {
		return "", errors.New("gpg-agent has no extra socket to forward")
	}
	if _, err := os.Stat(socket); err != nil {
		return "", fmt.Errorf("gpg-agent's extra socket is not there (%s)", socket)
	}

	s.mu.Lock()
	s.socket = socket
	s.mu.Unlock()
	return socket, nil
}

// Attach binds the service to a connection and prepares the remote GNUPGHOME.
//
// The preparation is idempotent and runs once per process rather than once per
// connection: a reconnect should not re-import keys, and the directory it makes
// survives one anyway.
func (s *Service) Attach(ctx context.Context, h service.Host) (service.Instance, error) {
	s.mu.Lock()
	s.host = h
	prepared := s.prepared
	s.mu.Unlock()

	if !prepared {
		if err := s.prepareRemote(ctx, h); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.prepared = true
		s.mu.Unlock()
	}
	return &instance{}, nil
}

// SocketName is the file name for this service's socket.
func (s *Service) SocketName() string { return socketName }

// SetupLines is the one line the remote shell needs.
func (s *Service) SetupLines(h service.Host) []string {
	return []string{fmt.Sprintf("export GNUPGHOME=%q", remoteHome(h))}
}

// remoteHome is the GNUPGHOME devtun manages on the remote box.
func remoteHome(h service.Host) string { return path.Join(path.Dir(h.ShimPath()), homeDir) }

// prepareRemote makes the GNUPGHOME, links the socket in, and imports the
// public keys.
//
// The link rather than binding the socket there directly: the session publishes
// every service socket beside the control socket, and a GNUPGHOME containing
// devtun's own binary and control socket would be a directory gpg feels free to
// write its own files into. gpg follows the link without noticing.
func (s *Service) prepareRemote(ctx context.Context, h service.Host) error {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()

	home := remoteHome(h)
	socket := path.Join(path.Dir(h.SocketPath()), socketName)

	// 0700 because gpg refuses a homedir anyone else can read, and says so in
	// a warning people then ignore.
	script := fmt.Sprintf("mkdir -p %s && chmod 700 %s && ln -sfn %s %s",
		quote(home), quote(home), quote(socket), quote(path.Join(home, "S.gpg-agent")))
	if _, err := h.Output(ctx, script); err != nil {
		return fmt.Errorf("preparing %s on %s: %w", home, h.Label(), err)
	}

	keys, err := s.export(ctx)
	if err != nil {
		// Not fatal. The socket still works, and somebody who keeps their
		// public keys on the box already is entitled to have devtun not
		// interfere with them.
		h.Events().Emit(event.Event{
			Kind: "keys-skipped", Class: event.Diagnostic, Level: event.Warn,
			Text: "could not export your public keys: " + err.Error(),
		})
		return nil
	}
	if len(keys) == 0 {
		return nil
	}
	return s.importKeys(ctx, h, home, keys)
}

// importKeys uploads the exported public keys and imports them remotely.
//
// Public keys only, and that is the point: the secret half never leaves this
// machine, which is the whole reason to forward an agent rather than a key.
func (s *Service) importKeys(ctx context.Context, h service.Host, home string, keys []byte) error {
	local, err := os.CreateTemp("", "devtun-pubkeys-*.asc")
	if err != nil {
		return fmt.Errorf("staging your public keys: %w", err)
	}
	defer func() { _ = os.Remove(local.Name()) }()

	if _, err := local.Write(keys); err != nil {
		_ = local.Close()
		return fmt.Errorf("staging your public keys: %w", err)
	}
	if err := local.Close(); err != nil {
		return fmt.Errorf("staging your public keys: %w", err)
	}

	remote := path.Join(home, keyFile)
	if err := h.Upload(ctx, local.Name(), remote, 0o600); err != nil {
		return fmt.Errorf("uploading your public keys to %s: %w", h.Label(), err)
	}
	script := fmt.Sprintf("GNUPGHOME=%s gpg --batch --quiet --import %s 2>&1", quote(home), quote(remote))
	if out, err := h.Output(ctx, script); err != nil {
		return fmt.Errorf("importing your public keys on %s: %w (%s)", h.Label(), err, strings.TrimSpace(out))
	}
	h.Events().Emit(event.Event{
		Kind: "keys-imported", Class: event.Lifecycle, Level: event.Debug,
		Text: "imported your public keys into " + home,
	})
	return nil
}

// ServeSocket accepts forwarded agent connections until the context is
// cancelled.
func (s *Service) ServeSocket(ctx context.Context, listener net.Listener) error {
	var connections sync.WaitGroup
	defer connections.Wait()

	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accepting a gpg-agent connection: %w", err)
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			s.serveConn(ctx, conn)
		}()
	}
}

// serveConn joins one forwarded connection to the local agent.
//
// The bytes are not inspected. The Assuan protocol is a conversation, not a
// request and a reply, and a devtun that parsed it in order to describe what is
// being signed would be claiming a precision it does not have — while the thing
// that *does* know is already on screen, in pinentry.
func (s *Service) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	host := s.current()
	if host == nil {
		return
	}
	events, label := host.Events(), host.Label()

	socket, err := s.localSocket(ctx)
	if err != nil {
		events.Emit(event.Event{
			Kind: "refused", Class: event.Security, Level: event.Warn,
			Text: "could not reach your gpg-agent: " + err.Error(),
		})
		return
	}
	local, err := s.dial(ctx, socket)
	if err != nil {
		events.Emit(event.Event{
			Kind: "refused", Class: event.Security, Level: event.Warn,
			Text: "could not reach your gpg-agent: " + err.Error(),
		})
		return
	}
	defer func() { _ = local.Close() }()

	// A connection to your signing key is worth a line whether or not anything
	// comes of it: it is the only record of what that box did with the key, and
	// pinentry appears for a first signature but not for a cached one.
	started := time.Now()
	events.Emit(event.Event{
		Kind: "connected", Class: event.Security, Level: event.Info,
		Text: label + " connected to your gpg-agent",
	})

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		_ = local.Close()
	})
	defer stop()

	up, down := pipe(conn, local)
	events.Emit(event.Event{
		Kind: "closed", Class: event.Security, Level: event.Debug,
		Text:   fmt.Sprintf("%s finished with your gpg-agent after %s", label, time.Since(started).Round(time.Second)),
		Fields: []any{"sent", down, "received", up},
	})
}

// pipe copies in both directions until either end closes, returning how much
// went each way.
func pipe(remote, local net.Conn) (fromRemote, toRemote int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		fromRemote, _ = io.Copy(local, remote)
		// Half-close so the agent sees the end of the conversation rather than
		// waiting for a command that is never coming.
		if half, ok := local.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = local.Close()
		}
	}()
	go func() {
		defer wg.Done()
		toRemote, _ = io.Copy(remote, local)
		if half, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = remote.Close()
		}
	}()
	wg.Wait()
	return fromRemote, toRemote
}

// current is the attached host, or nil.
func (s *Service) current() service.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host
}

// dial reaches the local agent.
func (s *Service) dial(ctx context.Context, socket string) (net.Conn, error) {
	if s.opts.Dial != nil {
		return s.opts.Dial(ctx)
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	return dialer.DialContext(ctx, "unix", socket)
}

// export reads the public half of every key this machine holds.
func (s *Service) export(ctx context.Context) ([]byte, error) {
	if s.opts.Export != nil {
		return s.opts.Export(ctx)
	}
	out, err := s.run(ctx, s.gpg(), "--export", "--armor")
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (s *Service) run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (s *Service) gpg() string {
	if s.opts.GPG != "" {
		return s.opts.GPG
	}
	return "gpg"
}

func (s *Service) conf() string {
	if s.opts.Conf != "" {
		return s.opts.Conf
	}
	return "gpgconf"
}

// quote wraps a path for a POSIX shell.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type instance struct{}

func (*instance) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (*instance) Close() error                  { return nil }
