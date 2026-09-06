// Package sshagent forwards the workstation's SSH agent to a remote
// development box, with every signature approved one at a time.
//
// `ssh -A` already forwards an agent, so the forwarding is not what this is
// for. The point is that plain ForwardAgent is a blind trust decision: for as
// long as you are connected, anyone with your uid — or root — on that box can
// sign as you, to anywhere, and you never find out it happened. The agent
// protocol carries no notion of a policy and no notion of a human, so there is
// nothing to configure; the only dial is on or off.
//
// devtun already owns the four things that fix that — an approval prompt,
// persistent per-host policy where deny beats allow, TTL grants, and a
// security-classed event log — so this service points them at signature
// requests.
//
// The split of the agent surface is deliberate and is the whole design:
//
//   - Sign is gated. It is the only operation that exercises a key, and so the
//     only one where a decision is worth a human's attention.
//   - List is allowed and recorded. It hands over which keys you hold, which is
//     not an authentication but is worth a line in the record.
//   - Add, Remove, RemoveAll, Lock, Unlock and Signers are refused outright,
//     with no policy consulted and no prompt offered. A remote box has no
//     business mutating the agent on your desk, and there is no answer to that
//     question worth asking for — the same reasoning as the 1Password guard
//     refusing --session and --config.
package sshagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

var (
	_ service.Service       = (*Service)(nil)
	_ service.SocketService = (*Service)(nil)
	_ service.Advisor       = (*Service)(nil)
	_ service.Instance      = (*instance)(nil)
	_ agent.ExtendedAgent   = (*gate)(nil)
)

// rulesKey is where this host's own rules live in its config document.
const rulesKey = "rules"

// Options is everything the caller decides for this service. Nothing here is
// read from a file by this package: where the settings live is the caller's
// business, as it is for the 1Password broker.
type Options struct {
	// Rules are the global policy rules, applying to every host. The rules
	// devtun writes when a prompt is answered "always" are per-host and are
	// kept in the host's own config document instead.
	Rules []authz.Rule
	// DefaultTTL is how long a "for a while" grant lasts. Zero means five
	// minutes.
	DefaultTTL time.Duration
	// PromptTimeout bounds how long a signature waits for a human. Zero means
	// two minutes. It matters more here than anywhere else in devtun: an `ssh`
	// client blocked on the agent is a login that appears to have hung.
	PromptTimeout time.Duration
	// Prompter asks the human. Nil means nobody can be asked, which refuses
	// everything a rule does not already allow: the zero value of a decision is
	// no.
	Prompter prompt.Prompter
	// AuthSock overrides $SSH_AUTH_SOCK as the local agent to forward.
	AuthSock string
	// KnownHosts are the files consulted to put a name on a signing
	// destination. Empty means destinations are named by host key fingerprint,
	// which is correct but hard to read in a prompt.
	KnownHosts []string
	// Dial replaces the connection to the local agent, for tests.
	Dial func(ctx context.Context) (net.Conn, error)
}

// Service is the agent broker. Grants and rules live here rather than on an
// Instance, so a dropped SSH connection is invisible to policy: reconnecting
// does not re-ask for a key you approved a minute ago, and a session grant
// lasts as long as devtun does.
type Service struct {
	opts     Options
	store    *authz.Store
	prompter prompt.Prompter
	names    *hostNames

	mu      sync.Mutex
	host    service.Host
	adopted bool // the host's own rules have been loaded
}

// New builds the service. It touches nothing — no agent, no file, no socket —
// so it is safe to construct for a host that turns out not to support it.
func New(opts Options) *Service {
	prompter := opts.Prompter
	if prompter == nil {
		prompter = prompt.Serialize(prompt.DenyAll{})
	}
	return &Service{
		opts: opts,
		store: authz.NewStore(authz.Config{
			DefaultTTL:    opts.DefaultTTL,
			PromptTimeout: opts.PromptTimeout,
			Rules:         opts.Rules,
		}),
		prompter: prompter,
		names:    newHostNames(opts.KnownHosts),
	}
}

// SetPrompter replaces how approvals are asked for.
//
// It exists for the same reason the 1Password service's does: the TUI's modal
// cannot be constructed until the Bubble Tea program is, which is after this
// service. Without it the zero-value substitution in New — a nil prompter
// becomes DenyAll, deliberately — would be permanent, and every signature under
// --tui would be refused with no way to say yes.
//
// Call it before the session starts; it is not safe afterwards.
func (s *Service) SetPrompter(p prompt.Prompter) {
	if p == nil {
		p = prompt.DenyAll{}
	}
	s.prompter = prompt.Serialize(p)
}

// Meta is the service's static identity.
func (s *Service) Meta() service.Meta {
	return service.Meta{
		ID:    "ssh-agent",
		Title: "SSH Agent",
		Glyph: "🔑",
		Class: event.Security,
		Short: "Forward your SSH agent to the remote box, one approved signature at a time",
	}
}

// Probe reports whether this service can work. What it needs is here, not
// there: a local agent that answers. The remote box needs nothing at all — an
// `ssh` client and a socket path are the entire requirement — so Facts are not
// consulted.
//
// Listing the identities rather than merely connecting is the same bargain as
// running `op --version`: a stale socket file left behind by a dead agent
// accepts a connection perfectly well, and finding that out now beats finding
// it out when a push stalls an hour in.
func (s *Service) Probe(ctx context.Context, _ service.Host) service.Support {
	conn, err := s.dial(ctx)
	if err != nil {
		return service.Unsupported(unreachable(s.authSock()))
	}
	defer func() { _ = conn.Close() }()

	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return service.Unsupported("the SSH agent will not answer: " + firstLine(err.Error()))
	}
	// No keys loaded is still supported: `ssh-add` during the session is
	// normal, and refusing to publish the socket would mean a reconnect to fix
	// it.
	return service.Support{OK: true, Detail: describeKeys(len(keys))}
}

// unreachable explains a failed probe. The two cases are worth telling apart
// because they are fixed differently: no SSH_AUTH_SOCK at all means agent
// forwarding was never going to work from this shell, while a socket that will
// not answer means the agent died and starting one fixes it.
func unreachable(path string) string {
	if path == "" {
		return "no SSH agent to forward (SSH_AUTH_SOCK is unset)"
	}
	return "no SSH agent to forward (nothing is listening on " + path + ")"
}

func describeKeys(n int) string {
	if n == 1 {
		return "1 key loaded"
	}
	return fmt.Sprintf("%d keys loaded", n)
}

// firstLine keeps an error to its first line, so a chatty failure cannot push
// the actionable words out of a narrow column.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// Attach binds the service to a connection. The only work is remembering where
// events go and, the first time, picking up the rules already recorded for this
// host.
func (s *Service) Attach(_ context.Context, h service.Host) (service.Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.host = h
	if !s.adopted {
		var rules []authz.Rule
		// GetLocal, not Get: the global rules arrived through Options, and Get
		// falls through to the global section when the host has no rules of its
		// own — so "allow always", which writes the whole slice back, would
		// copy them into the host file where deleting one globally no longer
		// reaches them.
		if _, err := h.Config().GetLocal(rulesKey, &rules); err != nil {
			// Rules that cannot be read include denies, so carrying on without
			// them would silently widen access. Refusing to attach is the only
			// safe reading of an unparseable policy.
			return nil, fmt.Errorf("reading the SSH agent rules for %s: %w", h.Label(), err)
		}
		s.store.AdoptHostRules(rules, configSaver{h.Config()})
		s.adopted = true
	}
	return &instance{}, nil
}

// Forget drops every live grant, which is the "lock it back up" action.
func (s *Service) Forget() int { return s.store.ForgetGrants() }

// Rules exposes the rules devtun wrote for this host, for a caller that lists
// or revokes them.
func (s *Service) Rules() []authz.Rule { return s.store.Rules() }

// Revoke removes the host rule at index, as numbered by Rules.
func (s *Service) Revoke(index int) error { return s.store.Revoke(index) }

// Grants lists the allowances a prompt created and that have not yet lapsed —
// which keys may currently sign, for where, without asking again.
func (s *Service) Grants() []authz.Grant { return s.store.Grants() }

// RevokeGrant drops a single live grant, reporting whether it was there.
func (s *Service) RevokeGrant(host, subject string) bool {
	return s.store.RevokeGrant(host, subject)
}

// authSock is the local agent to forward.
func (s *Service) authSock() string {
	if s.opts.AuthSock != "" {
		return s.opts.AuthSock
	}
	return os.Getenv("SSH_AUTH_SOCK")
}

// dial opens a connection to the local agent.
//
// Every forwarded connection gets one of its own. The agent client serialises
// requests over a single connection, so sharing one would put a signature that
// is waiting on a human in front of every other request in the process — and a
// prompt that blocks an unrelated `git fetch` for two minutes is a prompt that
// gets answered "yes" without being read.
func (s *Service) dial(ctx context.Context) (net.Conn, error) {
	if s.opts.Dial != nil {
		return s.opts.Dial(ctx)
	}
	path := s.authSock()
	if path == "" {
		return nil, errors.New("SSH_AUTH_SOCK is unset")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", path)
}

// current returns the host of the most recent attachment, or nil before there
// has been one.
func (s *Service) current() service.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host
}

// instance is the service bound to one SSH connection. There is nothing to run:
// the listener is the session's, and everything worth keeping lives on the
// Service so that a reconnect cannot lose it.
type instance struct{}

// Run blocks until the connection goes away.
func (*instance) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Close releases remote state, of which there is none — the socket is removed
// by the session that published it.
func (*instance) Close() error { return nil }

// configSaver persists the host's rules through the service's slice of the host
// config. Set marks the document dirty rather than writing it out; the session
// saves once, on exit, which is the same bargain every other service makes.
type configSaver struct {
	config service.Config
}

// SaveRules stores the whole rule set under the service's "rules" key.
func (c configSaver) SaveRules(rules []authz.Rule) error {
	return c.config.Set(rulesKey, rules)
}
