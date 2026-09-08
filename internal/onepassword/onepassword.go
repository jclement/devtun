// Package onepassword proxies `op` from a remote development box back to the
// unlocked vault on the workstation, one approval at a time.
//
// `op` needs an unlocked vault, and unlocking one needs the desktop app and a
// biometric. On a remote box you have neither, so the usual answers are a
// service-account token in a file or a session left signed in — both of which
// put long-lived vault access on a machine that is shared, snapshot or rebuilt
// often. This service moves the *request* instead of the credential: the vault
// stays here, the remote box gets a socket it can ask through, and every new
// thing it asks for is a question you answer.
//
// The order of checks matters and is deliberate. The guard runs first and is
// about *shape* — is this even a command we are willing to proxy. Policy runs
// second and is about *identity* — may this host have this secret. Only then
// does anything touch the vault. Nothing about the request's own claims of who
// it is affects either decision: that comes from the SSH destination, which is
// authenticated.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/onepassword/opcli"
	opguard "github.com/jclement/devtun/internal/onepassword/policy"
	"github.com/jclement/devtun/internal/onepassword/vaultcache"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// rulesKey is where the host's own rules live in its config document. The gate
// writes it; this is here so the tests can name the same key.
const rulesKey = "rules"

// SecretRunner is the slice of the 1Password CLI this service needs. It is an
// interface so the authorisation logic can be tested without a vault — the
// decisions are the part worth testing, and they must not depend on somebody
// being signed in.
type SecretRunner interface {
	Run(ctx context.Context, account string, argv []string, stdin []byte) (opcli.Result, error)
}

// Options is everything the caller decides for this service. Rules and account
// routing arrive here already parsed: where the user's settings live is the
// caller's business, and this package deliberately reads no files of its own.
type Options struct {
	// Rules are the global policy rules, applying to every host. The rules
	// devtun writes when a prompt is answered "always" are per-host and are
	// kept in the host's own config document instead.
	Rules []authz.Rule
	// Accounts routes vaults to 1Password accounts.
	Accounts Accounts
	// DefaultTTL is how long a "for a while" grant lasts. Zero means five
	// minutes.
	DefaultTTL time.Duration
	// PromptTimeout bounds how long a request waits for a human. Zero means two
	// minutes.
	PromptTimeout time.Duration
	// AllowCommands extends the read-only command allowlist.
	AllowCommands []string
	// AllowAllCommands disables the allowlist. It is equivalent to handing the
	// remote box the vault; it exists as an escape hatch, not as a setting.
	AllowAllCommands bool
	// CacheTTL turns on the secret cache and bounds how long a value may be
	// held. Zero — the default — keeps nothing in memory beyond one `op`
	// invocation.
	CacheTTL time.Duration
	// Prompter asks the human. Nil means nobody can be asked, which refuses
	// everything a rule does not already allow: the zero value of a decision is
	// no.
	Prompter prompt.Prompter
	// OpPath overrides where the 1Password CLI is found. Empty means $PATH.
	OpPath string
	// Runner replaces the real CLI, for tests.
	Runner SecretRunner
}

// Service is the 1Password broker. Grants, rules and cached values live here
// rather than on an Instance, so a dropped SSH connection is invisible to
// policy: reconnecting does not re-ask for a secret you approved a minute ago,
// and a session grant lasts as long as devtun does.
type Service struct {
	opts  Options
	gate  *authz.Gate
	guard *opguard.Guard
	cache *vaultcache.Cache

	mu     sync.Mutex
	runner SecretRunner
	host   service.Host
}

// New builds the service. It touches nothing — no vault, no file, no network —
// so it is safe to construct for a host that turns out not to support it.
func New(opts Options) *Service {
	return &Service{
		opts: opts,
		gate: authz.NewGate(authz.Config{
			DefaultTTL:    opts.DefaultTTL,
			PromptTimeout: opts.PromptTimeout,
			Rules:         opts.Rules,
		}, opts.Prompter),
		guard: opguard.NewGuard(opguard.GuardConfig{
			AllowCommands:    opts.AllowCommands,
			AllowAllCommands: opts.AllowAllCommands,
		}),
		cache:  vaultcache.New(opts.CacheTTL),
		runner: opts.Runner,
	}
}

// Meta is the service's static identity.
// SetPrompter replaces how approvals are asked for.
//
// It exists because the TUI's modal cannot be constructed until the Bubble Tea
// program is, which is after this service. Without it the zero-value
// substitution in New — a nil prompter becomes DenyAll, deliberately, so the
// zero value of a decision is no — would be permanent, and every request under
// --tui would be refused with no way to say yes.
//
// The prompter is wrapped in Serialize by the gate, as New does, so a caller
// cannot accidentally install one that allows two questions at once.
// Call it before the session starts; it is not safe afterwards.
func (s *Service) SetPrompter(p prompt.Prompter) { s.gate.SetPrompter(p) }

func (s *Service) Meta() service.Meta {
	return service.Meta{
		ID:    "1password",
		Title: "1Password",
		Glyph: "❖",
		Class: event.Security,
		Short: "Serve `op` from your unlocked vault to the remote box, one approval at a time",
	}
}

// Probe reports whether this service can work. What it needs is here, not
// there: a working `op` on the workstation. The remote box needing no `op` at
// all is the entire point of the tool, so Facts are not consulted.
//
// The version call is deliberate. Proving op works before anything remote is
// wired up turns a confusing mid-session failure — a script stalling on a
// locked vault an hour in — into a clear one at the moment of connecting.
func (s *Service) Probe(ctx context.Context, _ service.Host) service.Support {
	// The two failures are worth telling apart, and the reasons read
	// differently: "op is not here" is fixed by installing something, "op is
	// here and unhappy" is fixed by signing in. Stacking both behind one
	// sentence and then appending a Go exec error puts the only actionable
	// words last, where a narrow Services column truncates them away.
	runner, err := s.opRunner()
	if err != nil {
		return service.Unsupported(notInstalled)
	}
	result, err := runner.Run(ctx, "", []string{"--version"}, nil)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return service.Unsupported(notInstalled)
		}
		return service.Unsupported("op will not run here: " + firstLine(err.Error()))
	}
	if result.Exit != 0 {
		detail := firstLine(strings.TrimSpace(string(result.Stderr)))
		if detail == "" {
			detail = fmt.Sprintf("op --version exited %d", result.Exit)
		}
		return service.Unsupported("op is installed but not usable: " + detail)
	}
	return service.Support{OK: true, Detail: "op " + strings.TrimSpace(string(result.Stdout))}
}

// notInstalled says the one thing that fixes it, and says it early enough to
// survive a narrow column.
const notInstalled = "op is not installed here (brew install 1password-cli)"

// firstLine keeps an error to its first line. `op` is chatty on failure and a
// six-line stderr in a one-line slot is six lines of nothing.
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
	if err := s.gate.Adopt(h.Label(), h.Config(), "1Password"); err != nil {
		return nil, err
	}
	return instance{}, nil
}

// Forget drops every live grant and everything cached under one. It is the
// "lock it back up" action, and the two have to happen together: a cached value
// whose authorisation has been withdrawn is exactly what must not be served.
func (s *Service) Forget() (grants, cached int) {
	return s.gate.ForgetGrants(), s.cache.Purge()
}

// Rules exposes the rules devtun wrote for this host, for a caller that lists
// or revokes them.
func (s *Service) Rules() []authz.Rule { return s.gate.Rules() }

// Revoke removes the host rule at index, as numbered by Rules.
func (s *Service) Revoke(index int) error { return s.gate.Revoke(index) }

// Deny turns the host rule at index into a refusal. It only tightens: see
// authz.Store.Deny.
func (s *Service) Deny(index int) error { return s.gate.Deny(index) }

// GlobalRules are the rules from the top-level config: visible so a person can
// see everything that is deciding, and not removable here because devtun did
// not write them.
func (s *Service) GlobalRules() []authz.Rule { return s.gate.GlobalRules() }

// Grants lists the allowances a prompt created and that have not yet lapsed —
// the access currently open in the user's name, as opposed to the rules on
// disk. Forget() drops all of them at once; this is what makes it possible to
// see one and drop just that one.
func (s *Service) Grants() []authz.Grant { return s.gate.Grants() }

// RevokeGrant drops a single live grant, reporting whether it was there.
func (s *Service) RevokeGrant(host, subject string) bool {
	return s.gate.RevokeGrant(host, subject)
}

// opRunner resolves the 1Password CLI once and keeps it. Probe runs on every
// connection, and looking op up again each time would only invite the answer to
// change halfway through a session.
func (s *Service) opRunner() (SecretRunner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.runner != nil {
		return s.runner, nil
	}
	runner, err := opcli.New(s.opts.OpPath)
	if err != nil {
		return nil, err
	}
	s.runner = runner
	return runner, nil
}

// current returns the host of the most recent attachment, or nil before there
// has been one.
func (s *Service) current() service.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host
}

// instance is the service bound to one SSH connection. There is nothing to run:
// every request arrives on the shared control socket, which the session owns,
// and everything worth keeping lives on the Service.
type instance struct{}

// Run blocks until the connection goes away.
func (instance) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Close releases remote state, of which there is none.
func (instance) Close() error { return nil }
