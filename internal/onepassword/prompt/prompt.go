// Package prompt asks the human at the workstation whether a remote host may
// have a secret, and turns their answer into a policy decision.
//
// The interesting constraint is concurrency: several shim connections can
// arrive at once, but there is only one terminal and one human. Serialize wraps
// any prompter so requests queue rather than fighting over the screen.
package prompt

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/service"
)

// Choice is what the human picked.
type Choice int

const (
	// ChoiceDeny refuses this request and leaves no trace.
	ChoiceDeny Choice = iota
	// ChoiceAllowOnce permits exactly this request.
	ChoiceAllowOnce
	// ChoiceAllowSecretTTL permits this secret from this host until the grant
	// expires.
	ChoiceAllowSecretTTL
	// ChoiceAllowSecretSession permits this secret from this host for as long
	// as devtun runs. It is the middle ground between a few minutes and a
	// rule on disk: broad enough for an afternoon's work, and revoked by
	// quitting.
	ChoiceAllowSecretSession
	// ChoiceAllowSecretAlways writes a persistent allow rule for this secret.
	ChoiceAllowSecretAlways
	// ChoiceAllowHostTTL permits anything from this host until the grant
	// expires. Useful for a deploy script that reads a dozen secrets in a row.
	ChoiceAllowHostTTL
	// ChoiceAllowHostSession permits anything from this host for the rest of
	// the session — the broadest thing on the menu, and the one to reach for
	// only while actively working on that box.
	ChoiceAllowHostSession
)

// String renders the choice for logs.
func (c Choice) String() string {
	switch c {
	case ChoiceAllowOnce:
		return "allow once"
	case ChoiceAllowSecretTTL:
		return "allow secret temporarily"
	case ChoiceAllowSecretSession:
		return "allow secret this session"
	case ChoiceAllowSecretAlways:
		return "allow secret always"
	case ChoiceAllowHostTTL:
		return "allow host temporarily"
	case ChoiceAllowHostSession:
		return "allow host this session"
	default:
		return "deny"
	}
}

// Allows reports whether the choice permits the request to proceed.
func (c Choice) Allows() bool { return c != ChoiceDeny }

// Request is everything the human needs to make the decision.
type Request struct {
	// Host is the SSH host the request came from — the identity the decision is
	// recorded against.
	Host string
	// Subject is the secret or command being asked for.
	Subject string
	// Argv is the full command, shown so an unusual request is visible.
	Argv []string
	// Caller is unverified provenance from the remote box. It is displayed with
	// that caveat and never used to decide anything.
	Caller service.Caller
	// TTL is how long the temporary options will last, so the prompt can say so.
	TTL time.Duration
}

// ErrNoPrompter is returned when a decision is needed but nobody can be asked.
var ErrNoPrompter = errors.New("no interactive terminal available to approve this request")

// Prompter asks a human and returns their choice.
type Prompter interface {
	Ask(ctx context.Context, request Request) (Choice, error)
}

// Serialize returns a Prompter that lets only one question be asked at a time.
func Serialize(inner Prompter) Prompter { return &serialized{inner: inner} }

type serialized struct {
	mu    sync.Mutex
	inner Prompter
}

func (s *serialized) Ask(ctx context.Context, request Request) (Choice, error) {
	// Take the lock in a way that still respects cancellation, otherwise a shim
	// whose timeout has already elapsed would sit in the queue and then pop a
	// prompt for a caller that has gone away.
	acquired := make(chan struct{})
	go func() {
		s.mu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
	case <-ctx.Done():
		go func() {
			<-acquired
			s.mu.Unlock()
		}()
		return ChoiceDeny, ctx.Err()
	}
	defer s.mu.Unlock()
	return s.inner.Ask(ctx, request)
}

// DenyAll is the prompter used when there is no terminal: it refuses and
// explains, rather than blocking a script forever or silently allowing.
type DenyAll struct{}

// Ask always refuses.
func (DenyAll) Ask(context.Context, Request) (Choice, error) {
	return ChoiceDeny, ErrNoPrompter
}

// Backend names an approval user interface.
type Backend string

const (
	// BackendAuto uses the native desktop dialog where one exists and the
	// terminal otherwise.
	BackendAuto Backend = "auto"
	// BackendTUI always asks in the terminal running devtun.
	BackendTUI Backend = "tui"
	// BackendDialog always uses the native desktop dialog.
	BackendDialog Backend = "dialog"
	// BackendDeny refuses everything that is not already covered by policy,
	// which is how an unattended session should run.
	BackendDeny Backend = "deny"
)

// New builds the prompter for a backend, falling back where the requested one
// is unavailable on this platform or in this session.
func New(backend Backend) (Prompter, error) {
	switch backend {
	case BackendDeny:
		return Serialize(DenyAll{}), nil
	case BackendTUI:
		return Serialize(&TUI{}), nil
	case BackendDialog:
		if !dialogAvailable() {
			return nil, fmt.Errorf("the native dialog backend is not available on this platform")
		}
		return Serialize(&Dialog{}), nil
	case BackendAuto, "":
		if dialogAvailable() {
			return Serialize(&Dialog{fallback: &TUI{}}), nil
		}
		return Serialize(&TUI{}), nil
	default:
		return nil, fmt.Errorf("unknown prompt backend %q (want auto, tui, dialog or deny)", backend)
	}
}

// MenuItem is one answer offered to the human.
type MenuItem struct {
	Label  string
	Choice Choice
}

// MenuFor builds the list of answers, narrowest first so that the safe choice
// is the one under the cursor and the broad ones take deliberate effort to
// reach. Deny is last, and is the zero Choice, so an interrupted or timed-out
// prompt lands on it.
func MenuFor(request Request) []MenuItem {
	ttl := request.TTL.String()
	return []MenuItem{
		{"Allow once", ChoiceAllowOnce},
		{fmt.Sprintf("Allow this secret for %s", ttl), ChoiceAllowSecretTTL},
		{"Allow this secret for this session", ChoiceAllowSecretSession},
		{"Allow this secret always", ChoiceAllowSecretAlways},
		{fmt.Sprintf("Allow anything from %s for %s", request.Host, ttl), ChoiceAllowHostTTL},
		{fmt.Sprintf("Allow anything from %s this session", request.Host), ChoiceAllowHostSession},
		{"Deny", ChoiceDeny},
	}
}
