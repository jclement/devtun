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
	"strings"
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
	// ChoiceRefuseSession refuses this subject for the rest of the session.
	//
	// It closes an asymmetry that had been in the menu since opproxy: you
	// could say "allow always" and get a rule, but the only way to stop being
	// asked about something you kept declining was to approve it. A security
	// prompt that makes "yes" the only way to make itself go away is teaching
	// the wrong reflex.
	ChoiceRefuseSession
	// ChoiceRefuseAlways writes a persistent deny rule — "never".
	//
	// It is deliberately harder to undo than an approval: a deny beats every
	// allow, including one clicked through later, so the way back is the
	// config file. An approval given by mistake costs one secret; a refusal
	// given by mistake costs a moment's confusion, and the two should not be
	// equally easy to reverse by accident.
	ChoiceRefuseAlways
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
	case ChoiceRefuseSession:
		return "refuse this session"
	case ChoiceRefuseAlways:
		return "refuse always"
	default:
		return "deny"
	}
}

// Allows reports whether the choice permits the request to proceed.
func (c Choice) Allows() bool {
	switch c {
	case ChoiceDeny, ChoiceRefuseSession, ChoiceRefuseAlways:
		return false
	default:
		return true
	}
}

// Refuses reports a choice that should be remembered as a refusal rather than
// merely acted on once.
func (c Choice) Refuses() bool {
	return c == ChoiceRefuseSession || c == ChoiceRefuseAlways
}

// Request is everything the human needs to make the decision.
type Request struct {
	// Host is the SSH host the request came from — the identity the decision is
	// recorded against.
	Host string
	// Subject is the thing being asked for.
	Subject string
	// Noun is what the menu calls the subject — "secret", "key". Empty means
	// "secret". It exists because a menu offering to "allow this secret" for a
	// signature request is describing something that is not happening, and the
	// menu is read at the exact moment somebody is deciding.
	Noun string
	// Scope names what a subject-wide grant actually covers, when that is
	// narrower than the subject reads. The agent uses it for the destination:
	// "allow this key for github.com" is a promise a person can weigh, where
	// "allow this key" is not.
	Scope string
	// Prefer is the option the cursor starts on. Zero — ChoiceDeny — means
	// narrowest-first, which is the right default for a one-off secret. A
	// service whose requests arrive in floods (an agent signing for a `git
	// push`) sets the session option instead, because a menu whose default
	// costs six keystrokes a minute gets the service switched off.
	Prefer Choice
	// Rows are labelled detail lines shown above the menu. They are supplied
	// rather than derived so this package needs to know nothing about what any
	// particular service considers worth showing.
	Rows []Row
	// Caller is unverified provenance from the remote box. It is displayed with
	// that caveat and never used to decide anything.
	Caller service.Caller
	// TTL is how long the temporary options will last, so the prompt can say so.
	TTL time.Duration
}

// Row is one labelled line of detail in a prompt.
type Row struct {
	Label string
	Value string
}

// SubjectNoun is what to call the subject in a sentence.
func (r Request) SubjectNoun() string {
	if r.Noun == "" {
		return "secret"
	}
	return r.Noun
}

// ScopeSuffix renders the scope for a menu label, empty when there is none.
func (r Request) ScopeSuffix() string {
	if r.Scope == "" {
		return ""
	}
	return " for " + r.Scope
}

// PrompterFunc adapts a function to a Prompter, for a caller that has one
// answer to give and no state to keep.
type PrompterFunc func(context.Context, Request) (Choice, error)

// Ask calls f.
func (f PrompterFunc) Ask(ctx context.Context, r Request) (Choice, error) { return f(ctx, r) }

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

// Valid reports whether the backend names an interface devtun knows. It exists
// so a typo in a config file is caught when devtun starts rather than at the
// moment somebody's script asks for a secret.
func (b Backend) Valid() bool {
	switch b {
	case BackendAuto, BackendTUI, BackendDialog, BackendDeny, "":
		return true
	default:
		return false
	}
}

// New builds the prompter for a backend, falling back where the requested one
// is unavailable on this platform or in this session.
func New(backend Backend) (Prompter, error) { return NewWithFallback(backend, nil) }

// NewWithFallback is New for a caller that has a better answer than the
// terminal for a dialog that cannot be drawn.
//
// The interface passes its own modal: under the TUI the terminal is the alt
// screen, and a huh form there would draw over the thing it is asking about.
// A nil fallback means the terminal.
func NewWithFallback(backend Backend, fallback Prompter) (Prompter, error) {
	if fallback == nil {
		fallback = &TUI{}
	}
	switch backend {
	case BackendDeny:
		return Serialize(DenyAll{}), nil
	case BackendTUI:
		return Serialize(&TUI{}), nil
	case BackendDialog:
		if !dialogAvailable() {
			return nil, fmt.Errorf("no desktop dialog program here: devtun looked for %s. "+
				"install one, or use --prompt tui to be asked in the terminal", strings.Join(chooserNames(), ", "))
		}
		// There is still a fallback for the day the dialog cannot be drawn — a
		// locked screen, a broken helper. A prompt that fails is a prompt that
		// denies, and denying because a GUI would not start is not an answer
		// anybody gave.
		return Serialize(&Dialog{fallback: fallback}), nil
	case BackendAuto, "":
		if dialogAvailable() {
			return Serialize(&Dialog{fallback: fallback}), nil
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
	// "this key for github.com" rather than "this secret": the menu is the
	// sentence somebody is deciding on, and it should describe what will
	// actually happen.
	this := "this " + request.SubjectNoun() + request.ScopeSuffix()
	return []MenuItem{
		{"Yes, once", ChoiceAllowOnce},
		{fmt.Sprintf("Yes, %s — %s", this, ttl), ChoiceAllowSecretTTL},
		{fmt.Sprintf("Yes, %s — this session", this), ChoiceAllowSecretSession},
		{fmt.Sprintf("Yes, %s — always (writes a rule)", this), ChoiceAllowSecretAlways},
		{fmt.Sprintf("Yes to anything from %s — %s", request.Host, ttl), ChoiceAllowHostTTL},
		{fmt.Sprintf("Yes to anything from %s — this session", request.Host), ChoiceAllowHostSession},
		{"No", ChoiceDeny},
		{"No, and stop asking this session", ChoiceRefuseSession},
		{fmt.Sprintf("Never, %s (writes a deny rule)", this), ChoiceRefuseAlways},
	}
}

// PreferredIndex is where the cursor starts, given the request's Prefer.
//
// It is an index rather than a reordering on purpose: the options stay in
// narrowest-first order, so a hurried reader still sees the broad ones below
// the narrow ones and has to travel to reach them.
func PreferredIndex(items []MenuItem, prefer Choice) int {
	if prefer == ChoiceDeny {
		return 0
	}
	for i, item := range items {
		if item.Choice == prefer {
			return i
		}
	}
	return 0
}
