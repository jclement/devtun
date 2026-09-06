package onepassword

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/onepassword/opcli"
	"github.com/jclement/devtun/internal/onepassword/opref"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

const (
	// ExitDenied is the exit status the shim reports when devtun refused the
	// request. It follows sysexits.h EX_NOPERM so a script can tell "you may
	// not have this" apart from "op could not find it".
	ExitDenied = 77
	// ExitProxyError is reported for failures in devtun itself.
	ExitProxyError = 78
	// requestReadTimeout drops a connection that opens and then says nothing.
	requestReadTimeout = 30 * time.Second
)

// link is one connection's surroundings: the authenticated host it arrived
// from, where its events go, and what the shim claims about itself. The first
// two decide things; the third is only ever displayed.
type link struct {
	host   string
	events event.Sink
	caller service.Caller
}

// HandleConn serves exactly one request and closes the connection. One request
// per connection is deliberate: requests are rare and short, so a connection
// each means no stream framing state to corrupt, no head-of-line blocking
// behind a request that is waiting on a human, and a wedged client that can
// poison nothing but itself.
func (s *Service) HandleConn(ctx context.Context, conn net.Conn, caller service.Caller) error {
	defer func() { _ = conn.Close() }()

	host := s.current()
	if host == nil {
		// The session only routes to an attached service, so this is a wiring
		// mistake rather than anything a remote box can provoke.
		return errors.New("1password: a request arrived before the service attached to a host")
	}
	l := &link{host: host.Label(), events: host.Events(), caller: caller}

	// SSH channels do not honour SetDeadline, so an idle timer that closes the
	// connection is the way to bound the read.
	idle := time.AfterFunc(requestReadTimeout, func() { _ = conn.Close() })
	var request opRequest
	err := shim.ReadFrame(conn, &request)
	idle.Stop()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil // a client that connected and said nothing
		}
		return fmt.Errorf("1password: reading request: %w", err)
	}

	if err := shim.WriteFrame(conn, s.dispatch(ctx, l, request)); err != nil {
		return fmt.Errorf("1password: sending response: %w", err)
	}
	return nil
}

func (s *Service) dispatch(ctx context.Context, l *link, request opRequest) *opResponse {
	switch request.Op {
	case opPing:
		return &opResponse{}
	case opExec:
		return s.handleExec(ctx, l, request)
	case opResolve:
		return s.handleResolve(ctx, l, request)
	default:
		return refuse(fmt.Sprintf("unknown request type %q", request.Op))
	}
}

// handleExec authorises and runs a passthrough `op` command.
func (s *Service) handleExec(ctx context.Context, l *link, request opRequest) *opResponse {
	if len(request.Argv) == 0 {
		return refuse("no command given")
	}
	if err := s.guard.Check(request.Argv); err != nil {
		l.denied("op "+strings.Join(request.Argv, " "), err.Error())
		return &opResponse{Exit: ExitDenied, Error: err.Error()}
	}

	subject := opref.Subject(request.Argv)
	l.requested(subject)

	allowed, reason, until := s.authorize(ctx, l, subject, request.Argv)
	if !allowed {
		l.denied(subject, reason)
		return &opResponse{Exit: ExitDenied, Error: "denied by devtun: " + reason}
	}

	account := s.accountFor(subject)
	started := time.Now()

	// The cache is consulted only after the request has been authorised, never
	// instead of it, so a lapsed grant can never be satisfied from memory.
	if key, ok := cacheKey(account, request.Argv); ok {
		if cached, hit := s.cache.Get(key); hit {
			l.cached(subject, reason)
			return &opResponse{Stdout: cached}
		}
		result, err := s.run(ctx, l, account, subject, request.Argv, request.Stdin)
		if err != nil || result.Exit != 0 {
			return s.respond(l, result, err, subject, reason, started)
		}
		s.cache.Put(key, result.Stdout, until)
		return s.respond(l, result, nil, subject, reason, started)
	}

	result, err := s.run(ctx, l, account, subject, request.Argv, request.Stdin)
	return s.respond(l, result, err, subject, reason, started)
}

// run invokes op, keeping the error handling in one place.
func (s *Service) run(ctx context.Context, l *link, account, subject string, argv []string, stdin []byte) (opcli.Result, error) {
	runner, err := s.opRunner()
	if err != nil {
		l.failed(subject, err.Error())
		return opcli.Result{}, err
	}
	result, err := runner.Run(ctx, account, argv, stdin)
	if err != nil {
		l.failed(subject, err.Error())
	}
	return result, err
}

func (s *Service) respond(l *link, result opcli.Result, err error, subject, reason string, started time.Time) *opResponse {
	if err != nil {
		return &opResponse{Exit: ExitProxyError, Error: err.Error()}
	}
	l.allowed(subject, reason, time.Since(started))
	return &opResponse{Exit: result.Exit, Stdout: result.Stdout, Stderr: result.Stderr}
}

// cacheKey names the cache slot for a command, and reports whether the command
// is cacheable at all. Only a bare `op read <reference>` is: it is the one
// invocation whose output is a single secret's value and does not change
// between calls. Anything with extra flags, and anything that lists or reports,
// is passed through every time.
//
// Keys carry the account because two accounts can hold a vault of the same
// name, and serving one account's secret for the other's reference would be a
// leak dressed up as a cache hit.
func cacheKey(account string, argv []string) (string, bool) {
	if len(argv) != 2 || argv[0] != "read" {
		return "", false
	}
	ref, err := opref.Parse(argv[1])
	if err != nil {
		return "", false
	}
	return account + "\x00" + ref.String(), true
}

// accountFor picks the 1Password account a subject belongs to, which matters
// once more than one account is signed in: a reference names a vault, and the
// vault decides the account.
func (s *Service) accountFor(subject string) string {
	return s.opts.Accounts.For(subject)
}

// handleResolve authorises and reads a batch of secret references. It is
// all-or-nothing: a template injected with some values missing is a silent
// failure waiting to happen at deploy time, so one refusal fails the batch.
func (s *Service) handleResolve(ctx context.Context, l *link, request opRequest) *opResponse {
	if len(request.Refs) == 0 {
		return refuse("no references given")
	}

	secrets := make(map[string]string, len(request.Refs))
	for _, raw := range request.Refs {
		ref, err := opref.Parse(raw)
		if err != nil {
			return refuse(err.Error())
		}
		subject := ref.String()
		l.requested(subject)

		argv := []string{"read", subject}
		allowed, reason, until := s.authorize(ctx, l, subject, argv)
		if !allowed {
			l.denied(subject, reason)
			return &opResponse{Exit: ExitDenied, Error: fmt.Sprintf("denied by devtun: %s (%s)", subject, reason)}
		}

		account := s.accountFor(subject)
		started := time.Now()

		key, _ := cacheKey(account, argv)
		if cached, hit := s.cache.Get(key); hit {
			l.cached(subject, reason)
			secrets[raw] = trimSecret(cached)
			continue
		}

		result, err := s.run(ctx, l, account, subject, argv, nil)
		if err != nil {
			return &opResponse{Exit: ExitProxyError, Error: err.Error()}
		}
		if result.Exit != 0 {
			message := strings.TrimSpace(string(result.Stderr))
			if message == "" {
				message = fmt.Sprintf("op exited %d", result.Exit)
			}
			l.failed(subject, message)
			return &opResponse{Exit: ExitProxyError, Error: fmt.Sprintf("reading %s: %s", subject, message)}
		}
		s.cache.Put(key, result.Stdout, until)
		l.allowed(subject, reason, time.Since(started))
		secrets[raw] = trimSecret(result.Stdout)
	}
	return &opResponse{Secrets: secrets}
}

// authorize consults policy and, if policy has no answer, the human. The
// returned reason is reported and sent back to the remote box, so it says why
// rather than merely that.
//
// Note what is passed to Decide: the host devtun connected to, and the subject.
// Never the caller — that is the remote box describing itself, and a process
// that wants a secret it should not have would describe itself however it had
// to.
func (s *Service) authorize(ctx context.Context, l *link, subject string, argv []string) (allowed bool, reason string, until time.Time) {
	verdict := s.store.Decide(l.host, subject)
	switch verdict.Action {
	case authz.ActionAllow:
		return true, verdict.Reason, verdict.Until
	case authz.ActionDeny:
		return false, verdict.Reason, time.Time{}
	}

	config := s.store.Config()
	askCtx, cancel := context.WithTimeout(ctx, config.PromptTimeout)
	defer cancel()

	choice, err := s.prompter.Ask(askCtx, prompt.Request{
		Host:    l.host,
		Subject: subject,
		Noun:    "secret",
		Caller:  l.caller,
		TTL:     config.DefaultTTL,
		// The command is shown so an unusual request is visible: `op read` and
		// `op item get` reach the same secret, but a shape you did not expect
		// is worth seeing before approving it.
		Rows: []prompt.Row{{Label: "command", Value: "op " + strings.Join(argv, " ")}},
	})
	// Belt and braces on the prompt deadline. A Prompter is meant to abandon
	// its question when the context fires, but this is the one decision in
	// devtun where trusting a collaborator to have got that right is not good
	// enough: an answer that raced the deadline must not become an allow, and
	// checking here costs nothing.
	if askCtx.Err() != nil {
		return false, fmt.Sprintf("no answer within %s", config.PromptTimeout), time.Time{}
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, fmt.Sprintf("no answer within %s", config.PromptTimeout), time.Time{}
		}
		return false, err.Error(), time.Time{}
	}
	if !choice.Allows() {
		return false, "refused at the prompt", time.Time{}
	}

	return true, "approved: " + choice.String(), s.recordGrant(l, choice, subject, config)
}

// recordGrant turns the human's answer into policy, and returns when that
// answer lapses — the zero time when it does not lapse on its own. A failure to
// persist an "always" rule is reported but does not undo the approval: the user
// said yes, and the worst case is being asked again.
func (s *Service) recordGrant(l *link, choice prompt.Choice, subject string, config authz.Config) time.Time {
	ttl := config.DefaultTTL
	switch choice {
	case prompt.ChoiceAllowOnce:
		// Nothing is recorded, so nothing derived from it may be kept either.
		return time.Now()
	case prompt.ChoiceAllowSecretTTL:
		s.store.GrantTemporary(l.host, subject, ttl)
		return time.Now().Add(ttl)
	case prompt.ChoiceAllowHostTTL:
		s.store.GrantTemporary(l.host, authz.HostWildcard, ttl)
		return time.Now().Add(ttl)
	case prompt.ChoiceAllowSecretSession:
		s.store.GrantSession(l.host, subject)
	case prompt.ChoiceAllowHostSession:
		s.store.GrantSession(l.host, authz.HostWildcard)
	case prompt.ChoiceAllowSecretAlways:
		note := "approved interactively on " + time.Now().Format("2006-01-02")
		if err := s.store.GrantPermanent(l.host, subject, note); err != nil {
			l.failed(subject, "could not save the rule: "+err.Error())
			break
		}
		l.event("saved", event.Info, fmt.Sprintf("saved a rule allowing %s from %s", subject, l.host))
	}
	return time.Time{}
}

// trimSecret drops the newline `op read` prints after a value. Callers are
// substituting the result into an environment variable or a template, where the
// newline is never wanted.
func trimSecret(raw []byte) string {
	return strings.TrimRight(string(raw), "\r\n")
}

func refuse(message string) *opResponse {
	return &opResponse{Exit: ExitProxyError, Error: message}
}

// The events below are this service's security record: which host asked for
// which secret, and what was decided. Every semantic event gets a method so the
// wording stays consistent and the set of things worth reporting is visible in
// one place. Nothing here renders or styles anything — Class is what every
// renderer keys its treatment off.

func (l *link) event(kind string, level event.Level, text string, fields ...any) {
	l.events.Emit(event.Event{
		Kind:   kind,
		Class:  event.Security,
		Level:  level,
		Text:   text,
		Fields: fields,
	})
}

// requested records an incoming ask, before any decision is made. It is
// reported separately from the outcome so a request that is sitting waiting for
// a human is still visible.
func (l *link) requested(subject string) {
	// The caller is folded into the sentence rather than trailing after it as
	// `from=…`. "bedev wants op://… — deploy.sh, pid 4412" is the whole
	// question a human is being asked; the same words in logfmt are a record
	// nobody reads. The field survives for NDJSON either way.
	l.event("requested", event.Info,
		fmt.Sprintf("%s wants %s — %s", l.host, subject, describeCaller(l.caller)),
		"from", describeCaller(l.caller))
}

// allowed records a granted request and how long it took.
func (l *link) allowed(subject, reason string, elapsed time.Duration) {
	l.event("allowed", event.Info,
		fmt.Sprintf("gave %s %s (%s)", l.host, subject, reason),
		"why", reason, "took", elapsed.Round(time.Millisecond))
}

// cached records a request satisfied from memory. It is its own kind because
// "this secret did not leave the vault again" is a different fact from "this
// secret was fetched", and the record should not blur them.
func (l *link) cached(subject, reason string) {
	l.event("cached", event.Info, fmt.Sprintf("gave %s %s from cache", l.host, subject), "why", reason)
}

// denied records a refusal. Refusals are Info rather than Warn: denying is the
// system working, not failing.
func (l *link) denied(subject, reason string) {
	l.event("denied", event.Info,
		fmt.Sprintf("refused %s %s — %s", l.host, subject, reason), "why", reason)
}

// failed records op, or the machinery around it, going wrong — which is neither
// an allow nor a deny and should not be counted as either.
func (l *link) failed(subject, detail string) {
	l.event("failed", event.Error, "op failed for "+subject, "err", detail)
}

// describeCaller renders the shim's self-reported provenance. It is displayed
// so that "deploy.sh in ~/projects/api wants this" is available to whoever is
// deciding, and it reaches no decision of its own.
func describeCaller(caller service.Caller) string {
	var parts []string
	if caller.User != "" && caller.Host != "" {
		parts = append(parts, caller.User+"@"+caller.Host)
	}
	if caller.Program != "" {
		parts = append(parts, caller.Program)
	}
	if caller.PID != 0 {
		parts = append(parts, fmt.Sprintf("pid %d", caller.PID))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " ")
}
