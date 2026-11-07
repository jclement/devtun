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
	if err := s.currentGuard().Check(request.Argv); err != nil {
		l.denied("op "+strings.Join(request.Argv, " "), decision{reason: err.Error()})
		return &opResponse{Exit: ExitDenied, Error: err.Error()}
	}

	// Which account this reaches is settled before policy sees it, and op is
	// then told that account by devtun rather than by the caller: the argv
	// that runs has no --account of its own.
	argv := opref.StripAccount(request.Argv)
	bare := opref.Subject(argv)
	account, err := s.opts.Accounts.Effective(opref.Account(request.Argv), bare)
	if err != nil {
		l.denied("op "+strings.Join(request.Argv, " "), decision{reason: err.Error()})
		return &opResponse{Exit: ExitDenied, Error: err.Error()}
	}
	subject := s.opts.Accounts.Scope(account, bare)
	l.requested(subject)

	if refused := s.otherRefusal(l, subject, opref.Scoped(account, bare), bare); refused != nil {
		return refused
	}

	allowed, why, until := s.authorize(ctx, l, subject, request.Argv)
	if !allowed {
		l.denied(subject, why)
		return &opResponse{Exit: ExitDenied, Error: "denied by devtun: " + why.reason}
	}

	started := time.Now()

	// The cache is consulted only after the request has been authorised, never
	// instead of it, so a lapsed grant can never be satisfied from memory.
	if key, ok := cacheKey(account, argv); ok {
		if cached, hit := s.cache.Get(key); hit {
			l.cached(subject, why)
			return &opResponse{Stdout: cached}
		}
		result, err := s.run(ctx, l, account, subject, argv, request.Stdin)
		if err != nil || result.Exit != 0 {
			return s.respond(l, result, err, subject, why, started)
		}
		s.cache.Put(key, result.Stdout, until)
		return s.respond(l, result, nil, subject, why, started)
	}

	result, err := s.run(ctx, l, account, subject, argv, request.Stdin)
	return s.respond(l, result, err, subject, why, started)
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

func (s *Service) respond(l *link, result opcli.Result, err error, subject string, why decision, started time.Time) *opResponse {
	if err != nil {
		return &opResponse{Exit: ExitProxyError, Error: err.Error()}
	}
	l.allowed(subject, why, time.Since(started))
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
//
// A reference with a query is never cached. The query picks *which value* of
// a field comes back, and the commonest one, `?attribute=otp`, is a one-time
// code that changes every thirty seconds: cached for the configured TTL, a
// retry after the code's window would be handed a dead code that a direct
// `op read` would not give. The other queries are rare enough that telling the
// static ones from the time-varying ones is not worth getting wrong, so the
// classification is the conservative one — no query, or no cache.
func cacheKey(account string, argv []string) (string, bool) {
	if len(argv) != 2 || argv[0] != "read" {
		return "", false
	}
	ref, err := opref.Parse(argv[1])
	if err != nil || ref.Query != "" {
		return "", false
	}
	return account + "\x00" + ref.String(), true
}

// otherRefusal checks the request's other identities for a deny.
//
// A request reaching an account has two names: the scoped one,
// `[work] op://…`, and the bare reference. Allows are matched on subject alone
// — bare for the default account, scoped otherwise — so a bare allow means the
// default account and nothing more. Denies are different: any deny on either
// name refuses. A deny written as a bare reference is about the item wherever
// it lives, and a deny written for `[work]` is about the work account even
// when work is the default — if it were not, making an account the default
// would quietly switch off every deny written for it. subject itself has
// already been, or is about to be, authorised normally; this checks the rest.
//
// Only a deny something actually said counts, a rule or a "stop asking": the
// unmatched policy would otherwise refuse every request whose other name
// simply has no rule. The identities are evaluated one Decide at a time, so a
// rule edited in the instant between two of them is seen by one and not the
// other; either way the request is evaluated against rules that existed.
func (s *Service) otherRefusal(l *link, subject string, identities ...string) *opResponse {
	for _, identity := range identities {
		if identity == subject {
			continue
		}
		v := s.gate.Decide(l.host, identity)
		if v.Action != authz.ActionDeny || (v.By.Kind != authz.ByRule && v.By.Kind != authz.ByGrant) {
			continue
		}
		why := decision{reason: v.Reason, by: v.By}
		l.denied(subject, why)
		return &opResponse{Exit: ExitDenied, Error: "denied by devtun: " + why.reason}
	}
	return nil
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
		// The account is resolved before policy here too: `op run` and `op
		// inject` reach routed vaults exactly as `op read` does, and a scoped
		// deny has to hold for them as well.
		bare := ref.String()
		account := s.opts.Accounts.For(bare)
		subject := s.opts.Accounts.Scope(account, bare)
		l.requested(subject)
		if refused := s.otherRefusal(l, subject, opref.Scoped(account, bare), bare); refused != nil {
			return refused
		}

		argv := []string{"read", bare}
		allowed, why, until := s.authorize(ctx, l, subject, argv)
		if !allowed {
			l.denied(subject, why)
			return &opResponse{Exit: ExitDenied, Error: fmt.Sprintf("denied by devtun: %s (%s)", subject, why.reason)}
		}

		started := time.Now()

		key, cacheable := cacheKey(account, argv)
		if cached, hit := s.cache.Get(key); cacheable && hit {
			l.cached(subject, why)
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
		if cacheable {
			s.cache.Put(key, result.Stdout, until)
		}
		l.allowed(subject, why, time.Since(started))
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
func (s *Service) authorize(ctx context.Context, l *link, subject string, argv []string) (allowed bool, why decision, until time.Time) {
	asked := s.gate.Authorize(ctx, prompt.Request{
		Service: "1password",
		Host:    l.host,
		Subject: subject,
		Noun:    "secret",
		Caller:  l.caller,
		// The command is shown so an unusual request is visible: `op read` and
		// `op item get` reach the same secret, but a shape you did not expect
		// is worth seeing before approving it.
		Rows: []prompt.Row{{Label: "command", Value: "op " + strings.Join(argv, " ")}},
	})

	if asked.Err != nil {
		l.failed(subject, "could not save the rule: "+asked.Err.Error())
	} else if asked.Note != "" {
		l.event("saved", event.Info, asked.Note)
	}
	return asked.Allowed, decision{reason: asked.Reason, by: asked.By}, asked.Until
}

// decision is why a request went the way it did: the sentence for a person, and
// what decided, for the record.
type decision struct {
	reason string
	by     authz.Decider
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
func (l *link) allowed(subject string, why decision, elapsed time.Duration) {
	l.event("allowed", event.Info,
		fmt.Sprintf("gave %s %s (%s)", l.host, subject, why.reason),
		append([]any{"host", l.host, "subject", subject, "why", why.reason, "took", elapsed.Round(time.Millisecond)}, why.by.Fields()...)...)
}

// cached records a request satisfied from memory. It is its own kind because
// "this secret did not leave the vault again" is a different fact from "this
// secret was fetched", and the record should not blur them.
func (l *link) cached(subject string, why decision) {
	l.event("cached", event.Info, fmt.Sprintf("gave %s %s from cache", l.host, subject),
		append([]any{"host", l.host, "subject", subject, "why", why.reason}, why.by.Fields()...)...)
}

// denied records a refusal. Refusals are Info rather than Warn: denying is the
// system working, not failing.
func (l *link) denied(subject string, why decision) {
	l.event("denied", event.Info,
		fmt.Sprintf("refused %s %s — %s", l.host, subject, why.reason),
		append([]any{"host", l.host, "subject", subject, "why", why.reason}, why.by.Fields()...)...)
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
