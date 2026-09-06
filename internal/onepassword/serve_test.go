package onepassword

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/onepassword/opcli"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// fakeRunner stands in for the 1Password CLI. Recording the calls is the point:
// most of what is worth asserting is *whether* the vault was touched at all.
type fakeRunner struct {
	mu       sync.Mutex
	secrets  map[string]string
	version  string
	versErr  error
	execs    [][]string
	accounts []string
}

func (f *fakeRunner) Run(_ context.Context, account string, argv []string, _ []byte) (opcli.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(argv) == 1 && argv[0] == "--version" {
		if f.versErr != nil {
			return opcli.Result{}, f.versErr
		}
		return opcli.Result{Stdout: []byte(f.version + "\n")}, nil
	}

	f.execs = append(f.execs, argv)
	f.accounts = append(f.accounts, account)
	if len(argv) == 2 && argv[0] == "read" {
		value, ok := f.secrets[argv[1]]
		if !ok {
			return opcli.Result{Exit: 1, Stderr: []byte("no such item")}, nil
		}
		return opcli.Result{Stdout: []byte(value + "\n")}, nil
	}
	return opcli.Result{Stdout: []byte("ok\n")}, nil
}

// callCounts reports how many commands ran in total and how many of those
// actually consulted the vault for a secret — the number the caching tests care
// about.
func (f *fakeRunner) callCounts() (execs, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, argv := range f.execs {
		if len(argv) == 2 && argv[0] == "read" {
			reads++
		}
	}
	return len(f.execs), reads
}

func (f *fakeRunner) reads() int {
	_, reads := f.callCounts()
	return reads
}

func (f *fakeRunner) accountsUsed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.accounts))
	copy(out, f.accounts)
	return out
}

// scriptedPrompter answers with a fixed choice and counts how often it was
// asked, which is how the tests check that grants actually suppress prompting.
type scriptedPrompter struct {
	mu     sync.Mutex
	choice prompt.Choice
	err    error
	asked  int
}

func (s *scriptedPrompter) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	return s.choice, s.err
}

func (s *scriptedPrompter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

func (s *scriptedPrompter) answer(choice prompt.Choice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.choice = choice
}

type harness struct {
	service  *Service
	runner   *fakeRunner
	prompter *scriptedPrompter
	host     *fakeHost
	caller   service.Caller
}

// start builds a service and attaches it to a host with no SSH connection
// behind it, then serves each request over a pipe the way the session does — so
// the tests exercise the framing and the decision logic together rather than
// one at a time.
func start(t *testing.T, opts Options, secrets map[string]string) *harness {
	t.Helper()

	runner := &fakeRunner{secrets: secrets, version: "2.30.0"}
	// A test that brings its own prompter keeps it; one that does not gets a
	// scripted one, so the prompt count is always something to assert on.
	prompter, _ := opts.Prompter.(*scriptedPrompter)
	if opts.Prompter == nil {
		prompter = &scriptedPrompter{}
		opts.Prompter = prompter
	}
	opts.Runner = runner

	host := newFakeHost("devbox")
	svc := New(opts)
	instance, err := svc.Attach(context.Background(), host)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return &harness{
		service:  svc,
		runner:   runner,
		prompter: prompter,
		host:     host,
		caller:   service.Caller{Version: "test", User: "jsc", Host: "devbox", PID: 42, Program: "deploy.sh"},
	}
}

// allowAll is the policy most tests want: the interesting refusals then come
// from the guard or the prompt rather than from a rule.
func allowAll() Options {
	return Options{Rules: []authz.Rule{{Host: "**", Subject: "**", Action: authz.ActionAllow}}}
}

// send serves one request on its own connection and returns the reply.
func (h *harness) send(t *testing.T, request opRequest) opResponse {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()

	served := make(chan error, 1)
	go func() { served <- h.service.HandleConn(context.Background(), server, h.caller) }()

	if err := shim.WriteFrame(client, request); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	var response opResponse
	if err := shim.ReadFrame(client, &response); err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("HandleConn: %v", err)
	}
	return response
}

func (h *harness) exec(t *testing.T, argv ...string) opResponse {
	t.Helper()
	return h.send(t, opRequest{Op: opExec, Argv: argv})
}

func (h *harness) resolve(t *testing.T, refs ...string) opResponse {
	t.Helper()
	return h.send(t, opRequest{Op: opResolve, Refs: refs})
}

func TestReadIsForwardedWhenPolicyAllows(t *testing.T) {
	opts := Options{Rules: []authz.Rule{{Host: "devbox", Subject: "op://Personal/**", Action: authz.ActionAllow}}}
	h := start(t, opts, map[string]string{"op://Personal/Docker/PAT": "ghp_secret"})

	response := h.exec(t, "read", "op://Personal/Docker/PAT")
	if response.Exit != 0 {
		t.Fatalf("exit = %d, error = %q", response.Exit, response.Error)
	}
	if strings.TrimSpace(string(response.Stdout)) != "ghp_secret" {
		t.Errorf("stdout = %q, want the secret", response.Stdout)
	}
	if h.prompter.count() != 0 {
		t.Errorf("a rule should mean no prompt, but the user was asked %d times", h.prompter.count())
	}
	if kinds := h.host.events.kinds(); !reflect.DeepEqual(kinds, []string{"requested", "allowed"}) {
		t.Errorf("events = %v, want requested then allowed", kinds)
	}
}

func TestDeniedRequestNeverReachesTheVault(t *testing.T) {
	opts := Options{Rules: []authz.Rule{{Host: "**", Subject: "op://Personal/**", Action: authz.ActionDeny}}}
	opts.Prompter = &scriptedPrompter{choice: prompt.ChoiceAllowOnce}
	h := start(t, opts, map[string]string{"op://Personal/Docker/PAT": "ghp_secret"})

	response := h.exec(t, "read", "op://Personal/Docker/PAT")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if strings.Contains(string(response.Stdout), "ghp_secret") {
		t.Fatal("a denied request leaked the secret")
	}
	if !strings.Contains(response.Error, "denied by devtun") {
		t.Errorf("error = %q, want it to say the request was denied", response.Error)
	}
	if execs, reads := h.runner.callCounts(); execs != 0 || reads != 0 {
		t.Errorf("op was called %d times (%d reads) for a denied request", execs, reads)
	}
	if h.prompter.count() != 0 {
		t.Error("a deny rule must not reach the prompt")
	}
}

// The guard runs before policy, so a blocked command must be refused even when
// a rule would otherwise have allowed the subject.
func TestGuardBlocksBeforePolicyIsConsulted(t *testing.T) {
	h := start(t, allowAll(), nil)

	response := h.exec(t, "item", "delete", "Docker")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if !strings.Contains(response.Error, "allowlist") {
		t.Errorf("error = %q, want the allowlist explanation", response.Error)
	}
	if execs, _ := h.runner.callCounts(); execs != 0 {
		t.Error("a command blocked by the guard still reached op")
	}
	// The guard refuses on shape alone, so nothing was ever "requested" of the
	// vault; the record should say denied and nothing else.
	if kinds := h.host.events.kinds(); !reflect.DeepEqual(kinds, []string{"denied"}) {
		t.Errorf("events = %v, want a single denial", kinds)
	}
}

func TestOutFileFlagIsRefused(t *testing.T) {
	h := start(t, allowAll(), map[string]string{"op://Personal/Docker/PAT": "ghp_secret"})

	response := h.exec(t, "read", "op://Personal/Docker/PAT", "--out-file", "/tmp/leak")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if !strings.Contains(response.Error, "not allowed through the proxy") {
		t.Errorf("error = %q", response.Error)
	}
}

// Answering "allow this secret for a while" must suppress the next prompt for
// the same secret and only that secret.
func TestTemporaryGrantSuppressesRepeatPrompts(t *testing.T) {
	opts := Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretTTL}}
	h := start(t, opts, map[string]string{
		"op://Personal/Docker/PAT": "ghp_secret",
		"op://Personal/Other/key":  "other",
	})

	for i := 0; i < 3; i++ {
		if response := h.exec(t, "read", "op://Personal/Docker/PAT"); response.Exit != 0 {
			t.Fatalf("attempt %d: exit = %d, error = %q", i, response.Exit, response.Error)
		}
	}
	if got := h.prompter.count(); got != 1 {
		t.Errorf("asked %d times, want 1", got)
	}

	if response := h.exec(t, "read", "op://Personal/Other/key"); response.Exit != 0 {
		t.Fatalf("second secret: exit = %d, error = %q", response.Exit, response.Error)
	}
	if got := h.prompter.count(); got != 2 {
		t.Errorf("a grant for one secret should not cover another; asked %d times, want 2", got)
	}
}

func TestRefusalAtThePromptIsDenied(t *testing.T) {
	opts := Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceDeny}}
	h := start(t, opts, map[string]string{"op://V/I/F": "s"})

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if len(response.Stdout) != 0 {
		t.Fatalf("stdout = %q, want nothing", response.Stdout)
	}
}

// With nobody to ask there is no answer, and the request must fail rather than
// hang or default to yes. A caller that passes no prompter at all gets this.
func TestNoPrompterMeansDenied(t *testing.T) {
	host := newFakeHost("devbox")
	runner := &fakeRunner{version: "2.30.0", secrets: map[string]string{"op://V/I/F": "s"}}
	// No prompter at all: the service's own default has to be the refusing one.
	svc := New(Options{Runner: runner})
	if _, err := svc.Attach(context.Background(), host); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	h := &harness{service: svc, runner: runner, host: host}

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if !strings.Contains(response.Error, "interactive terminal") {
		t.Errorf("error = %q, want it to explain that nobody could be asked", response.Error)
	}
	if execs, _ := h.runner.callCounts(); execs != 0 {
		t.Error("op ran for a request nobody approved")
	}
}

// A prompt nobody answers is a refusal, and it must be one that says so rather
// than stalling the script on the remote box for ever.
func TestPromptTimeoutIsARefusal(t *testing.T) {
	opts := Options{
		PromptTimeout: 20 * time.Millisecond,
		Prompter:      prompt.Prompter(&hangingPrompter{}),
	}
	h := start(t, opts, map[string]string{"op://V/I/F": "s"})

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if !strings.Contains(response.Error, "no answer within") {
		t.Errorf("error = %q, want it to say nobody answered", response.Error)
	}
}

// hangingPrompter never answers, which is what a prompt on a screen nobody is
// looking at amounts to.
type hangingPrompter struct{}

func (hangingPrompter) Ask(ctx context.Context, _ prompt.Request) (prompt.Choice, error) {
	<-ctx.Done()
	return prompt.ChoiceDeny, ctx.Err()
}

func TestPing(t *testing.T) {
	h := start(t, Options{}, nil)

	response := h.send(t, opRequest{Op: opPing})
	if response.Exit != 0 || response.Error != "" {
		t.Fatalf("ping = %+v, want an empty reply", response)
	}
	if execs, _ := h.runner.callCounts(); execs != 0 {
		t.Error("a ping touched the vault")
	}
}

func TestUnknownRequestKindIsRefused(t *testing.T) {
	h := start(t, allowAll(), nil)

	response := h.send(t, opRequest{Op: "sudo"})
	if response.Exit != ExitProxyError {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitProxyError)
	}
	if !strings.Contains(response.Error, "unknown request type") {
		t.Errorf("error = %q", response.Error)
	}
}

// One request per connection is an isolation property, not an accident: a
// client that wedges mid-stream can poison nothing but itself.
func TestOneRequestPerConnection(t *testing.T) {
	h := start(t, allowAll(), map[string]string{"op://V/I/F": "s3cret"})

	client, server := net.Pipe()
	defer client.Close()
	served := make(chan error, 1)
	go func() { served <- h.service.HandleConn(context.Background(), server, h.caller) }()

	if err := shim.WriteFrame(client, opRequest{Op: opExec, Argv: []string{"read", "op://V/I/F"}}); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	var response opResponse
	if err := shim.ReadFrame(client, &response); err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("HandleConn: %v", err)
	}

	// The second request has nowhere to go: the handler has closed its end.
	err := shim.WriteFrame(client, opRequest{Op: opExec, Argv: []string{"read", "op://V/I/F"}})
	if err == nil {
		if readErr := shim.ReadFrame(client, &response); readErr == nil {
			t.Fatal("a second request on the same connection was served")
		}
	}
	if reads := h.runner.reads(); reads != 1 {
		t.Errorf("op read ran %d times, want 1", reads)
	}
}

// Decisions come from the SSH destination and the command. What the shim says
// about itself is displayed and nothing more — so a caller claiming to be a
// host with a rule must not get that host's rule.
func TestDecisionsIgnoreWhatTheCallerClaims(t *testing.T) {
	opts := Options{
		Rules:    []authz.Rule{{Host: "trusted", Subject: "**", Action: authz.ActionAllow}},
		Prompter: &scriptedPrompter{choice: prompt.ChoiceDeny},
	}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})
	h.caller = service.Caller{Version: "test", User: "root", Host: "trusted", Program: "trusted"}

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d — a rule was matched against the caller's own claim", response.Exit, ExitDenied)
	}
	if h.prompter.count() != 1 {
		t.Errorf("asked %d times, want 1: the claim should have changed nothing", h.prompter.count())
	}

	// It is still shown, because it is what makes an approval decidable.
	var from string
	for _, e := range h.host.events.all() {
		if e.Kind != "requested" {
			continue
		}
		for i := 0; i+1 < len(e.Fields); i += 2 {
			if e.Fields[i] == "from" {
				from, _ = e.Fields[i+1].(string)
			}
		}
	}
	if !strings.Contains(from, "root@trusted") {
		t.Errorf("the request event says it came from %q, want the caller's own account of itself", from)
	}
}

// ---- resolve ----

// A batch is resolved in one round trip, so a twenty-reference template costs a
// handful of prompts rather than twenty and one exchange rather than twenty.
func TestResolveReturnsTheWholeBatch(t *testing.T) {
	h := start(t, allowAll(), map[string]string{
		"op://V/I/F": "s3cret",
		"op://V/I/G": "other",
	})

	response := h.resolve(t, "op://V/I/F", "op://V/I/G")
	if response.Exit != 0 {
		t.Fatalf("exit = %d, error = %q", response.Exit, response.Error)
	}
	want := map[string]string{"op://V/I/F": "s3cret", "op://V/I/G": "other"}
	if !reflect.DeepEqual(response.Secrets, want) {
		t.Errorf("secrets = %v, want %v", response.Secrets, want)
	}
	if reads := h.runner.reads(); reads != 2 {
		t.Errorf("op read ran %d times for two references, want 2", reads)
	}
}

// A denied reference must fail the whole batch: a config file that is
// three-quarters filled in is a deploy-time failure with no obvious cause.
func TestResolveIsAllOrNothing(t *testing.T) {
	opts := Options{Rules: []authz.Rule{
		{Host: "**", Subject: "op://Personal/Docker/**", Action: authz.ActionAllow},
		{Host: "**", Subject: "op://Personal/Root/**", Action: authz.ActionDeny},
	}}
	h := start(t, opts, map[string]string{
		"op://Personal/Docker/PAT": "ghp_secret",
		"op://Personal/Root/key":   "very-secret",
	})

	response := h.resolve(t, "op://Personal/Docker/PAT", "op://Personal/Root/key")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if len(response.Secrets) != 0 {
		t.Errorf("secrets = %v, want none: a refused batch hands back nothing", response.Secrets)
	}
	if !strings.Contains(response.Error, "denied") {
		t.Errorf("error = %q", response.Error)
	}
}

func TestResolveRefusesAMalformedReference(t *testing.T) {
	h := start(t, allowAll(), nil)

	response := h.resolve(t, "op://V")
	if response.Exit != ExitProxyError {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitProxyError)
	}
	if execs, _ := h.runner.callCounts(); execs != 0 {
		t.Error("a malformed reference reached op")
	}
}

// ---- caching ----

func TestCacheServesRepeatedReadsWithoutCallingOp(t *testing.T) {
	opts := allowAll()
	opts.CacheTTL = time.Minute
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	for i := 0; i < 4; i++ {
		response := h.exec(t, "read", "op://V/I/F")
		if response.Exit != 0 {
			t.Fatalf("attempt %d: exit = %d, error = %q", i, response.Exit, response.Error)
		}
		if strings.TrimSpace(string(response.Stdout)) != "s3cret" {
			t.Fatalf("attempt %d: stdout = %q", i, response.Stdout)
		}
	}
	if reads := h.runner.reads(); reads != 1 {
		t.Errorf("op read ran %d times for four identical requests, want 1", reads)
	}
	if kinds := h.host.events.kinds(); kinds[len(kinds)-1] != "cached" {
		t.Errorf("last event = %q, want a cache hit to say so", kinds[len(kinds)-1])
	}
}

// A cached value must not outlive the grant that authorised it, even when the
// cache TTL is much longer: the entry expires at the earlier of the two.
func TestCachedValuesDieWithTheirGrant(t *testing.T) {
	opts := Options{
		DefaultTTL: 40 * time.Millisecond,
		CacheTTL:   time.Hour,
		Prompter:   &scriptedPrompter{choice: prompt.ChoiceAllowSecretTTL},
	}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("first read: exit = %d, error = %q", response.Exit, response.Error)
	}

	// The grant lapses; the cache's own TTL still has an hour to run.
	time.Sleep(80 * time.Millisecond)
	h.prompter.answer(prompt.ChoiceDeny)

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d — a lapsed grant was satisfied from cache", response.Exit, ExitDenied)
	}
	if strings.Contains(string(response.Stdout), "s3cret") {
		t.Fatal("the cache served a secret to a denied request")
	}
}

// And the cache is read only *after* authorize has allowed the request, never
// in place of it. That is a separate claim from the one above, and it needs a
// live entry to test: a session grant has no expiry of its own, so the value is
// cached for the full hour. Dropping the grant alone — without purging — leaves
// exactly the state an ordering mistake would serve from.
func TestCacheIsNeverServedWithoutReauthorising(t *testing.T) {
	opts := Options{
		CacheTTL: time.Hour,
		Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession},
	}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("first read: exit = %d, error = %q", response.Exit, response.Error)
	}
	if h.service.cache.Len() != 1 {
		t.Fatal("the value was not cached, so this test would prove nothing")
	}

	h.service.store.ForgetGrants() // the authorisation goes; the entry stays
	h.prompter.answer(prompt.ChoiceDeny)

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d — the cache answered instead of policy", response.Exit, ExitDenied)
	}
	if strings.Contains(string(response.Stdout), "s3cret") {
		t.Fatal("a live cache entry was served to a request that was refused")
	}
}

// "Allow once" authorises exactly one request, so it must leave nothing behind
// for the next one to reuse.
func TestAllowOnceDoesNotPopulateTheCache(t *testing.T) {
	opts := Options{CacheTTL: time.Hour, Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowOnce}}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	for i := 0; i < 2; i++ {
		if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
			t.Fatalf("attempt %d: exit = %d, error = %q", i, response.Exit, response.Error)
		}
	}
	if h.prompter.count() != 2 {
		t.Errorf("asked %d times, want 2 — allow-once must not be reusable", h.prompter.count())
	}
	if reads := h.runner.reads(); reads != 2 {
		t.Errorf("op read ran %d times, want 2 — nothing should have been cached", reads)
	}
}

// Only a bare `op read <ref>` has an output that is a single unchanging secret.
// Anything that lists, or that carries extra flags, has to run every time.
func TestOnlyBareReadsAreCached(t *testing.T) {
	opts := allowAll()
	opts.CacheTTL = time.Minute
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	for i := 0; i < 3; i++ {
		if response := h.exec(t, "item", "list", "--vault", "V"); response.Exit != 0 {
			t.Fatalf("exit = %d, error = %q", response.Exit, response.Error)
		}
	}
	if execs, _ := h.runner.callCounts(); execs != 3 {
		t.Errorf("`item list` ran %d times, want 3 — listings must not be cached", execs)
	}
}

func TestCacheAlsoServesResolve(t *testing.T) {
	opts := allowAll()
	opts.CacheTTL = time.Minute
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("read: exit = %d, error = %q", response.Exit, response.Error)
	}

	response := h.resolve(t, "op://V/I/F")
	if response.Exit != 0 {
		t.Fatalf("resolve: exit = %d, error = %q", response.Exit, response.Error)
	}
	if got := response.Secrets["op://V/I/F"]; got != "s3cret" {
		t.Errorf("secret = %q, want the value without its trailing newline", got)
	}
	if reads := h.runner.reads(); reads != 1 {
		t.Errorf("op read ran %d times, want 1 — resolve should reuse the cached value", reads)
	}
}

func TestForgetDropsGrantsAndCachedValues(t *testing.T) {
	opts := Options{CacheTTL: time.Hour, Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("exit = %d, error = %q", response.Exit, response.Error)
	}
	grants, cached := h.service.Forget()
	if grants != 1 || cached != 1 {
		t.Fatalf("Forget() = %d grants, %d cached; want 1 and 1", grants, cached)
	}

	// With the grant gone the next request is asked about again, and refusing
	// it must not be answerable from what the last one left in memory.
	h.prompter.answer(prompt.ChoiceDeny)
	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if strings.Contains(string(response.Stdout), "s3cret") {
		t.Fatal("a purged value was still served")
	}
}

// ---- multiple accounts ----

func TestAccountRoutingByVault(t *testing.T) {
	opts := allowAll()
	opts.Accounts = Accounts{
		Default: "adipose.1password.com",
		ByVault: map[string]string{"Barreleye": "barreleyesoftware.1password.com"},
	}
	h := start(t, opts, map[string]string{
		"op://Barreleye/CI/token": "work",
		"op://Private/Docker/PAT": "personal",
	})

	if response := h.exec(t, "read", "op://Barreleye/CI/token"); response.Exit != 0 {
		t.Fatalf("work vault: exit = %d, error = %q", response.Exit, response.Error)
	}
	if response := h.exec(t, "read", "op://Private/Docker/PAT"); response.Exit != 0 {
		t.Fatalf("personal vault: exit = %d, error = %q", response.Exit, response.Error)
	}

	accounts := h.runner.accountsUsed()
	want := []string{"barreleyesoftware.1password.com", "adipose.1password.com"}
	if !reflect.DeepEqual(accounts, want) {
		t.Errorf("accounts used = %v, want %v", accounts, want)
	}
}

// Two accounts can hold a vault of the same name, so the cache has to keep them
// apart or one account's secret would be served for the other's reference.
func TestCacheKeysAreScopedToTheAccount(t *testing.T) {
	opts := allowAll()
	opts.CacheTTL = time.Minute
	opts.Accounts = Accounts{
		Default: "personal.1password.com",
		ByVault: map[string]string{"Shared": "work.1password.com"},
	}
	h := start(t, opts, map[string]string{
		"op://Shared/I/F": "work-value",
		"op://Other/I/F":  "personal-value",
	})

	if response := h.exec(t, "read", "op://Shared/I/F"); strings.TrimSpace(string(response.Stdout)) != "work-value" {
		t.Fatalf("stdout = %q", response.Stdout)
	}
	if response := h.exec(t, "read", "op://Other/I/F"); strings.TrimSpace(string(response.Stdout)) != "personal-value" {
		t.Fatalf("stdout = %q — a cached value crossed accounts", response.Stdout)
	}
	if reads := h.runner.reads(); reads != 2 {
		t.Errorf("op read ran %d times, want 2 — the references are distinct", reads)
	}
}

// ---- probe, attach and persistence ----

func TestProbeNeedsAWorkingLocalOp(t *testing.T) {
	runner := &fakeRunner{version: "2.30.0"}
	support := New(Options{Runner: runner}).Probe(context.Background(), newFakeHost("devbox"))
	if !support.OK {
		t.Fatalf("Probe = %+v, want it supported", support)
	}
	if !strings.Contains(support.Detail, "2.30.0") {
		t.Errorf("detail = %q, want the op version", support.Detail)
	}

	broken := &fakeRunner{versErr: errors.New("op is locked")}
	support = New(Options{Runner: broken}).Probe(context.Background(), newFakeHost("devbox"))
	if support.OK {
		t.Fatal("Probe reported a broken op as usable")
	}
	// The reason must lead with what is wrong and carry op's own words, so the
	// actionable part survives a narrow column.
	if !strings.Contains(support.Reason, "op") || !strings.Contains(support.Reason, "op is locked") {
		t.Errorf("reason = %q, want it to name the problem", support.Reason)
	}
}

// What this service needs is a vault here, not a CLI there — a remote box with
// no `op` on it at all is the case the whole tool exists for.
func TestProbeIgnoresTheRemoteBox(t *testing.T) {
	host := newFakeHost("devbox")
	host.facts.Tools = map[string]string{} // no op, no anything

	if support := New(Options{Runner: &fakeRunner{version: "2.30.0"}}).Probe(context.Background(), host); !support.OK {
		t.Fatalf("Probe = %+v, want it supported without op on the remote box", support)
	}
}

// Rules written on a previous run are in the host's config document, and they
// have to be in force before the first request rather than after the first
// prompt.
func TestAttachAdoptsTheHostsOwnRules(t *testing.T) {
	host := newFakeHost("devbox")
	host.config.seed(t, rulesKey, []authz.Rule{
		{Host: "devbox", Subject: "op://V/I/F", Action: authz.ActionDeny},
	})

	runner := &fakeRunner{version: "2.30.0", secrets: map[string]string{"op://V/I/F": "s3cret"}}
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowOnce}
	svc := New(Options{Runner: runner, Prompter: prompter})
	if _, err := svc.Attach(context.Background(), host); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	h := &harness{service: svc, runner: runner, prompter: prompter, host: host}

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != ExitDenied {
		t.Fatalf("exit = %d, want %d", response.Exit, ExitDenied)
	}
	if prompter.count() != 0 {
		t.Error("a persisted deny must not reach the prompt")
	}
}

// Rules that cannot be read include denies, so carrying on without them would
// silently widen access. Refusing to attach is the only safe reading.
func TestAttachRefusesUnreadableRules(t *testing.T) {
	host := newFakeHost("devbox")
	host.config.getErr = errors.New("yaml: line 3: mapping values are not allowed")

	if _, err := New(Options{Runner: &fakeRunner{}}).Attach(context.Background(), host); err == nil {
		t.Fatal("Attach = nil, want a refusal to run without the host's rules")
	}
}

// "Always" has to reach the host's config, and it has to hold for the next
// request without another prompt.
func TestAlwaysWritesARuleToTheHostConfig(t *testing.T) {
	opts := Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretAlways}}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("exit = %d, error = %q", response.Exit, response.Error)
	}
	if h.host.config.writes() != 1 {
		t.Errorf("the host config was written %d times, want 1", h.host.config.writes())
	}

	var stored []authz.Rule
	if _, err := h.host.config.Get(rulesKey, &stored); err != nil {
		t.Fatalf("reading back the rules: %v", err)
	}
	if len(stored) != 1 || stored[0].Subject != "op://V/I/F" || stored[0].Action != authz.ActionAllow {
		t.Fatalf("stored rules = %+v", stored)
	}

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("second read: exit = %d, error = %q", response.Exit, response.Error)
	}
	if h.prompter.count() != 1 {
		t.Errorf("asked %d times, want 1 — the saved rule should cover the second read", h.prompter.count())
	}
}

// The user said yes. A config that will not take the rule is worth reporting,
// but it must not turn an approval into a refusal — the worst case is being
// asked again.
func TestApprovalSurvivesAFailedRuleSave(t *testing.T) {
	opts := Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretAlways}}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})
	h.host.config.setErr = errors.New("read-only config")

	response := h.exec(t, "read", "op://V/I/F")
	if response.Exit != 0 {
		t.Fatalf("exit = %d, error = %q — a failed save undid the approval", response.Exit, response.Error)
	}
	if strings.TrimSpace(string(response.Stdout)) != "s3cret" {
		t.Errorf("stdout = %q", response.Stdout)
	}
	var failed bool
	for _, e := range h.host.events.all() {
		if e.Kind == "failed" {
			failed = true
		}
	}
	if !failed {
		t.Error("the failure to save was not reported")
	}
}

// A reconnect is a Close and a fresh Attach, and policy must not notice: a
// grant given a minute ago still stands.
func TestGrantsSurviveAReconnect(t *testing.T) {
	opts := Options{Prompter: &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}}
	h := start(t, opts, map[string]string{"op://V/I/F": "s3cret"})

	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("exit = %d, error = %q", response.Exit, response.Error)
	}
	if _, err := h.service.Attach(context.Background(), h.host); err != nil {
		t.Fatalf("re-Attach: %v", err)
	}
	if response := h.exec(t, "read", "op://V/I/F"); response.Exit != 0 {
		t.Fatalf("after reconnect: exit = %d, error = %q", response.Exit, response.Error)
	}
	if h.prompter.count() != 1 {
		t.Errorf("asked %d times, want 1 — a reconnect must be invisible to policy", h.prompter.count())
	}
}

func TestMeta(t *testing.T) {
	meta := New(Options{}).Meta()
	if meta.ID != "1password" || meta.Title != "1Password" || meta.Glyph != "🔒" {
		t.Errorf("meta = %+v", meta)
	}
	if meta.Class != event.Security {
		t.Errorf("class = %q, want security", meta.Class)
	}
}

// A frame that announces more than the cap is refused before anything is
// allocated for it, and the connection dies with it. Nothing about the request
// was understood, so nothing about the vault may happen.
func TestAnOversizedFrameIsRefused(t *testing.T) {
	h := start(t, allowAll(), map[string]string{"op://V/I/F": "s3cret"})

	client, server := net.Pipe()
	defer client.Close()
	served := make(chan error, 1)
	go func() { served <- h.service.HandleConn(context.Background(), server, h.caller) }()

	if _, err := client.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatalf("writing the header: %v", err)
	}
	if err := <-served; err == nil {
		t.Fatal("HandleConn = nil, want a refusal of the oversized frame")
	}
	if execs, _ := h.runner.callCounts(); execs != 0 {
		t.Error("op ran for a request that was never read")
	}
}

// The TUI's modal cannot exist until the Bubble Tea program does, which is
// after this service. Without a setter, New's deliberate nil-becomes-DenyAll
// substitution would be permanent and every request under --tui would be
// refused with no way to say yes.
func TestSetPrompterReplacesTheDefaultRefusal(t *testing.T) {
	svc := New(Options{})

	if _, err := svc.prompter.Ask(context.Background(), prompt.Request{}); err == nil {
		t.Fatal("a service built with no prompter should refuse")
	}

	svc.SetPrompter(allowOncePrompter{})

	choice, err := svc.prompter.Ask(context.Background(), prompt.Request{})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if choice != prompt.ChoiceAllowOnce {
		t.Errorf("want the installed prompter to answer, got %v", choice)
	}
}

// Installing nil must not open the door: the zero value of a decision is no.
func TestSetPrompterNilStillRefuses(t *testing.T) {
	svc := New(Options{Prompter: allowOncePrompter{}})
	svc.SetPrompter(nil)

	choice, _ := svc.prompter.Ask(context.Background(), prompt.Request{})
	if choice != prompt.ChoiceDeny {
		t.Errorf("installing nil must refuse, got %v", choice)
	}
}

type allowOncePrompter struct{}

func (allowOncePrompter) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	return prompt.ChoiceAllowOnce, nil
}

// The only actionable words must come first: the Services tab clamps this to
// the column width, and a reason that leads with prose puts the fix off-screen.
func TestMissingOpSaysHowToInstallItFirst(t *testing.T) {
	svc := New(Options{OpPath: "/nonexistent/op-does-not-exist"})

	support := svc.Probe(context.Background(), nil)

	if support.OK {
		t.Fatal("a missing op cannot support the service")
	}
	if !strings.Contains(support.Reason, "1password-cli") {
		t.Errorf("the reason should name the fix, got %q", support.Reason)
	}
	if strings.Count(support.Reason, ":") > 1 {
		t.Errorf("the reason stacks clauses instead of saying one thing: %q", support.Reason)
	}
	// Not an error — a dev box without op is an ordinary dev box.
	if len(support.Reason) > 80 {
		t.Errorf("the reason will not fit a narrow column: %q", support.Reason)
	}
}

// An answer that races the prompt deadline must not become an allow.
//
// A select whose cases are both ready picks at random, so a prompter that
// returns a choice at the same instant its context fires can hand back an
// approval the deadline had already refused. This is the one decision where
// trusting the prompter to have got that right is not good enough.
func TestAnAnswerThatRacesTheDeadlineIsRefused(t *testing.T) {
	svc := New(Options{
		PromptTimeout: time.Millisecond,
		Runner:        &fakeRunner{},
		// Answers "allow", but only after its context has already expired.
		Prompter: lateAllowPrompter{},
	})

	l := &link{host: "bedev", events: event.Discard}
	allowed, reason, _ := svc.authorize(context.Background(), l,
		"op://Personal/Docker/PAT", []string{"read", "op://Personal/Docker/PAT"})

	if allowed {
		t.Fatal("an answer arriving after the deadline was treated as an approval")
	}
	if !strings.Contains(reason, "no answer within") {
		t.Errorf("the refusal should say it timed out, got %q", reason)
	}
}

// lateAllowPrompter waits for its deadline and then approves anyway, which is
// exactly the shape a racing prompter has.
type lateAllowPrompter struct{}

func (lateAllowPrompter) Ask(ctx context.Context, _ prompt.Request) (prompt.Choice, error) {
	<-ctx.Done()
	return prompt.ChoiceAllowSecretSession, nil
}
