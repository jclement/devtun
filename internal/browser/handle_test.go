package browser

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
	"github.com/jclement/devtun/internal/tunnels"
)

// exchange runs one open request through HandleConn over an in-process pipe.
func exchange(t *testing.T, svc *Service, request openRequest) openResponse {
	t.Helper()
	client, server := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = svc.HandleConn(context.Background(), server, service.Caller{Program: "vite"})
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := shim.WriteFrame(client, request); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	var response openResponse
	if err := shim.ReadFrame(client, &response); err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	client.Close()
	wg.Wait()
	return response
}

func TestHandleConnOpensARewrittenURL(t *testing.T) {
	var opened string
	svc := New(Options{
		Prompter: allowOnce{},
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174, Remapped: false}}},
		Open:     func(_ context.Context, u string) error { opened = u; return nil },
		Poll:     time.Millisecond,
		Wait:     50 * time.Millisecond,
	})

	got := exchange(t, svc, openRequest{URL: "http://localhost:5173/app"})

	if !got.OK {
		t.Fatalf("want success, got error %q", got.Error)
	}
	if opened != "http://localhost:5174/app" {
		t.Errorf("opened the wrong URL: %q", opened)
	}
}

// A refusal must come back as a reply, not a dropped connection: the shim on
// the far side prints it so the human can open the URL themselves.
func TestHandleConnReportsARefusalRatherThanHangingUp(t *testing.T) {
	svc := New(Options{
		Prompter: allowOnce{},
		Tunnels:  &fakeTunnels{},
		Open:     func(context.Context, string) error { return nil },
		Poll:     time.Millisecond,
		Wait:     50 * time.Millisecond,
	})

	got := exchange(t, svc, openRequest{URL: "http://localhost:9999/"})

	if got.OK {
		t.Fatal("an unforwarded port must not report success")
	}
	if !strings.Contains(got.Error, "9999") {
		t.Errorf("the reply should say what was wrong, got %q", got.Error)
	}
}

// A failure to launch the browser is the user's problem to hear about, not
// something to swallow into a success.
func TestHandleConnReportsALaunchFailure(t *testing.T) {
	svc := New(Options{
		Prompter: allowOnce{},
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 3000, LocalPort: 3000}}},
		Open:     func(context.Context, string) error { return errNoBrowser },
		Poll:     time.Millisecond,
		Wait:     50 * time.Millisecond,
	})

	got := exchange(t, svc, openRequest{URL: "http://localhost:3000/"})

	if got.OK {
		t.Fatal("a failed launch must not report success")
	}
	if !strings.Contains(got.Error, "no browser") {
		t.Errorf("the reply should carry the reason, got %q", got.Error)
	}
}

func TestAttachAndCloseAreQuiet(t *testing.T) {
	svc := New(Options{Open: func(context.Context, string) error { return nil }})
	inst, err := svc.Attach(context.Background(), newStubHost())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- inst.Run(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a cancelled Run should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if err := inst.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// stubHost is the smallest thing satisfying service.Host: this service uses
// the label, the event sink, and its slice of the host's config.
type stubHost struct {
	service.Host
	config *stubConfig
}

func newStubHost() stubHost { return stubHost{config: &stubConfig{docs: map[string]any{}}} }

func (stubHost) Label() string      { return "bedev" }
func (stubHost) Events() event.Sink { return event.Discard }

func (h stubHost) Config() service.Config {
	if h.config == nil {
		return &stubConfig{docs: map[string]any{}}
	}
	return h.config
}

// stubConfig is an in-memory config document.
type stubConfig struct{ docs map[string]any }

func (c *stubConfig) Get(key string, v any) (bool, error) { return c.GetLocal(key, v) }

func (c *stubConfig) GetLocal(key string, v any) (bool, error) {
	doc, ok := c.docs[key]
	if !ok {
		return false, nil
	}
	switch target := v.(type) {
	case *string:
		text, ok := doc.(string)
		if !ok {
			return false, nil
		}
		*target = text
	case *[]authz.Rule:
		rules, ok := doc.([]authz.Rule)
		if !ok {
			return false, nil
		}
		*target = rules
	default:
		return false, nil
	}
	return true, nil
}

func (c *stubConfig) Set(key string, v any) error { c.docs[key] = v; return nil }

var errNoBrowser = errNoBrowserType{}

type errNoBrowserType struct{}

func (errNoBrowserType) Error() string { return "no browser on this machine" }

// A browser window appearing because a process on another machine asked for it
// must never be a surprise: it has to be accountable afterwards.
func TestOpeningIsReported(t *testing.T) {
	bus := event.NewBus(8)
	svc := New(Options{
		Prompter: allowOnce{},
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:     func(context.Context, string) error { return nil },
		Poll:     time.Millisecond,
		Wait:     50 * time.Millisecond,
	})
	if _, err := svc.Attach(context.Background(), busHost{bus: bus}); err != nil {
		t.Fatal(err)
	}

	if got := exchange(t, svc, openRequest{URL: "http://localhost:5173/app"}); !got.OK {
		t.Fatalf("want success, got %q", got.Error)
	}

	var found bool
	for _, e := range bus.History() {
		if e.Kind == "opened" && e.Class == event.Network {
			found = true
			if !strings.Contains(e.Text, "5174") {
				t.Errorf("the event should name the URL actually opened, got %q", e.Text)
			}
			if !strings.Contains(e.Text, "vite") {
				t.Errorf("the event should name who asked, got %q", e.Text)
			}
		}
	}
	if !found {
		t.Errorf("opening a browser emitted nothing:\n%+v", bus.History())
	}
}

func TestRefusalIsReported(t *testing.T) {
	bus := event.NewBus(8)
	svc := New(Options{
		Prompter: allowOnce{},
		Tunnels:  &fakeTunnels{},
		Open:     func(context.Context, string) error { return nil },
		Poll:     time.Millisecond,
		Wait:     20 * time.Millisecond,
	})
	if _, err := svc.Attach(context.Background(), busHost{bus: bus}); err != nil {
		t.Fatal(err)
	}

	_ = exchange(t, svc, openRequest{URL: "http://localhost:9999/"})

	for _, e := range bus.History() {
		if e.Kind == "refused" && e.Level == event.Warn {
			return
		}
	}
	t.Errorf("a refusal should be reported too:\n%+v", bus.History())
}

type busHost struct {
	service.Host
	bus *event.Bus
}

func (h busHost) Label() string      { return "bedev" }
func (h busHost) Events() event.Sink { return h.bus.For("browser") }

func (h busHost) Config() service.Config { return &stubConfig{docs: map[string]any{}} }

// gating -------------------------------------------------------------------

// denyAll refuses everything, standing in for a person who says no.
type denyAll struct{}

func (denyAll) Ask(context.Context, prompt.Request) (prompt.Choice, error) {
	return prompt.ChoiceDeny, nil
}

// recorder remembers the question it was asked, so the wording can be checked:
// the wording is the thing somebody is deciding on.
type recorder struct {
	mu      sync.Mutex
	request prompt.Request
	answer  prompt.Choice
}

func (r *recorder) Ask(_ context.Context, request prompt.Request) (prompt.Choice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.request = request
	return r.answer, nil
}

func (r *recorder) seen() prompt.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.request
}

// A window appearing on your laptop because a process on another machine asked
// for it is a thing to be asked about, and refusing means it does not open.
func TestARefusedSiteIsNotOpened(t *testing.T) {
	opened := 0
	svc := New(Options{
		Prompter: denyAll{},
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:     func(context.Context, string) error { opened++; return nil },
	})
	if _, err := svc.Attach(context.Background(), asking()); err != nil {
		t.Fatal(err)
	}

	got := exchange(t, svc, openRequest{URL: "https://github.com/login"})
	if got.OK {
		t.Error("a refused request reported success")
	}
	if opened != 0 {
		t.Error("a refused URL was opened anyway")
	}
	if !strings.Contains(got.Error, "refused") {
		t.Errorf("the remote was not told why: %q", got.Error)
	}
}

// The question names the site, not the URL — a grant on github.com covers the
// dozen redirects an OAuth flow makes, where a grant on one URL would ask again
// at every one of them.
func TestTheQuestionIsAboutTheSite(t *testing.T) {
	asker := &recorder{answer: prompt.ChoiceAllowOnce}
	svc := New(Options{
		Prompter: asker,
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:     func(context.Context, string) error { return nil },
	})
	if _, err := svc.Attach(context.Background(), asking()); err != nil {
		t.Fatal(err)
	}

	exchange(t, svc, openRequest{URL: "https://github.com/login/oauth?code=abc"})
	request := asker.seen()
	if request.Subject != "github.com" {
		t.Errorf("subject = %q, want the site", request.Subject)
	}
	if request.Host != "bedev" {
		t.Errorf("host = %q, want the box that asked", request.Host)
	}
	if request.SubjectNoun() != "site" {
		t.Errorf("the menu would call it a %q", request.SubjectNoun())
	}
	// The whole URL is still shown: the site is what is decided, the URL is
	// what is being opened, and the person deciding needs both.
	var urls int
	for _, row := range request.Rows {
		if row.Label == "url" && strings.Contains(row.Value, "code=abc") {
			urls++
		}
	}
	if urls != 1 {
		t.Errorf("the full URL was not shown: %+v", request.Rows)
	}

	// A dev server on the box is identified by its port, so approving one for
	// the afternoon does not approve whatever else that box starts.
	exchange(t, svc, openRequest{URL: "http://localhost:5173/app"})
	if got := asker.seen().Subject; got != "localhost:5173" {
		t.Errorf("a loopback URL asked about %q", got)
	}
}

// Saying yes once is enough: an "always" answer is a rule, and the rule decides
// the next time without anybody being asked.
func TestAnAlwaysAnswerStopsTheAsking(t *testing.T) {
	asker := &recorder{answer: prompt.ChoiceAllowSecretAlways}
	svc := New(Options{
		Prompter: asker,
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:     func(context.Context, string) error { return nil },
	})
	host := asking()
	if _, err := svc.Attach(context.Background(), host); err != nil {
		t.Fatal(err)
	}

	exchange(t, svc, openRequest{URL: "https://github.com/login"})
	if len(svc.Rules()) != 1 {
		t.Fatalf("no rule was written: %+v", svc.Rules())
	}

	// The prompter would say no from here on; policy has to answer instead.
	asker.answer = prompt.ChoiceDeny
	if got := exchange(t, svc, openRequest{URL: "https://github.com/settings"}); !got.OK {
		t.Errorf("the rule did not decide the second request: %q", got.Error)
	}
}

// asking is a host with `gate: ask` set, which is what the gating tests are
// about. It is not the default: the dial for this service is the service, on or
// off per host, and a prompt for every window a command you just typed asked
// for is a prompt that gets answered without being read.
func asking() stubHost {
	host := newStubHost()
	host.config.docs[gateKey] = "ask"
	return host
}

// The default is to open without asking. This is the check that says so, since
// every other test here sets `gate: ask` explicitly.
func TestByDefaultNobodyIsAsked(t *testing.T) {
	asked := 0
	svc := New(Options{
		Prompter: promptFunc(func() (prompt.Choice, error) { asked++; return prompt.ChoiceDeny, nil }),
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:     func(context.Context, string) error { return nil },
	})
	if _, err := svc.Attach(context.Background(), newStubHost()); err != nil {
		t.Fatal(err)
	}

	if got := exchange(t, svc, openRequest{URL: "http://localhost:5173/app"}); !got.OK {
		t.Errorf("the default refused a URL: %q", got.Error)
	}
	if asked != 0 {
		t.Error("the default asked")
	}
}

// `gate: auto` is the explicit spelling of the default, for a config that has
// `gate: ask` globally and one host that would rather not be asked.
func TestGateAutoOpensWithoutAsking(t *testing.T) {
	asked := 0
	svc := New(Options{
		Prompter: promptFunc(func() (prompt.Choice, error) { asked++; return prompt.ChoiceDeny, nil }),
		Tunnels:  &fakeTunnels{states: []tunnels.State{{RemotePort: 5173, LocalPort: 5174}}},
		Open:     func(context.Context, string) error { return nil },
	})
	host := newStubHost()
	host.config.docs[gateKey] = "auto"
	if _, err := svc.Attach(context.Background(), host); err != nil {
		t.Fatal(err)
	}

	if got := exchange(t, svc, openRequest{URL: "http://localhost:5173/app"}); !got.OK {
		t.Errorf("gate: auto still refused: %q", got.Error)
	}
	if asked != 0 {
		t.Error("gate: auto still asked")
	}
}

type promptFunc func() (prompt.Choice, error)

func (f promptFunc) Ask(context.Context, prompt.Request) (prompt.Choice, error) { return f() }
