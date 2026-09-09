package web

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/approval"
	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
)

const token = "test-token"

// fakeTunnels is the port table, without a network.
type fakeTunnels struct {
	states []tunnels.State
	modes  map[int]tunnels.Mode
	labels map[int]string
	locals map[int]int
	policy tunnels.Policy
	prefs  tunnels.ViewPrefs
}

func newFakeTunnels(states ...tunnels.State) *fakeTunnels {
	return &fakeTunnels{states: states, modes: map[int]tunnels.Mode{}}
}

func (f *fakeTunnels) States() []tunnels.State { return f.states }

func (f *fakeTunnels) SetMode(port int, mode tunnels.Mode) tunnels.Mode {
	f.modes[port] = mode
	return mode
}

func (f *fakeTunnels) SetScheme(_ int, scheme tunnels.Scheme) tunnels.Scheme { return scheme }

func (f *fakeTunnels) SetLabel(port int, label string) error {
	if f.labels == nil {
		f.labels = map[int]string{}
	}
	if port == 9999 {
		return errors.New("remote port 9999 is not listed")
	}
	f.labels[port] = label
	return nil
}
func (f *fakeTunnels) SetLocalPort(port, local int) error {
	if f.locals == nil {
		f.locals = map[int]int{}
	}
	if port == 9999 {
		return errors.New("remote port 9999 is not listed")
	}
	f.locals[port] = local
	return nil
}

func (f *fakeTunnels) Policy() tunnels.Policy           { return f.policy }
func (f *fakeTunnels) SetPolicy(p tunnels.Policy)       { f.policy = p }
func (f *fakeTunnels) Hidden() int                      { return len(f.modes) }
func (f *fakeTunnels) ViewPrefs() tunnels.ViewPrefs     { return f.prefs }
func (f *fakeTunnels) SetViewPrefs(p tunnels.ViewPrefs) { f.prefs = p }

// fakeBroker is a gated service with rules and grants to list.
type fakeBroker struct {
	service.Service
	rules   []authz.Rule
	global  []authz.Rule
	grants  []authz.Grant
	revoked []int
	denied  []int
	dropped []string
	// forgets is what Forget claims to have dropped, so a test can tell one
	// broker's contribution from another's.
	forgets [2]int
	forgot  bool
}

func (b *fakeBroker) Meta() service.Meta {
	return service.Meta{ID: "1password", Title: "1Password", Glyph: "❖", Short: "the vault"}
}

func (b *fakeBroker) Rules() []authz.Rule       { return b.rules }
func (b *fakeBroker) GlobalRules() []authz.Rule { return b.global }
func (b *fakeBroker) Grants() []authz.Grant     { return b.grants }

func (b *fakeBroker) Deny(index int) error {
	b.denied = append(b.denied, index)
	return nil
}

func (b *fakeBroker) Forget() (grants, cached int) {
	b.forgot = true
	return b.forgets[0], b.forgets[1]
}

func (b *fakeBroker) Revoke(index int) error {
	b.revoked = append(b.revoked, index)
	return nil
}

func (b *fakeBroker) RevokeGrant(host, subject string) bool {
	b.dropped = append(b.dropped, host+" "+subject)
	return true
}

// fakeCachelessBroker is the other shape of broker: one that never sees a
// secret, so it has grants to drop and no cache to purge.
type fakeCachelessBroker struct {
	fakeBroker
	grants int
	forgot bool
}

func (b *fakeCachelessBroker) Meta() service.Meta {
	return service.Meta{ID: "agent", Title: "SSH agent", Glyph: "⚿", Short: "the agent"}
}

func (b *fakeCachelessBroker) Forget() int {
	b.forgot = true
	return b.grants
}

// stateOf asks for the snapshot the page draws from.
func stateOf(t *testing.T, s *Server) statePayload {
	t.Helper()
	recorder := ask(t, s, http.MethodGet, "/api/state")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/state = %d", recorder.Code)
	}
	var payload statePayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding the snapshot: %v", err)
	}
	return payload
}

func newTestServer(t *testing.T, opts Options) *Server {
	t.Helper()
	opts.Token = token
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) }
	}
	server, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server
}

// ask makes a request the way the page does: loopback Host, the cookie the
// token was traded for, and an Origin that matches.
func ask(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.Host = "127.0.0.1:9999"
	request.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
	if method != http.MethodGet {
		request.Header.Set("Origin", "http://127.0.0.1:9999")
	}
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)
	return recorder
}

// A port on 127.0.0.1 is not private: every process on the machine can reach
// it. The token is the whole of the defence, so nothing may be reachable
// without it.
func TestNothingIsReachableWithoutTheToken(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})

	for _, path := range []string{"/", "/api/state", "/api/events"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "127.0.0.1:9999"
		recorder := httptest.NewRecorder()
		s.mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token = %d, want 401", path, recorder.Code)
		}
	}

	// A wrong token is no better than none.
	request := httptest.NewRequest(http.MethodGet, "/api/state?t=nearly", nil)
	request.Host = "127.0.0.1:9999"
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("a wrong token = %d, want 401", recorder.Code)
	}
}

// The token arrives in the URL once and is traded for a cookie, so it stops
// being in the address bar — and in every screenshot of it. The cookie is not
// the token: if it were, the token out of browser history could be replayed as
// a cookie and the trade would have bought nothing.
func TestTheTokenInTheURLIsTradedForACookie(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})

	request := httptest.NewRequest(http.MethodGet, "/api/state?t="+token, nil)
	request.Host = "localhost:9999"
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("the token in the URL was refused: %d", recorder.Code)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookieName || cookies[0].Value == "" {
		t.Fatalf("no cookie was set: %+v", cookies)
	}
	if cookies[0].Value == token {
		t.Error("the cookie is the URL token, so the token in browser history still opens the board")
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("the cookie is not locked down: %+v", cookies[0])
	}
}

// devtun opens the browser itself, so the tokened URL is in history from the
// first second and nothing here can take it out again. What it can do is make
// it worth nothing once the page it opened has traded it.
func TestTheURLTokenIsGoodForOneTrade(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, Options{
		Tunnels: newFakeTunnels(),
		Now:     func() time.Time { return now },
	})

	first := httptest.NewRequest(http.MethodGet, "/?t="+token, nil)
	first.Host = "127.0.0.1:9999"
	opened := httptest.NewRecorder()
	s.mux.ServeHTTP(opened, first)
	if opened.Code != http.StatusOK {
		t.Fatalf("the first use of the token = %d", opened.Code)
	}
	cookies := opened.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("the first use set no cookie: %+v", cookies)
	}
	granted := cookies[0]

	now = now.Add(time.Hour)

	// The bookmark, reopened tomorrow in a browser that no longer has the
	// cookie: refused, and told what to do about it.
	replay := httptest.NewRequest(http.MethodGet, "/?t="+token, nil)
	replay.Host = "127.0.0.1:9999"
	refused := httptest.NewRecorder()
	s.mux.ServeHTTP(refused, replay)
	if refused.Code != http.StatusUnauthorized {
		t.Errorf("the token worked twice: %d", refused.Code)
	}
	if !strings.Contains(refused.Body.String(), "already been used") {
		t.Errorf("a spent token says only %q", refused.Body.String())
	}

	// Nor is the token any use as a cookie, which is the replay the separate
	// values exist to stop.
	asCookie := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	asCookie.Host = "127.0.0.1:9999"
	asCookie.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, asCookie)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("the URL token was accepted as a cookie: %d", recorder.Code)
	}

	// The tab that did the trade is unaffected, however long it stays open —
	// including when it reloads the bookmarked URL it still has in its bar.
	for _, path := range []string{"/api/state", "/api/state?t=" + token} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "127.0.0.1:9999"
		request.AddCookie(granted)
		kept := httptest.NewRecorder()
		s.mux.ServeHTTP(kept, request)
		if kept.Code != http.StatusOK {
			t.Errorf("GET %s with the cookie from the trade = %d, want 200", path, kept.Code)
		}
	}
}

// One page load is not one request, and a browser may prerender the URL before
// navigating to it. Whatever arrives in that first moment has to get the same
// cookie rather than racing the token into a refusal.
func TestConcurrentFirstRequestsAllGetTheSameCookie(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})

	var wait sync.WaitGroup
	values := make([]string, 8)
	codes := make([]int, 8)
	for i := range values {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := httptest.NewRequest(http.MethodGet, "/api/state?t="+token, nil)
			request.Host = "127.0.0.1:9999"
			recorder := httptest.NewRecorder()
			s.mux.ServeHTTP(recorder, request)
			codes[i] = recorder.Code
			if cookies := recorder.Result().Cookies(); len(cookies) == 1 {
				values[i] = cookies[0].Value
			}
		}()
	}
	wait.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("request %d of the page load = %d, want 200", i, code)
		}
		if values[i] == "" || values[i] != values[0] {
			t.Fatalf("request %d was given a different cookie: %q vs %q", i, values[i], values[0])
		}
	}
}

// DNS rebinding is the way a page in your browser reaches a server it should
// not be able to name: a hostname somebody else controls, pointed at 127.0.0.1.
// The Host header is the part of that they cannot forge.
func TestAHostThatIsNotLoopbackIsRefused(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})

	request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	request.Host = "devtun.attacker.example"
	request.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("a rebound hostname = %d, want 403", recorder.Code)
	}
}

// A cookie is sent by the browser whatever page asked, so anything that changes
// something has to prove it came from this one.
func TestACrossOriginPostIsRefused(t *testing.T) {
	tunnels := newFakeTunnels()
	s := newTestServer(t, Options{Tunnels: tunnels})

	request := httptest.NewRequest(http.MethodPost, "/api/ports/3000/mode?mode=hidden", nil)
	request.Host = "127.0.0.1:9999"
	request.Header.Set("Origin", "https://evil.example")
	request.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("a cross-origin POST = %d, want 403", recorder.Code)
	}
	if len(tunnels.modes) != 0 {
		t.Error("a cross-origin POST changed something")
	}
}

func TestStateCarriesTheBoard(t *testing.T) {
	broker := &fakeBroker{
		rules:  []authz.Rule{{Host: "bedev", Subject: "op://V/I/F", Action: authz.ActionAllow}},
		global: []authz.Rule{{Host: "*", Subject: "op://Private/**", Action: authz.ActionDeny}},
		grants: []authz.Grant{{Host: "bedev", Subject: "op://V/other/F", Action: authz.ActionAllow}},
	}
	s := newTestServer(t, Options{
		Host:    "bedev",
		Version: "v1.2.3",
		Tunnels: newFakeTunnels(tunnels.State{
			RemotePort: 3000, LocalPort: 3000, LocalAddr: "127.0.0.1",
			Proc: "node", Status: tunnels.StatusActive, Scheme: tunnels.SchemeHTTP,
			FirstSeen: time.Date(2026, 9, 7, 11, 45, 0, 0, time.UTC),
		}),
		Services: []service.Service{broker},
		Status: func() session.Status {
			return session.Status{State: session.Connected, Since: time.Date(2026, 9, 7, 11, 30, 0, 0, time.UTC)}
		},
	})

	recorder := ask(t, s, http.MethodGet, "/api/state")
	if recorder.Code != http.StatusOK {
		t.Fatalf("state = %d", recorder.Code)
	}
	var payload statePayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("the state is not JSON: %v\n%s", err, recorder.Body)
	}

	if payload.Host != "bedev" || payload.Version != "v1.2.3" {
		t.Errorf("header fields = %+v", payload)
	}
	if payload.Connection.State != string(session.Connected) || payload.Connection.Uptime != "30m0s" {
		t.Errorf("connection = %+v", payload.Connection)
	}
	if len(payload.Ports) != 1 || payload.Ports[0].URL != "http://127.0.0.1:3000" {
		t.Errorf("ports = %+v", payload.Ports)
	}
	if len(payload.Services) != 1 || payload.Services[0].ID != "1password" {
		t.Errorf("services = %+v", payload.Services)
	}
	if len(payload.Grants) != 1 {
		t.Errorf("grants = %+v", payload.Grants)
	}

	// Both rule sets are listed, and the one from the config file is marked as
	// such — it is not devtun's to rewrite, and the page must not offer to.
	if len(payload.Rules) != 2 {
		t.Fatalf("rules = %+v", payload.Rules)
	}
	var globals int
	for _, rule := range payload.Rules {
		if rule.Global {
			globals++
			if rule.Index >= 0 {
				t.Errorf("a global rule was given a revocable index: %+v", rule)
			}
		}
	}
	if globals != 1 {
		t.Errorf("%d rules came from the config, want 1", globals)
	}
}

// Hiding a port and taking back access are the two things this page changes,
// and both narrow what the remote box can do.
func TestThePageCanHideAPortAndRevokeAccess(t *testing.T) {
	ports := newFakeTunnels()
	broker := &fakeBroker{rules: []authz.Rule{{Subject: "op://V/I/F"}}}
	s := newTestServer(t, Options{Tunnels: ports, Services: []service.Service{broker}})

	if got := ask(t, s, http.MethodPost, "/api/ports/5432/mode?mode=hidden"); got.Code != http.StatusOK {
		t.Fatalf("hiding a port = %d: %s", got.Code, got.Body)
	}
	if ports.modes[5432] != tunnels.ModeHidden {
		t.Errorf("the port was not hidden: %+v", ports.modes)
	}

	if got := ask(t, s, http.MethodPost, "/api/rules/revoke?source=1password&index=0"); got.Code != http.StatusOK {
		t.Fatalf("revoking a rule = %d: %s", got.Code, got.Body)
	}
	if len(broker.revoked) != 1 || broker.revoked[0] != 0 {
		t.Errorf("revoked = %+v", broker.revoked)
	}

	if got := ask(t, s, http.MethodPost,
		"/api/grants/revoke?source=1password&host=bedev&subject=op://V/I/F"); got.Code != http.StatusOK {
		t.Fatalf("revoking a grant = %d: %s", got.Code, got.Body)
	}
	if len(broker.dropped) != 1 {
		t.Errorf("dropped = %+v", broker.dropped)
	}
}

// A global rule came out of a file somebody hand-wrote. The page lists it so
// they can see what is deciding, and must not offer to rewrite it — the index
// it is given (-1) is not one the broker will accept.
func TestAGlobalRuleCannotBeRevokedFromThePage(t *testing.T) {
	broker := &fakeBroker{global: []authz.Rule{{Subject: "op://Private/**", Action: authz.ActionDeny}}}
	s := newTestServer(t, Options{Services: []service.Service{broker}})

	if got := ask(t, s, http.MethodPost, "/api/rules/revoke?source=1password&index=-1"); got.Code == http.StatusOK {
		t.Error("the page revoked a rule from the config file")
	}
	if len(broker.revoked) != 0 {
		t.Errorf("something was revoked anyway: %+v", broker.revoked)
	}
}

func TestNonsenseIsRefusedRatherThanApplied(t *testing.T) {
	ports := newFakeTunnels()
	s := newTestServer(t, Options{Tunnels: ports, Services: nil})

	for _, path := range []string{
		"/api/ports/70000/mode?mode=hidden",
		"/api/ports/3000/mode?mode=whatever",
		"/api/ports/notaport/mode?mode=hidden",
		"/api/rules/revoke?source=nosuch&index=0",
	} {
		if got := ask(t, s, http.MethodPost, path); got.Code == http.StatusOK {
			t.Errorf("POST %s was accepted", path)
		}
	}
	if len(ports.modes) != 0 {
		t.Errorf("something was changed anyway: %+v", ports.modes)
	}
}

// The stream opens with what has already happened, so a tab opened an hour in
// is not looking at a blank page.
func TestTheEventStreamOpensWithTheHistory(t *testing.T) {
	bus := event.NewBus(8)
	bus.Emit(event.Event{Service: "tunnels", Class: event.Network, Kind: "opened", Text: "remote 3000"})
	s := newTestServer(t, Options{Bus: bus})

	request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request.Host = "127.0.0.1:9999"
	request.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
	ctx, cancel := context.WithCancel(request.Context())
	request = request.WithContext(ctx)

	// A recorder of its own rather than httptest's: the handler streams from
	// its own goroutine while this one reads, and httptest.ResponseRecorder's
	// buffer is not safe for that.
	stream := &syncWriter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.mux.ServeHTTP(stream, request)
	}()

	deadline := time.After(3 * time.Second)
	for {
		if strings.Contains(stream.String(), "remote 3000") {
			cancel()
			<-done
			return
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("the history never arrived:\n%s", stream.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// syncWriter is a ResponseWriter a test can read while the handler writes.
type syncWriter struct {
	mu     sync.Mutex
	body   strings.Builder
	header http.Header
}

func (w *syncWriter) Header() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}

func (w *syncWriter) WriteHeader(int) {}
func (w *syncWriter) Flush()          {}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

// The page is served from the binary, so the interface works on a machine with
// no network at all — which is most of the point of a local board.
func TestThePageIsEmbedded(t *testing.T) {
	s := newTestServer(t, Options{})
	recorder := ask(t, s, http.MethodGet, "/")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET / = %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"<title>devtun</title>", "/api/state", "/api/events"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
	// Nothing may be fetched from anywhere else: a board that needs a CDN is a
	// board that stops working on a train.
	for _, forbidden := range []string{"https://", "http://cdn", "unpkg", "jsdelivr"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the page reaches out to %q", forbidden)
		}
	}
}

// The set of endpoints the page may call is written down, so that adding one is
// deliberate rather than incidental.
//
// This used to enforce "the page may say an approval is waiting; it may never
// answer one", and /api/approve was added to it on purpose, once the replay
// question had an answer: a request is addressed by an unguessable id that is
// spent on first use, and a choice is checked against that one request's menu.
// The list survives the rule it originally guarded, because the failure it
// prevents is the same either way — a helpful patch teaching the page one more
// endpoint, with nobody weighing what that endpoint can do.
func TestThePageCallsNothingItIsNotAllowedTo(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	allowed := map[string]bool{
		"/api/state":         true,
		"/api/events":        true,
		"/api/ports/*/mode":  true,
		"/api/rules/revoke":  true,
		"/api/grants/revoke": true,
		"/api/reconnect":     true,
		"/api/hidden":        true,
		"/api/approve":       true,
		"/api/ports/*/label": true,
		"/api/ports/*/local": true,
		"/api/pause":         true,
		"/api/rules/deny":    true,
		"/api/grants/forget": true,
		"/api/config":        true,
		"/api/config/*":      true,
		// The trailing-slash form is what the scanner sees in the string that
		// builds a key path; the key itself is interpolated.
		"/api/config/": true,
	}

	// A template hole stands in for whatever the page interpolates, so the
	// path is compared and the port number is not.
	hole := regexp.MustCompile(`\$\{[^}]*\}`)
	for _, call := range regexp.MustCompile("/api/[^\"'`?\\s]*").FindAllString(string(page), -1) {
		if path := hole.ReplaceAllString(call, "*"); !allowed[path] {
			t.Errorf("the page calls %q, which is not one of the endpoints it may call", path)
		}
	}
}

func TestLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1:8080":   true,
		"localhost:8080":   true,
		"LocalHost":        true,
		"[::1]:8080":       true,
		"127.0.0.2:1":      true,
		"10.0.0.5:8080":    false,
		"devtun.example":   false,
		"192.168.1.9:8080": false,
	} {
		if got := loopbackHost(host); got != want {
			t.Errorf("loopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// --- approvals -------------------------------------------------------------

// deskWith returns a server whose desk has one question waiting on it, and the
// function that stops the asker.
func deskWith(t *testing.T, opts Options) (*Server, *approval.Desk, approval.Item, func()) {
	t.Helper()
	// Publishing on, because the board only sees a question when `web` is one
	// of the chosen surfaces — which is what these tests are about.
	desk := approval.New(approval.Options{Publish: true})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _ = desk.Ask(ctx, prompt.Request{
			Host: "bedev", Subject: "op://Personal/Docker/PAT", TTL: 5 * time.Minute,
			Rows: []prompt.Row{{Label: "caller", Value: "deploy.sh"}},
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for len(desk.Waiting()) == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the desk never published the question")
		}
		time.Sleep(time.Millisecond)
	}

	opts.Approvals = desk
	return newTestServer(t, opts), desk, desk.Waiting()[0], cancel
}

// The board shows what is waiting, with the id it needs to answer and the same
// menu every other surface offers.
func TestTheBoardShowsWhatIsWaiting(t *testing.T) {
	s, _, item, stop := deskWith(t, Options{})
	defer stop()

	recorder := ask(t, s, http.MethodGet, "/api/state")
	var payload statePayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("state: %v", err)
	}
	if len(payload.Waiting) != 1 {
		t.Fatalf("waiting = %+v", payload.Waiting)
	}
	got := payload.Waiting[0]
	if got.ID != item.ID || got.Subject != "op://Personal/Docker/PAT" {
		t.Errorf("the board published %+v", got)
	}
	if len(got.Options) == 0 {
		t.Error("the board offered no answers, so nothing could be decided from it")
	}
	// The caller detail is what makes an approval decidable at all.
	if len(got.Rows) != 1 || got.Rows[0].Value != "deploy.sh" {
		t.Errorf("the detail rows did not survive: %+v", got.Rows)
	}
}

func TestApprovingFromTheBoardAnswersTheRequest(t *testing.T) {
	s, desk, item, stop := deskWith(t, Options{})
	defer stop()

	path := "/api/approve?id=" + url.QueryEscape(item.ID) +
		"&choice=" + strconv.Itoa(int(prompt.ChoiceAllowOnce))
	if got := ask(t, s, http.MethodPost, path); got.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", got.Code, got.Body)
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(desk.Waiting()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the question is still waiting after being approved")
		}
		time.Sleep(time.Millisecond)
	}
}

// An id is spent on first use, so a replayed approval — a double submit, a
// resent request — cannot land on whatever is waiting next.
func TestAnApprovalCannotBeReplayed(t *testing.T) {
	s, _, item, stop := deskWith(t, Options{})
	defer stop()

	path := "/api/approve?id=" + url.QueryEscape(item.ID) +
		"&choice=" + strconv.Itoa(int(prompt.ChoiceAllowOnce))
	if got := ask(t, s, http.MethodPost, path); got.Code != http.StatusOK {
		t.Fatalf("the first approval was refused: %d", got.Code)
	}
	got := ask(t, s, http.MethodPost, path)
	if got.Code != http.StatusConflict {
		t.Errorf("a replayed approval returned %d, want 409", got.Code)
	}
	if !strings.Contains(got.Body.String(), "no longer waiting") {
		t.Errorf("the refusal does not say why: %s", got.Body)
	}
}

// Guessing at ids, and answering with something never offered, are the two
// ways to aim an approval at the wrong thing.
func TestApproveRefusesWhatItCannotVerify(t *testing.T) {
	s, _, item, stop := deskWith(t, Options{})
	defer stop()

	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{"a guessed id", "/api/approve?id=AAAAAAAAAAAAAAAAAAAAAA&choice=1", http.StatusConflict},
		{"no id at all", "/api/approve?choice=1", http.StatusConflict},
		{"no choice", "/api/approve?id=" + url.QueryEscape(item.ID), http.StatusBadRequest},
		{"a choice that is not a number", "/api/approve?id=" + url.QueryEscape(item.ID) + "&choice=yes", http.StatusBadRequest},
		{"a choice off the end of the menu", "/api/approve?id=" + url.QueryEscape(item.ID) + "&choice=99", http.StatusBadRequest},
	} {
		if got := ask(t, s, http.MethodPost, tc.path); got.Code != tc.want {
			t.Errorf("%s = %d, want %d: %s", tc.name, got.Code, tc.want, got.Body)
		}
	}
}

// Approving is a mutation, so it carries every defence the others do: no
// token, no rebound hostname, no cross-origin post.
func TestApproveIsGuardedLikeEveryOtherMutation(t *testing.T) {
	s, _, item, stop := deskWith(t, Options{})
	defer stop()

	path := "/api/approve?id=" + url.QueryEscape(item.ID) + "&choice=1"

	noToken := httptest.NewRequest(http.MethodPost, path, nil)
	noToken.Host = "127.0.0.1:9999"
	noToken.Header.Set("Origin", "http://127.0.0.1:9999")
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, noToken)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("approving without a token = %d, want 401", recorder.Code)
	}

	rebound := httptest.NewRequest(http.MethodPost, path, nil)
	rebound.Host = "devtun.attacker.example"
	rebound.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
	recorder = httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, rebound)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("approving through a rebound hostname = %d, want 403", recorder.Code)
	}

	crossOrigin := httptest.NewRequest(http.MethodPost, path, nil)
	crossOrigin.Host = "127.0.0.1:9999"
	crossOrigin.Header.Set("Origin", "https://evil.example")
	crossOrigin.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
	recorder = httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, crossOrigin)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("a cross-origin approval = %d, want 403", recorder.Code)
	}
}

// A session with nothing that asks for approval must not pretend it can.
func TestApproveWithNoDeskSaysSo(t *testing.T) {
	s := newTestServer(t, Options{})
	if got := ask(t, s, http.MethodPost, "/api/approve?id=x&choice=1"); got.Code != http.StatusServiceUnavailable {
		t.Errorf("approve with no desk = %d, want 503", got.Code)
	}
}

// Anything the page hides has to actually be hidden.
//
// The `hidden` attribute is `display: none` in the browser's own stylesheet,
// which any author rule outranks. The approval dialog's backdrop is
// `display: grid`, so it shipped dimming the entire board at all times while
// the page's own script believed it was hidden — a whole feature's worth of
// chrome on screen, permanently, from one line of CSS.
//
// The fix is one rule, and this is what keeps it there. It also fails if a new
// element is given `display` and marked `hidden` without it.
func TestHiddenElementsAreActuallyHidden(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	text := string(page)

	if !regexp.MustCompile(`\[hidden\]\s*\{[^}]*display:\s*none\s*!important`).MatchString(text) {
		t.Fatal("the page has no `[hidden] { display: none !important }`, so any element " +
			"with a display rule of its own will stay on screen when the script hides it")
	}

	// Every id the markup marks hidden must be one the script can unhide, or
	// it is dead chrome nobody will notice is missing.
	for _, id := range regexp.MustCompile(`id="([a-z-]+)"[^>]*\shidden`).FindAllStringSubmatch(text, -1) {
		if !strings.Contains(text, `$("`+id[1]+`")`) {
			t.Errorf("#%s starts hidden and nothing in the page ever shows it", id[1])
		}
	}
}

// A bare `--web` picks a fixed port so the board can be bookmarked, and gives
// way to any free one when something already has it — a second devtun on the
// same machine is an ordinary thing to want, and refusing to start over a port
// number would be a poor trade for a stable URL.
func TestTheDefaultPortGivesWayButANamedOneDoesNot(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("taking a port: %v", err)
	}
	defer func() { _ = busy.Close() }()
	taken := busy.Addr().String()

	// Defaulted: it moves aside and still comes up.
	defaulted := newTestServer(t, Options{Addr: taken})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- defaulted.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for defaulted.URL() == "" {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("a defaulted address did not give way to a free port")
		}
		time.Sleep(time.Millisecond)
	}
	if strings.Contains(defaulted.URL(), taken) {
		t.Errorf("it bound the busy port anyway: %s", defaulted.URL())
	}
	cancel()
	<-done

	// Named: honoured or reported, never quietly moved.
	named := newTestServer(t, Options{Addr: taken, FixedAddr: true})
	if err := named.Run(context.Background()); err == nil {
		t.Error("an address the user named was silently moved")
	}
}

// Naming a port is a thing you can do at the table, and under `--web` — where
// the board is the surface rather than a second view — being unable to do it
// here was a hole rather than a missing nicety.
func TestTheBoardCanNameAPort(t *testing.T) {
	ports := newFakeTunnels(tunnels.State{RemotePort: 3000, LocalPort: 3000, Proc: "node"})
	s := newTestServer(t, Options{Tunnels: ports})

	if got := ask(t, s, http.MethodPost, "/api/ports/3000/label?label=frontend"); got.Code != http.StatusOK {
		t.Fatalf("naming a port = %d: %s", got.Code, got.Body)
	}
	if ports.labels[3000] != "frontend" {
		t.Errorf("the name did not reach the service: %+v", ports.labels)
	}

	// Blank clears it, which is how you take a name back.
	if got := ask(t, s, http.MethodPost, "/api/ports/3000/label?label="); got.Code != http.StatusOK {
		t.Fatalf("clearing a name = %d", got.Code)
	}
	if ports.labels[3000] != "" {
		t.Errorf("the name was not cleared: %q", ports.labels[3000])
	}

	// A name that would push the rest of the row off the screen is refused,
	// and so is a port that is not there.
	long := "/api/ports/3000/label?label=" + strings.Repeat("x", 65)
	if got := ask(t, s, http.MethodPost, long); got.Code != http.StatusBadRequest {
		t.Errorf("an over-long name = %d, want 400", got.Code)
	}
	if got := ask(t, s, http.MethodPost, "/api/ports/9999/label?label=x"); got.Code != http.StatusConflict {
		t.Errorf("naming a port that is not listed = %d, want 409", got.Code)
	}
}

// --- the actions the interface had and the board did not ------------------

// Pinning a local port is `l` at the table. Under `--web` the board is the
// surface, so a callback URL the remote baked in — the case the pin exists for
// — was simply unreachable there.
func TestTheBoardCanPinALocalPort(t *testing.T) {
	ports := newFakeTunnels(tunnels.State{RemotePort: 3000, LocalPort: 51234, Proc: "node"})
	s := newTestServer(t, Options{Tunnels: ports})

	if got := ask(t, s, http.MethodPost, "/api/ports/3000/local?local=3000"); got.Code != http.StatusOK {
		t.Fatalf("pinning a local port = %d: %s", got.Code, got.Body)
	}
	if ports.locals[3000] != 3000 {
		t.Errorf("the pin did not reach the service: %+v", ports.locals)
	}

	// Zero is the way back to the default, and is the one value below 1 this
	// endpoint has to accept.
	if got := ask(t, s, http.MethodPost, "/api/ports/3000/local?local=0"); got.Code != http.StatusOK {
		t.Fatalf("clearing a pin = %d: %s", got.Code, got.Body)
	}
	if ports.locals[3000] != 0 {
		t.Errorf("the pin was not cleared: %+v", ports.locals)
	}

	for _, path := range []string{
		"/api/ports/3000/local?local=70000",
		"/api/ports/3000/local?local=-1",
		"/api/ports/3000/local?local=notaport",
		"/api/ports/3000/local",
	} {
		if got := ask(t, s, http.MethodPost, path); got.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400", path, got.Code)
		}
	}

	// A port something else already holds is a failure the caller has to see:
	// the tunnel is reopened now, so reporting success would be a lie.
	if got := ask(t, s, http.MethodPost, "/api/ports/9999/local?local=3000"); got.Code != http.StatusConflict {
		t.Errorf("pinning a port that is not listed = %d, want 409", got.Code)
	}
}

// Pausing is `p` at the table. The state has to come back in the snapshot too,
// or the board cannot say which way the switch is.
func TestTheBoardCanPauseAndResumeForwarding(t *testing.T) {
	ports := newFakeTunnels()
	s := newTestServer(t, Options{Tunnels: ports})

	if got := ask(t, s, http.MethodPost, "/api/pause?paused=true"); got.Code != http.StatusOK {
		t.Fatalf("pausing = %d: %s", got.Code, got.Body)
	}
	if !ports.policy.Paused {
		t.Error("the policy was not paused")
	}
	if !stateOf(t, s).Paused {
		t.Error("the snapshot does not say the session is paused")
	}

	// Naming the state rather than flipping it is what makes a second click, or
	// a retry, land where the user meant it to.
	if got := ask(t, s, http.MethodPost, "/api/pause?paused=true"); got.Code != http.StatusOK {
		t.Fatalf("pausing twice = %d", got.Code)
	}
	if !ports.policy.Paused {
		t.Error("pausing twice unpaused it")
	}

	if got := ask(t, s, http.MethodPost, "/api/pause?paused=false"); got.Code != http.StatusOK {
		t.Fatalf("resuming = %d: %s", got.Code, got.Body)
	}
	if ports.policy.Paused || stateOf(t, s).Paused {
		t.Error("the session did not resume")
	}
}

// Denying is `D` at the table: the rule you regret becomes a refusal rather
// than being forgotten, so the next request is not asked about either.
func TestTheBoardCanTurnARuleIntoARefusal(t *testing.T) {
	broker := &fakeBroker{
		rules:  []authz.Rule{{Subject: "op://V/I/F", Action: authz.ActionAllow}},
		global: []authz.Rule{{Subject: "op://Private/**", Action: authz.ActionDeny}},
	}
	s := newTestServer(t, Options{Services: []service.Service{broker}})

	if got := ask(t, s, http.MethodPost, "/api/rules/deny?source=1password&index=0"); got.Code != http.StatusOK {
		t.Fatalf("denying a rule = %d: %s", got.Code, got.Body)
	}
	if len(broker.denied) != 1 || broker.denied[0] != 0 {
		t.Errorf("denied = %+v", broker.denied)
	}

	// A rule from the config file arrives with the index the page was given for
	// it, which is the one index this must not accept: devtun did not write
	// that file and a page quietly rewriting it would be the worse surprise.
	fromTheFile := ask(t, s, http.MethodPost, "/api/rules/deny?source=1password&index=-1")
	if fromTheFile.Code != http.StatusBadRequest {
		t.Errorf("denying a global rule = %d, want 400", fromTheFile.Code)
	}
	if !strings.Contains(fromTheFile.Body.String(), "config file") {
		t.Errorf("the refusal does not say where to change it: %s", fromTheFile.Body)
	}
	if len(broker.denied) != 1 {
		t.Errorf("a global rule was denied anyway: %+v", broker.denied)
	}

	// A grant has no index, so it cannot be named here even by hand — which is
	// the whole of the interface's "that is a live grant" refusal.
	if got := ask(t, s, http.MethodPost, "/api/rules/deny?source=1password&index=notanindex"); got.Code != http.StatusBadRequest {
		t.Errorf("denying something that is not a rule = %d, want 400", got.Code)
	}
	if got := ask(t, s, http.MethodPost, "/api/rules/deny?source=nosuch&index=0"); got.Code != http.StatusNotFound {
		t.Errorf("denying on a service that is not here = %d, want 404", got.Code)
	}
}

// Forgetting everything is `F` at the table, and it is the panic button: one
// broker left holding an open door after it would be worse than not offering
// it. Both shapes of broker have to be swept — the vault reports grants and
// cached values, the agent and the browser have no cache and report one number.
func TestForgettingEverythingSweepsEveryBroker(t *testing.T) {
	vault := &fakeBroker{forgets: [2]int{2, 3}}
	agent := &fakeCachelessBroker{grants: 1}
	s := newTestServer(t, Options{Services: []service.Service{vault, agent}})

	recorder := ask(t, s, http.MethodPost, "/api/grants/forget")
	if recorder.Code != http.StatusOK {
		t.Fatalf("forgetting everything = %d: %s", recorder.Code, recorder.Body)
	}
	var counts struct{ Grants, Cached int }
	if err := json.Unmarshal(recorder.Body.Bytes(), &counts); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if counts.Grants != 3 || counts.Cached != 3 {
		t.Errorf("forgot %+v, want 3 grants and 3 cached values", counts)
	}
	if !vault.forgot || !agent.forgot {
		t.Errorf("a broker was left holding the door: vault=%v agent=%v", vault.forgot, agent.forgot)
	}

	// The board only offers the button when something is deciding, and says so
	// in the snapshot rather than the page guessing from an empty grants list —
	// a value can still be cached when no grant is live.
	if !stateOf(t, s).Gated {
		t.Error("a session with brokers does not say it is gated")
	}
	if stateOf(t, newTestServer(t, Options{Tunnels: newFakeTunnels()})).Gated {
		t.Error("a session with nothing gating it says it is gated")
	}
}

// Nothing to forget is an answer, not a failure: the button reports two zeros
// rather than looking broken.
func TestForgettingWithNothingToForgetSaysZero(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})
	recorder := ask(t, s, http.MethodPost, "/api/grants/forget")
	if recorder.Code != http.StatusOK {
		t.Fatalf("forgetting with no brokers = %d: %s", recorder.Code, recorder.Body)
	}
	if body := strings.TrimSpace(recorder.Body.String()); !strings.Contains(body, `"grants":0`) {
		t.Errorf("body = %s, want two zeros", body)
	}
}

// Every mutation is behind the same guard, and a new endpoint that missed it
// would be one a page you happened to be reading could post to. This is the
// check that adding a route without s.guard fails a test rather than shipping.
func TestTheNewMutationsAreGuardedLikeTheOldOnes(t *testing.T) {
	broker := &fakeBroker{rules: []authz.Rule{{Subject: "op://V/I/F"}}}
	s := newTestServer(t, Options{Tunnels: newFakeTunnels(), Services: []service.Service{broker}})

	for _, path := range []string{
		"/api/ports/3000/local?local=3000",
		"/api/pause?paused=true",
		"/api/rules/deny?source=1password&index=0",
		"/api/grants/forget",
	} {
		noCookie := httptest.NewRequest(http.MethodPost, path, nil)
		noCookie.Host = "127.0.0.1:9999"
		noCookie.Header.Set("Origin", "http://127.0.0.1:9999")
		recorder := httptest.NewRecorder()
		s.mux.ServeHTTP(recorder, noCookie)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("POST %s without the cookie = %d, want 401", path, recorder.Code)
		}

		crossOrigin := httptest.NewRequest(http.MethodPost, path, nil)
		crossOrigin.Host = "127.0.0.1:9999"
		crossOrigin.Header.Set("Origin", "https://evil.example")
		crossOrigin.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
		recorder = httptest.NewRecorder()
		s.mux.ServeHTTP(recorder, crossOrigin)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("POST %s from another origin = %d, want 403", path, recorder.Code)
		}

		notLoopback := httptest.NewRequest(http.MethodPost, path, nil)
		notLoopback.Host = "devtun.example"
		notLoopback.AddCookie(&http.Cookie{Name: cookieName, Value: s.session})
		recorder = httptest.NewRecorder()
		s.mux.ServeHTTP(recorder, notLoopback)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("POST %s to a name that is not loopback = %d, want 403", path, recorder.Code)
		}
	}

	if len(broker.denied) != 0 || broker.forgot {
		t.Error("a guarded endpoint did something anyway")
	}
}

// The board is the surface under `--web`, so an action it cannot reach is one
// those users do not have. A Go test cannot press a button, but it can check
// that the button is wired to the endpoint at all — the failure here is silent
// on every other test.
func TestThePageOffersEveryActionTheInterfaceDoes(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	text := string(page)
	for endpoint, action := range map[string]string{
		"/api/ports/${port.remote}/local": "pin a local port",
		"/api/pause":                      "pause and resume forwarding",
		"/api/rules/deny":                 "turn a rule into a refusal",
		"/api/grants/forget":              "forget every live grant",
	} {
		if !strings.Contains(text, endpoint) {
			t.Errorf("the page cannot %s — nothing on it calls %s", action, endpoint)
		}
	}
}

// A control revealed on hover is invisible until the rule that reveals it
// exists, and a page bug of that shape passes every other test here: the button
// is in the markup, wired to the right endpoint, and permanently transparent.
func TestHoverRevealedControlsAreActuallyRevealed(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	text := string(page)

	transparent := regexp.MustCompile(`\.([a-z-]+)[^{}]*\{[^{}]*opacity:\s*0[;\s}]`)
	found := transparent.FindAllStringSubmatch(text, -1)
	if len(found) == 0 {
		t.Fatal("no hover-revealed control found, so this test is guarding nothing")
	}
	for _, match := range found {
		if !strings.Contains(text, "tr:hover ."+match[1]) {
			t.Errorf(".%s is transparent and nothing reveals it on hover", match[1])
		}
	}
}

// A reference to a name that does not exist throws where it stands, and the
// rest of the handler never runs.
//
// This was real: the approval work left `waiting.set(...)` behind in the event
// stream's handler after the thing that declared `waiting` was deleted. Every
// SECURITY event — the requests, the approvals, the refusals, exactly the
// events the board exists to show — threw before it could be logged and before
// the refresh that follows it, so a decision made at the terminal never reached
// the board at all. It cost nothing at build time and nothing in any Go test,
// because neither one runs the page.
func TestThePageHasNoUndeclaredNames(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script := string(page)

	// Every name the script declares for itself, plus the browser's own.
	declared := map[string]bool{}
	for _, pattern := range []string{
		`(?m)^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)`,
		`(?m)^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)`,
		// Parameters are declarations too: `(event) => …` is where most of
		// this page's names come from.
		`\(([A-Za-z_$][\w$]*)\)\s*=>`,
		`\bfunction\s*[A-Za-z_$][\w$]*\s*\(([^)]*)\)`,
		`\bfunction\s*\(([^)]*)\)`,
		`\bcatch\s*\(([A-Za-z_$][\w$]*)\)`,
		`\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)`,
	} {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(script, -1) {
			for _, name := range strings.Split(m[1], ",") {
				name = strings.TrimSpace(name)
				// A default value or a rest element is still a binding.
				name = strings.TrimPrefix(name, "...")
				if i := strings.IndexAny(name, "="); i >= 0 {
					name = strings.TrimSpace(name[:i])
				}
				if name != "" {
					declared[name] = true
				}
			}
		}
	}

	// The names a called-as-an-object identifier could be. Anything the script
	// calls a method on is either something it declared, something the browser
	// gave it, or a bug.
	globals := map[string]bool{
		"document": true, "window": true, "navigator": true, "location": true,
		"console": true, "JSON": true, "Date": true, "Math": true, "Object": true,
		"Array": true, "Number": true, "String": true, "Map": true, "Set": true,
		"URL": true, "EventSource": true, "history": true, "localStorage": true, "sessionStorage": true, "AbortController": true, "Intl": true,
	}

	// Any `name.method(` where `name` is not itself a property. The leading
	// class stands in for a lookbehind, which RE2 does not have: it is what
	// keeps `a.b.c()` from reporting the property `b` as an undeclared name.
	//
	// This is looking for a name used as an object, not parsing JavaScript.
	calls := regexp.MustCompile(`(?:^|[^.\w$])([A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*\(`)
	for _, m := range calls.FindAllStringSubmatch(script, -1) {
		name := m[1]
		if declared[name] || globals[name] {
			continue
		}
		t.Errorf("the page calls a method on %q, which nothing declares — "+
			"every statement after it in that handler is dead", name)
	}
}

// namedBroker is a second gated service, so the order two of them come back in
// is observable at all. With one broker a map and a slice look identical.
type namedBroker struct {
	*fakeBroker
	id string
}

func (b *namedBroker) Meta() service.Meta {
	return service.Meta{ID: b.id, Title: b.id, Short: "another gate"}
}

// The board polls twice a second. A list whose order changes each time is one
// you cannot read — and worse, one where the row under your cursor is not the
// row you are about to click revoke on.
//
// This was real, and it was a map: brokers() returned one and the caller ranged
// over it, so Go's randomised iteration reshuffled every rule and grant on
// every poll. The interface walks a slice and never had it — the same class of
// divergence as the rest of this file.
func TestRulesAndGrantsComeBackInTheSameOrderEveryTime(t *testing.T) {
	rule := func(subject string) authz.Rule {
		return authz.Rule{Host: "bedev", Subject: subject, Action: authz.ActionAllow}
	}
	grant := func(subject string) authz.Grant {
		return authz.Grant{Host: "bedev", Subject: subject, Action: authz.ActionAllow}
	}
	first := &fakeBroker{
		rules:  []authz.Rule{rule("op://A/one"), rule("op://A/two")},
		grants: []authz.Grant{grant("op://A/one")},
	}
	second := &namedBroker{id: "ssh-agent", fakeBroker: &fakeBroker{
		rules:  []authz.Rule{rule("SHA256:aaa"), rule("SHA256:bbb")},
		grants: []authz.Grant{grant("SHA256:aaa")},
	}}
	s := newTestServer(t, Options{Services: []service.Service{first, second}})

	key := func(payload statePayload) string {
		var out []string
		for _, r := range payload.Rules {
			out = append(out, r.Source+":"+r.Subject)
		}
		out = append(out, "|")
		for _, g := range payload.Grants {
			out = append(out, g.Source+":"+g.Subject)
		}
		return strings.Join(out, ",")
	}

	// Enough polls that a shuffle of two brokers is overwhelmingly likely to
	// show up: a map with two keys reorders about half the time.
	want := key(stateOf(t, s))
	for range 40 {
		if got := key(stateOf(t, s)); got != want {
			t.Fatalf("the board reordered itself between polls:\n  %s\n  %s", want, got)
		}
	}

	// And the order is the registry's, not something incidental — the same
	// order the interface lists them in.
	if len(want) == 0 || !strings.HasPrefix(want, "1password:") {
		t.Errorf("the list does not start with the first registered service: %s", want)
	}
}

// Every panel belongs to a tab, and every tab is one the interface has.
//
// The board was six panels down one scroll, which is a list rather than an
// interface. Behind tabs, a panel with no tab is a panel nothing can reach —
// invisible rather than merely buried — so this is worth a test where the
// scrolling version needed none.
func TestEveryPanelIsOnATabTheInterfaceAlsoHas(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	// The same five, in the same order, as internal/tui's tabTitles.
	tabs := map[string]bool{
		"Tunnels": true, "Activity": true, "Access": true, "Services": true, "Config": true,
	}

	sections := regexp.MustCompile(`<section([^>]*)>`).FindAllStringSubmatch(string(page), -1)
	if len(sections) == 0 {
		t.Fatal("the page has no panels at all")
	}
	seen := map[string]bool{}
	for _, section := range sections {
		m := regexp.MustCompile(`data-tab="([^"]*)"`).FindStringSubmatch(section[1])
		if m == nil {
			t.Errorf("a panel has no data-tab, so no tab shows it: <section%s>", section[1])
			continue
		}
		if !tabs[m[1]] {
			t.Errorf("a panel is on tab %q, which is not one of the five", m[1])
		}
		seen[m[1]] = true
	}
	for name := range tabs {
		if !seen[name] {
			t.Errorf("the %s tab has no panel on it, so selecting it shows an empty page", name)
		}
	}
}
