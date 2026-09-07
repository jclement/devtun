package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
)

const token = "test-token"

// fakeTunnels is the port table, without a network.
type fakeTunnels struct {
	states []tunnels.State
	modes  map[int]tunnels.Mode
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
func (f *fakeTunnels) Hidden() int                                           { return len(f.modes) }
func (f *fakeTunnels) ViewPrefs() tunnels.ViewPrefs                          { return f.prefs }
func (f *fakeTunnels) SetViewPrefs(p tunnels.ViewPrefs)                      { f.prefs = p }

// fakeBroker is a gated service with rules and grants to list.
type fakeBroker struct {
	service.Service
	rules   []authz.Rule
	global  []authz.Rule
	grants  []authz.Grant
	revoked []int
	dropped []string
}

func (b *fakeBroker) Meta() service.Meta {
	return service.Meta{ID: "1password", Title: "1Password", Glyph: "🔒", Short: "the vault"}
}

func (b *fakeBroker) Rules() []authz.Rule       { return b.rules }
func (b *fakeBroker) GlobalRules() []authz.Rule { return b.global }
func (b *fakeBroker) Grants() []authz.Grant     { return b.grants }
func (b *fakeBroker) Deny(int) error            { return nil }

func (b *fakeBroker) Revoke(index int) error {
	b.revoked = append(b.revoked, index)
	return nil
}

func (b *fakeBroker) RevokeGrant(host, subject string) bool {
	b.dropped = append(b.dropped, host+" "+subject)
	return true
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

// ask makes a request the way the page does: loopback Host, the token, and an
// Origin that matches.
func ask(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.Host = "127.0.0.1:9999"
	request.AddCookie(&http.Cookie{Name: cookieName, Value: token})
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

// The token arrives in the URL once and becomes a cookie, so it stops being in
// the address bar — and in every screenshot of it.
func TestTheTokenInTheURLBecomesACookie(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})

	request := httptest.NewRequest(http.MethodGet, "/api/state?t="+token, nil)
	request.Host = "localhost:9999"
	recorder := httptest.NewRecorder()
	s.mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("the token in the URL was refused: %d", recorder.Code)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookieName || cookies[0].Value != token {
		t.Fatalf("no cookie was set: %+v", cookies)
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("the cookie is not locked down: %+v", cookies[0])
	}
}

// DNS rebinding is the way a page in your browser reaches a server it should
// not be able to name: a hostname somebody else controls, pointed at 127.0.0.1.
// The Host header is the part of that they cannot forge.
func TestAHostThatIsNotLoopbackIsRefused(t *testing.T) {
	s := newTestServer(t, Options{Tunnels: newFakeTunnels()})

	request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	request.Host = "devtun.attacker.example"
	request.AddCookie(&http.Cookie{Name: cookieName, Value: token})
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
	request.AddCookie(&http.Cookie{Name: cookieName, Value: token})
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
	request.AddCookie(&http.Cookie{Name: cookieName, Value: token})
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
