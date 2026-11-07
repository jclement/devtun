package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

// These drive the Access endpoints against a real authz.Gate, not a fake: the
// point of the board is that it asks the same policy the requests are decided
// by, so a fake that agreed with the handler would prove nothing. Only where
// the rules are kept is replaced, by a book in memory.

// testBook keeps all three lists in memory, so a test can put a hand-written
// host rule beside devtun's own.
type testBook struct {
	mu       sync.Mutex
	loaded   authz.Loaded
	revision uint64
}

func (b *testBook) Load() (authz.Loaded, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return authz.Loaded{
		Global:     append([]authz.Rule(nil), b.loaded.Global...),
		Host:       append([]authz.Rule(nil), b.loaded.Host...),
		Remembered: append([]authz.Rule(nil), b.loaded.Remembered...),
		Unmatched:  b.loaded.Unmatched, UnmatchedLevel: b.loaded.UnmatchedLevel,
	}, nil
}

// Edit hands the list over with the IDs the store would give it, which it
// learns by asking a store — the hashing is the store's business.
func (b *testBook) Edit(source authz.Source, edit func([]authz.Rule) ([]authz.Rule, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := &b.loaded.Remembered
	if source == authz.SourceHost {
		list = &b.loaded.Host
	}
	next, err := edit(withIDs(source, *list))
	if err != nil {
		return err
	}
	*list = next
	b.revision++
	return nil
}

func (b *testBook) Revision() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.revision
}

func withIDs(source authz.Source, rules []authz.Rule) []authz.Rule {
	scratch := authz.NewStore(authz.Config{})
	loaded := authz.Loaded{}
	if source == authz.SourceHost {
		loaded.Host = rules
	} else {
		loaded.Remembered = rules
	}
	scratch.AdoptBook(&staticBook{loaded})
	return scratch.Rules()
}

type staticBook struct{ loaded authz.Loaded }

func (s *staticBook) Load() (authz.Loaded, error) { return s.loaded, nil }
func (s *staticBook) Edit(authz.Source, func([]authz.Rule) ([]authz.Rule, error)) error {
	return nil
}
func (s *staticBook) Revision() uint64 { return 0 }

// gatedVault is a 1Password-shaped service backed by a real gate.
type gatedVault struct {
	service.Service
	authz.Surface
	gate *authz.Gate
}

func (v *gatedVault) Meta() service.Meta {
	return service.Meta{ID: "1password", Title: "1Password", Glyph: "❖"}
}

// sshSchema is the agent's two-field subject, for the tests that need fields.
var sshSchema = authz.Schema{
	Noun: "signature",
	Fields: []authz.Field{
		{Name: "key", Label: "key"}, {Name: "destination", Label: "destination"},
	},
	Separator: " → ",
}

func newVault(t *testing.T, book *testBook, schema authz.Schema) *gatedVault {
	t.Helper()
	gate := authz.NewGate(authz.Config{Schema: schema}, nil)
	gate.Store().AdoptBook(book)
	return &gatedVault{Surface: gate.Surface(), gate: gate}
}

func accessServer(t *testing.T, book *testBook) (*Server, *gatedVault) {
	t.Helper()
	vault := newVault(t, book, authz.Schema{})
	return newTestServer(t, Options{Host: "bedev", Services: []service.Service{vault}}), vault
}

// post is a same-origin POST with the credential, which is what the page sends.
func post(t *testing.T, s *Server, path string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return ask(t, s, http.MethodPost, path+"?"+query.Encode())
}

func ruleNamed(t *testing.T, v *gatedVault, subject string) authz.Rule {
	t.Helper()
	for _, r := range v.Rules() {
		if r.Subject == subject {
			return r
		}
	}
	t.Fatalf("no rule for %q in %+v", subject, v.Rules())
	return authz.Rule{}
}

func q(pairs ...string) url.Values {
	out := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out.Set(pairs[i], pairs[i+1])
	}
	return out
}

func TestTheStateGroupsRulesBySourceWithFieldsAndPolicy(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Global:         []authz.Rule{{Subject: "op://Private/**", Action: authz.ActionDeny}},
		Host:           []authz.Rule{{Host: "bedev", Subject: "op://Shared/*", Action: authz.ActionAllow}},
		Remembered:     []authz.Rule{{Host: "bedev", Subject: "op://Private/GitHub/token", Action: authz.ActionAllow}},
		Unmatched:      "deny",
		UnmatchedLevel: "host",
	}}
	s, _ := accessServer(t, book)
	state := stateOf(t, s)

	origins := map[string]ruleView{}
	for _, r := range state.Rules {
		origins[r.Origin] = r
	}
	if !origins["global"].Global || origins["global"].Editable {
		t.Errorf("a global rule must come back read-only: %+v", origins["global"])
	}
	if !origins["host"].Editable || !origins["remembered"].Editable {
		t.Errorf("host and remembered rules are editable here: %+v", state.Rules)
	}
	// The remembered allow is under the global deny of op://Private/**, so it
	// never wins — the ⚠ the page shows.
	if !origins["remembered"].Outranked {
		t.Error("an allow beneath a matching deny should be marked outranked")
	}
	if origins["host"].Outranked {
		t.Error("an allow nothing denies is not outranked")
	}
	if len(state.Policies) != 1 {
		t.Fatalf("want one policy row, got %+v", state.Policies)
	}
	p := state.Policies[0]
	if p.Short != "op" || p.Unmatched.Action != "deny" || p.Unmatched.Level != "host" {
		t.Errorf("policy row = %+v, want op / deny / host", p)
	}
	if state.Revision == "" {
		t.Error("the snapshot carries no revision, so the page cannot tell when rules changed")
	}
}

func TestRemovingADenyFromTheBoardNeedsAConfirm(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{{Host: "bedev", Subject: "op://Personal/Stripe/key", Action: authz.ActionDeny}},
	}}
	s, vault := accessServer(t, book)
	rule := ruleNamed(t, vault, "op://Personal/Stripe/key")

	if code := post(t, s, "/api/rules/remove", q("source", "1password", "id", rule.ID)).Code; code != http.StatusPreconditionRequired {
		t.Fatalf("removing a deny without confirm = %d, want 428", code)
	}
	if len(vault.Rules()) != 1 {
		t.Fatal("the deny went anyway")
	}
	if code := post(t, s, "/api/rules/remove", q("source", "1password", "id", rule.ID, "confirm", "1")).Code; code != http.StatusOK {
		t.Fatalf("confirmed removal = %d", code)
	}
	if len(vault.Rules()) != 0 {
		t.Error("the confirmed removal did not remove it")
	}
}

func TestRemovingAnAllowIsOneClick(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{{Host: "bedev", Subject: "op://Shared/Dev/token", Action: authz.ActionAllow}},
	}}
	s, vault := accessServer(t, book)
	rule := ruleNamed(t, vault, "op://Shared/Dev/token")
	if code := post(t, s, "/api/rules/remove", q("source", "1password", "id", rule.ID)).Code; code != http.StatusOK {
		t.Fatalf("removing an allow = %d, want 200 — it only tightens", code)
	}
}

func TestAGlobalRuleIsReadOnlyToEveryAction(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Global: []authz.Rule{{Subject: "op://Shared/**", Action: authz.ActionAllow}},
	}}
	s, vault := accessServer(t, book)
	rule := ruleNamed(t, vault, "op://Shared/**")
	for _, call := range []struct {
		path  string
		query url.Values
	}{
		{"/api/rules/remove", q("source", "1password", "id", rule.ID, "confirm", "1")},
		{"/api/rules/action", q("source", "1password", "id", rule.ID, "action", "deny")},
		{"/api/rules/update", q("source", "1password", "id", rule.ID, "note", "x")},
	} {
		if code := post(t, s, call.path, call.query).Code; code != http.StatusForbidden {
			t.Errorf("%s on a global rule = %d, want 403", call.path, code)
		}
	}
	if got := vault.Rules(); len(got) != 1 || got[0].Action != authz.ActionAllow {
		t.Errorf("the global rule changed: %+v", got)
	}
}

func TestTurningARuleIntoAnAllowNeedsAConfirmButADenyDoesNot(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{
			{Host: "bedev", Subject: "op://A/x/y", Action: authz.ActionAllow},
			{Host: "bedev", Subject: "op://B/x/y", Action: authz.ActionDeny},
		},
	}}
	s, vault := accessServer(t, book)
	allow, deny := ruleNamed(t, vault, "op://A/x/y"), ruleNamed(t, vault, "op://B/x/y")

	if code := post(t, s, "/api/rules/action", q("source", "1password", "id", allow.ID, "action", "deny")).Code; code != http.StatusOK {
		t.Errorf("allow → deny = %d, want 200 without a confirm", code)
	}
	if code := post(t, s, "/api/rules/action", q("source", "1password", "id", deny.ID, "action", "allow")).Code; code != http.StatusPreconditionRequired {
		t.Errorf("deny → allow without confirm = %d, want 428", code)
	}
	if ruleNamed(t, vault, "op://B/x/y").Action != authz.ActionDeny {
		t.Fatal("the deny became an allow without a confirm")
	}
	recorder := post(t, s, "/api/rules/action", q("source", "1password", "id", deny.ID, "action", "allow", "confirm", "1"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("confirmed deny → allow = %d", recorder.Code)
	}
	if ruleNamed(t, vault, "op://B/x/y").Action != authz.ActionAllow {
		t.Error("the confirmed change did not happen")
	}
	if code := post(t, s, "/api/rules/action", q("source", "1password", "id", deny.ID, "action", "ask")).Code; code != http.StatusBadRequest {
		t.Errorf("action=ask = %d, want 400: ask is not something a rule says", code)
	}
}

func TestAddingAnAllowRuleNeedsAConfirmAndLandsInRemembered(t *testing.T) {
	s, vault := accessServer(t, &testBook{})
	base := q("source", "1password", "host", "bedev", "subject", "op://Personal/Docker/*", "action", "allow", "note", "deploy")
	if code := post(t, s, "/api/rules/add", base).Code; code != http.StatusPreconditionRequired {
		t.Fatalf("a new allow without confirm = %d, want 428", code)
	}
	base.Set("confirm", "1")
	recorder := post(t, s, "/api/rules/add", base)
	if recorder.Code != http.StatusOK {
		t.Fatalf("confirmed add = %d: %s", recorder.Code, recorder.Body)
	}
	rule := ruleNamed(t, vault, "op://Personal/Docker/*")
	if rule.Source != authz.SourceRemembered || rule.Note != "deploy" || rule.Host != "bedev" {
		t.Errorf("added rule = %+v, want remembered, for bedev, with its note", rule)
	}
	var reply map[string]string
	_ = json.Unmarshal(recorder.Body.Bytes(), &reply)
	if reply["id"] != rule.ID {
		t.Errorf("the reply names %q, the rule is %q", reply["id"], rule.ID)
	}

	deny := q("source", "1password", "host", "", "subject", "op://Private/**", "action", "deny")
	if code := post(t, s, "/api/rules/add", deny).Code; code != http.StatusOK {
		t.Errorf("a new deny = %d, want 200 without a confirm — it only tightens", code)
	}
	if code := post(t, s, "/api/rules/add", q("source", "1password", "subject", " ", "action", "deny")).Code; code != http.StatusBadRequest {
		t.Errorf("an empty subject = %d, want 400", code)
	}
}

func TestChangingWhatARuleMatchesNeedsAConfirmButANoteDoesNot(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow}},
	}}
	s, vault := accessServer(t, book)
	rule := ruleNamed(t, vault, "op://Personal/Docker/PAT")

	recorder := post(t, s, "/api/rules/update", q("source", "1password", "id", rule.ID, "note", "registry"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a note-only edit = %d, want 200", recorder.Code)
	}
	var reply map[string]string
	_ = json.Unmarshal(recorder.Body.Bytes(), &reply)
	updated, ok := vault.Rule(reply["id"])
	if !ok || updated.Note != "registry" {
		t.Fatalf("the reply's id %q does not name the edited rule (%+v)", reply["id"], vault.Rules())
	}

	widen := q("source", "1password", "id", updated.ID, "subject", "op://Personal/Docker/*")
	if code := post(t, s, "/api/rules/update", widen).Code; code != http.StatusPreconditionRequired {
		t.Fatalf("widening without confirm = %d, want 428", code)
	}
	widen.Set("confirm", "1")
	if code := post(t, s, "/api/rules/update", widen).Code; code != http.StatusOK {
		t.Fatalf("confirmed widening = %d", code)
	}
	ruleNamed(t, vault, "op://Personal/Docker/*")

	// The id from before the edit no longer names anything.
	if code := post(t, s, "/api/rules/remove", q("source", "1password", "id", rule.ID)).Code; code != http.StatusConflict {
		t.Errorf("a stale id = %d, want 409", code)
	}
}

func TestGrantsFromTheBoard(t *testing.T) {
	s, vault := accessServer(t, &testBook{})

	allow := q("source", "1password", "host", "bedev", "subject", "op://A/b/c", "action", "allow", "ttl", "300")
	if code := post(t, s, "/api/grants/add", allow).Code; code != http.StatusPreconditionRequired {
		t.Fatalf("a grant without confirm = %d, want 428", code)
	}
	allow.Set("confirm", "1")
	if code := post(t, s, "/api/grants/add", allow).Code; code != http.StatusOK {
		t.Fatalf("confirmed grant = %d", code)
	}
	refuse := q("source", "1password", "host", "bedev", "subject", "op://A/b/d", "action", "deny", "ttl", "0")
	if code := post(t, s, "/api/grants/add", refuse).Code; code != http.StatusOK {
		t.Fatalf("a refusal = %d, want 200 without a confirm", code)
	}
	for _, bad := range []url.Values{
		q("source", "1password", "host", "", "subject", "x", "action", "deny", "ttl", "0"),
		q("source", "1password", "host", "*", "subject", "x", "action", "deny", "ttl", "0"),
		q("source", "1password", "host", "bedev", "subject", "x", "action", "deny", "ttl", "-1"),
		q("source", "1password", "host", "bedev", "subject", "x", "action", "deny", "ttl", "999999"),
	} {
		if code := post(t, s, "/api/grants/add", bad).Code; code != http.StatusBadRequest {
			t.Errorf("grant %v = %d, want 400", bad, code)
		}
	}

	var allowID, denyID string
	for _, g := range vault.Grants() {
		if g.Action == authz.ActionDeny {
			denyID = g.ID
		} else {
			allowID = g.ID
		}
	}
	if code := post(t, s, "/api/grants/revoke", q("source", "1password", "id", denyID)).Code; code != http.StatusPreconditionRequired {
		t.Errorf("revoking a refusal without confirm = %d, want 428", code)
	}

	// Forget drops the allow and keeps the refusal.
	if code := post(t, s, "/api/grants/forget", nil).Code; code != http.StatusOK {
		t.Fatalf("forget = %d", code)
	}
	if got := vault.Grants(); len(got) != 1 || got[0].ID != denyID {
		t.Fatalf("after forget: %+v, want only the refusal %s (allow was %s)", got, denyID, allowID)
	}

	if code := post(t, s, "/api/grants/forget-refusals", nil).Code; code != http.StatusPreconditionRequired {
		t.Errorf("forget-refusals without confirm = %d, want 428", code)
	}
	recorder := post(t, s, "/api/grants/forget-refusals", q("confirm", "1"))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"refusals":1`) {
		t.Errorf("forget-refusals = %d %s, want one refusal gone", recorder.Code, recorder.Body)
	}
	if len(vault.Grants()) != 0 {
		t.Error("the refusal survived forget-refusals")
	}
}

func TestExplainSaysWhatDecidesAndWhatLost(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Global:     []authz.Rule{{Subject: "op://Private/Root Keys/**", Action: authz.ActionDeny}},
		Remembered: []authz.Rule{{Host: "bedev", Subject: "op://Private/**", Action: authz.ActionAllow}},
	}}
	s, vault := accessServer(t, book)

	var x explainView
	recorder := ask(t, s, http.MethodGet, "/api/explain?"+q("source", "1password", "host", "bedev",
		"subject", "op://Private/Root Keys/ssh").Encode())
	if recorder.Code != http.StatusOK {
		t.Fatalf("explain = %d: %s", recorder.Code, recorder.Body)
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &x)
	if x.Verdict.Action != "deny" || x.Verdict.By.Kind != "rule" || x.Verdict.By.Source != "global" {
		t.Errorf("verdict = %+v, want deny by the global rule", x.Verdict)
	}
	if len(x.Matches) != 2 || !x.Matches[0].Decided || !x.Matches[1].Outranked {
		t.Errorf("matches = %+v, want the deny deciding and the allow outranked", x.Matches)
	}

	// Asked about the allow itself: what beats it.
	allow := ruleNamed(t, vault, "op://Private/**")
	_ = allow
	// The allow's own pattern is not under the narrower deny, so nothing beats
	// it for the request it describes.
	recorder = ask(t, s, http.MethodGet, "/api/explain?"+q("source", "1password", "rule", allow.ID).Encode())
	x = explainView{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &x)
	if x.Self == nil || x.Self.ID != allow.ID || len(x.BeatenBy) != 0 {
		t.Errorf("explain rule = %+v, want self and nothing beating it", x)
	}

	// A global deny is asked about by id: it beats the allow under it.
	deny := ruleNamed(t, vault, "op://Private/Root Keys/**")
	recorder = ask(t, s, http.MethodGet, "/api/explain?"+q("source", "1password", "rule", deny.ID).Encode())
	x = explainView{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &x)
	if !x.Self.Decided || len(x.Beats) != 1 || x.Beats[0].ID != allow.ID {
		t.Errorf("explain deny = %+v, want it deciding and beating the allow", x)
	}

	if code := ask(t, s, http.MethodGet, "/api/explain?source=1password&rule=nope").Code; code != http.StatusNotFound {
		t.Errorf("explaining a rule that is gone = %d, want 404", code)
	}
	if code := ask(t, s, http.MethodGet, "/api/explain?source=1password&subject=").Code; code != http.StatusBadRequest {
		t.Errorf("explaining nothing = %d, want 400", code)
	}
}

// The case the ⚠ marker was designed around: the README's old SSH example.
func TestAnAllowUnderACatchAllDenyIsOutranked(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{{Host: "bedev", Subject: "* → github.com", Action: authz.ActionAllow}},
		Host:       []authz.Rule{{Host: "bedev", Subject: "** → **", Action: authz.ActionDeny}},
	}}
	vault := newVault(t, book, sshSchema)
	s := newTestServer(t, Options{Host: "bedev", Services: []service.Service{vault}})
	state := stateOf(t, s)
	for _, r := range state.Rules {
		if r.Subject == "* → github.com" {
			if !r.Outranked {
				t.Error("allow * → github.com under deny ** → ** should be outranked")
			}
			if len(r.Parts) != 2 || r.Parts[1] != "github.com" {
				t.Errorf("parts = %q, want key and destination", r.Parts)
			}
		}
	}
	allow := ruleNamed(t, vault, "* → github.com")
	var x explainView
	recorder := ask(t, s, http.MethodGet, "/api/explain?"+q("source", "1password", "rule", allow.ID).Encode())
	_ = json.Unmarshal(recorder.Body.Bytes(), &x)
	if len(x.BeatenBy) != 1 || x.BeatenBy[0].Subject != "** → **" {
		t.Errorf("beatenBy = %+v, want the catch-all deny", x.BeatenBy)
	}
}

// Every Access endpoint is behind the same guard as everything else: the
// bearer credential, the loopback Host, and — for anything that changes state — the
// Origin.
func TestTheAccessEndpointsAreGuarded(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{{Host: "bedev", Subject: "op://A/b/c", Action: authz.ActionAllow}},
	}}
	s, vault := accessServer(t, book)
	id := ruleNamed(t, vault, "op://A/b/c").ID
	mutations := []string{
		"/api/rules/add?source=1password&subject=x&action=deny",
		"/api/rules/remove?source=1password&id=" + id,
		"/api/rules/action?source=1password&action=deny&id=" + id,
		"/api/rules/update?source=1password&note=x&id=" + id,
		"/api/grants/add?source=1password&host=bedev&subject=x&action=deny&ttl=0",
		"/api/grants/revoke?source=1password&id=g1",
		"/api/grants/forget",
		"/api/grants/forget-refusals?confirm=1",
	}
	for _, path := range append(mutations, "/api/explain?source=1password&subject=x") {
		method := http.MethodPost
		if strings.HasPrefix(path, "/api/explain") {
			method = http.MethodGet
		}
		req := httptest.NewRequest(method, path, nil)
		req.Host = "127.0.0.1:1"
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without the credential = %d, want 401", method, path, rec.Code)
		}

		req = httptest.NewRequest(method, path, nil)
		req.Host = "evil.example"
		req.Header.Set("Authorization", bearerPrefix+s.session)
		rec = httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s to a name that is not loopback = %d, want 403", method, path, rec.Code)
		}
	}
	for _, path := range mutations {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Host = "127.0.0.1:1"
		req.Header.Set("Origin", "http://127.0.0.1:3000")
		req.Header.Set("Authorization", bearerPrefix+s.session)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s from another origin = %d, want 403", path, rec.Code)
		}
	}
	if len(vault.Rules()) != 1 {
		t.Errorf("a refused request changed the rules: %+v", vault.Rules())
	}
}

// The event stream carries the decision's fields, which is what "why?" on the
// page follows.
func TestEventsCarryTheirFields(t *testing.T) {
	got := fieldMap([]any{"by", "rule", "rule", "abc", 3, "skipped", "source", "global"})
	if got["by"] != "rule" || got["rule"] != "abc" || got["source"] != "global" {
		t.Errorf("fieldMap = %v", got)
	}
	if _, ok := got["skipped"]; ok {
		t.Error("a value under a non-string key should be dropped, not promoted to a key")
	}
	if fieldMap(nil) != nil {
		t.Error("no fields should be no map")
	}
}

// A wildcard means different things in different services: one path segment
// in an op:// reference, any run of characters in an SSH key or destination.
// The form's hint used to say the former about every field, which taught the
// wrong rule exactly where it mattered — `* → github.com` covers every key.
func TestEachFieldSaysWhatItsWildcardsMean(t *testing.T) {
	vault := newVault(t, &testBook{}, authz.Schema{
		Noun:     "secret",
		Fields:   []authz.Field{{Name: "reference", Label: "reference"}},
		PathLike: true,
	})
	agent := &namedVault{gatedVault: newVault(t, &testBook{}, sshSchema), id: "ssh-agent", title: "SSH agent"}
	s := newTestServer(t, Options{Host: "bedev", Services: []service.Service{vault, agent}})

	globs := map[string][]fieldView{}
	for _, p := range stateOf(t, s).Policies {
		globs[p.Source] = p.Schema.Fields
		if p.Source == "1password" && !p.Schema.PathLike {
			t.Error("1password's schema should say it is path-like")
		}
	}
	op, ssh := globs["1password"], globs["ssh-agent"]
	if len(op) != 1 || len(ssh) != 2 {
		t.Fatalf("fields = %+v / %+v", op, ssh)
	}
	if !strings.Contains(op[0].Glob, "segment") {
		t.Errorf("op reference glob = %q, want it to say * is one segment", op[0].Glob)
	}
	for _, f := range ssh {
		if strings.Contains(f.Glob, "segment") || !strings.Contains(f.Glob, "anything") {
			t.Errorf("ssh %s glob = %q, want * to match anything within the field", f.Name, f.Glob)
		}
	}
}

// The page must take the hint from the schema, and must not carry a glob rule
// of its own that would be wrong for some service.
func TestTheFormHintComesFromTheSchema(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, fixed := range []string{"matches one part", "matches everything below"} {
		if strings.Contains(text, fixed) {
			t.Errorf("the page still hard-codes %q as a field hint", fixed)
		}
	}
	if !strings.Contains(text, "f.help || f.glob") {
		t.Error("the form's field hint is not the field's own help or glob")
	}
}

// A row carries one action and the menu: the primary one (revoke, remove
// refusal, remove) inline, the allow/deny switch only on the row under the
// pointer or selected, and everything else in the menu, drawer and keys.
func TestARowShowsOnlyItsPrimaryAction(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	if strings.Contains(text, "inline: true") {
		t.Error("an action is still always-inline; only the primary one may be")
	}
	if n := strings.Count(text, `inline: "primary"`); n != 3 {
		t.Errorf("%d primary inline actions, want 3 (revoke, remove refusal, remove)", n)
	}
	if !strings.Contains(text, `tr:hover .reveal`) || !strings.Contains(text, `tr[aria-selected="true"] .reveal`) {
		t.Error("the revealed action has no rule showing it on hover and selection")
	}
}

// The TTL is bounded before it is multiplied into a Duration. A value large
// enough to wrap to zero used to pass every check and come out as a session
// grant.
func TestAGrantTTLIsBoundedBeforeItCanOverflow(t *testing.T) {
	s, vault := accessServer(t, &testBook{})
	max := int(maxGrantTTL / time.Second)
	grant := func(ttl string) int {
		return post(t, s, "/api/grants/add", q("source", "1password", "host", "bedev",
			"subject", "op://A/b/"+ttl, "action", "deny", "ttl", ttl)).Code
	}
	if code := grant(strconv.Itoa(max)); code != http.StatusOK {
		t.Fatalf("ttl = a day exactly = %d, want 200", code)
	}
	for _, ttl := range []string{
		strconv.Itoa(max + 1),
		"36028797018963968", // × 1e9 wraps to exactly zero on 64 bits
		"9223372036854775807",
		"99999999999999999999", // does not parse as an int at all
	} {
		if code := grant(ttl); code != http.StatusBadRequest {
			t.Errorf("ttl=%s = %d, want 400", ttl, code)
		}
	}
	if got := vault.Grants(); len(got) != 1 {
		t.Errorf("grants = %+v, want only the one-day refusal", got)
	}
	if got := vault.Grants(); len(got) == 1 && got[0].Expires.IsZero() {
		t.Error("the one-day grant came out as a session grant")
	}
}

// The board's "explain" on a browser decision asks the browser's policy about
// the event's own subject and host. Both have to reach the page, and the
// browser has to be one of the policies the page can ask.
func TestABrowserDecisionReachesThePageWithItsSubject(t *testing.T) {
	site := &namedVault{gatedVault: newVault(t, &testBook{}, authz.Schema{
		Noun: "site", Fields: []authz.Field{{Name: "site", Label: "site"}}, PathLike: true,
	}), id: "browser", title: "Browser"}
	s := newTestServer(t, Options{Host: "bedev", Services: []service.Service{site}})
	if p := stateOf(t, s).Policies; len(p) != 1 || p[0].Source != "browser" || p[0].Noun != "site" {
		t.Fatalf("policies = %+v, want the browser's", p)
	}

	recorder := httptest.NewRecorder()
	err := writeEvent(recorder, event.Event{
		Service: "browser", Kind: "opened", Class: event.Network, Text: "opened",
		Fields: []any{"url", "http://localhost:5174/app", "host", "bedev", "subject", "localhost:5173", "by", "prompt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var view eventView
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(recorder.Body.String(), "data: "))), &view); err != nil {
		t.Fatalf("decoding %q: %v", recorder.Body, err)
	}
	if view.Service != "browser" || view.Fields["subject"] != "localhost:5173" || view.Fields["host"] != "bedev" || view.Fields["by"] != "prompt" {
		t.Errorf("event on the stream = %+v", view)
	}
}

// An approval that appears under a moving pointer must not take the click aimed
// at the board beneath it: a pointer cannot answer a question until that
// question has been up for 800ms, and a replacement question starts again.
// The keys are separate and immediate. The behaviour itself is exercised in a
// real browser by the demo board (see the worker report); this pins the
// wiring so a refactor cannot quietly drop it.
func TestApprovalAnswersAreArmedPerQuestion(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{
		"const ASK_ARM_MS = 800;",
		// armed afresh for every question drawn, inside renderAsk after the
		// same-id early return
		"askArmedAt = performance.now() + ASK_ARM_MS;",
		// a pointer click (detail > 0) before arming, or one whose press began
		// before arming, does nothing
		"if (event.detail > 0 && (pressedEarly || !askArmed())) {",
		// the keys answer directly, never through a click
		"answerWithKey(buttons[n - 1]);",
		"answerWithKey(buttons[buttons.length - 1]);",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the approval dialog is missing %q", want)
		}
	}
	render := text[strings.Index(text, "function renderAsk("):]
	render = render[:strings.Index(render, "\n}\n")]
	if strings.Index(render, "if (askShown === ask.id) return;") > strings.Index(render, "askArmedAt = performance.now()") {
		t.Error("the arming is reset on every poll, not once per question")
	}
}

// An edit is an edit of that rule, in that broker, and nothing else: the update
// route reads host, subject and note only, so it cannot turn a deny into an
// allow, become a grant, or land in another broker under the rule's id. (The
// terminal's form had a path that could; this pins that the board's cannot.)
func TestAnEditCannotChangeEffectBrokerOrKind(t *testing.T) {
	book := &testBook{loaded: authz.Loaded{
		Remembered: []authz.Rule{{Host: "bedev", Subject: "op://Work/**", Action: authz.ActionDeny}},
	}}
	vault := newVault(t, book, authz.Schema{})
	agent := &namedVault{gatedVault: newVault(t, &testBook{}, sshSchema), id: "ssh-agent", title: "SSH agent"}
	s := newTestServer(t, Options{Host: "bedev", Services: []service.Service{vault, agent}})
	rule := ruleNamed(t, vault, "op://Work/**")

	// Extra parameters an edit has no business sending are ignored.
	recorder := post(t, s, "/api/rules/update", q("source", "1password", "id", rule.ID,
		"note", "kept", "action", "allow", "ttl", "300", "kind", "grant"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("note edit = %d: %s", recorder.Code, recorder.Body)
	}
	got := vault.Rules()
	if len(got) != 1 || got[0].Action != authz.ActionDeny || got[0].Note != "kept" || len(vault.Grants()) != 0 {
		t.Errorf("after the edit: rules %+v grants %+v — want the same deny, noted, and no grant", got, vault.Grants())
	}

	// The rule's id under another broker names nothing there.
	if code := post(t, s, "/api/rules/update", q("source", "ssh-agent", "id", got[0].ID,
		"subject", "** → **", "confirm", "1")).Code; code != http.StatusConflict {
		t.Errorf("an edit sent to another broker = %d, want 409", code)
	}
	if len(agent.Rules()) != 0 {
		t.Errorf("the other broker gained a rule: %+v", agent.Rules())
	}
}

// The page's form keeps an edit on its own broker and effect, and never offers
// "lasts" for one, so a save can only be an update of that rule.
func TestThePageFormCannotTurnAnEditIntoSomethingElse(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{
		`editing ? "a rule stays with the service it belongs to" : ""`,
		`editing ? "use “make it an allow / a deny” for that" : ""`,
		`if (!editing) {
      row("lasts"`,
		`const path = "/api/rules/update?source=" + encodeURIComponent(editing.source) + "&id=" + encodeURIComponent(editing.id) +`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the form is missing %q", want)
		}
	}
}
