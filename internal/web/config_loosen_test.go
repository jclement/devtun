package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/service"
)

// A settings write that lets more through — "when nothing matches" back from
// deny to ask, approvals turned back on, the browser no longer asking — is
// refused by the board without confirm=1, whichever way it is spelled: an
// explicit value, clearing a level to inherit, or a step. What counts as
// loosening is the catalogue's answer (settings.Loosening), worked out over
// both files; these tests check the board asks it and enforces the answer.
func TestLooseningSettingsNeedAConfirm(t *testing.T) {
	type write struct {
		name    string
		seed    map[string]string // label/section/key → value
		path    string
		want    int    // without confirm
		storeAt string // label/section/key read back
		before  string // what is there after a refused write
		after   string // what is there after a confirmed write
	}
	for _, c := range []write{
		{"unmatched deny → ask", map[string]string{"bedev/1password/unmatched": "deny"},
			"/api/config/unmatched.1password?level=host&value=ask", http.StatusPreconditionRequired,
			"bedev/1password/unmatched", "deny", "ask"},
		{"unmatched deny → inherit (default ask)", map[string]string{"bedev/1password/unmatched": "deny"},
			"/api/config/unmatched.1password?level=host&value=", http.StatusPreconditionRequired,
			"bedev/1password/unmatched", "deny", ""},
		{"unmatched deny → the word inherit", map[string]string{"bedev/1password/unmatched": "deny"},
			"/api/config/unmatched.1password?level=host&value=inherit", http.StatusPreconditionRequired,
			"bedev/1password/unmatched", "deny", ""},
		{"unmatched deny → a step", map[string]string{"bedev/1password/unmatched": "deny"},
			"/api/config/unmatched.1password?level=host&step=1", http.StatusPreconditionRequired,
			"bedev/1password/unmatched", "deny", ""},
		{"unmatched global deny → ask", map[string]string{"/1password/unmatched": "deny"},
			"/api/config/unmatched.1password?level=global&value=ask", http.StatusPreconditionRequired,
			"/1password/unmatched", "deny", "ask"},
		{"prompt deny → all", map[string]string{"bedev//prompt": "deny"},
			"/api/config/prompt?level=host&value=all", http.StatusPreconditionRequired,
			"bedev//prompt", "deny", "all"},
		{"prompt deny → inherit", map[string]string{"bedev//prompt": "deny"},
			"/api/config/prompt?level=host&value=", http.StatusPreconditionRequired,
			"bedev//prompt", "deny", ""},
		{"browser gate ask → auto", map[string]string{"bedev/browser/gate": "ask"},
			"/api/config/gate?level=host&value=auto", http.StatusPreconditionRequired,
			"bedev/browser/gate", "ask", "auto"},
		{"browser gate ask → a step", map[string]string{"bedev/browser/gate": "ask"},
			"/api/config/gate?level=host&step=1", http.StatusPreconditionRequired,
			"bedev/browser/gate", "ask", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, s := looseningServer(t, c.seed)
			got := ask(t, s, http.MethodPost, c.path)
			if got.Code != c.want {
				t.Fatalf("without confirm = %d (%s), want %d", got.Code, got.Body, c.want)
			}
			if got.Body.Len() < 10 {
				t.Errorf("the refusal does not say what would loosen: %q", got.Body)
			}
			if v := store.values[c.storeAt]; v != c.before {
				t.Fatalf("a refused write changed the file: %q, want %q", v, c.before)
			}
			if got := ask(t, s, http.MethodPost, c.path+"&confirm=1"); got.Code != http.StatusOK {
				t.Fatalf("with confirm = %d: %s", got.Code, got.Body)
			}
			if v := store.values[c.storeAt]; v == c.before {
				t.Errorf("the confirmed write did not land: still %q", v)
			}
			// Inherit clears the level; the word itself is never written.
			if v := store.values[c.storeAt]; v == "inherit" {
				t.Errorf("%q was stored literally", v)
			}
		})
	}
}

// Tightening — and a change that loosens nothing because the other file still
// decides — stays one click.
func TestTighteningSettingsNeedNoConfirm(t *testing.T) {
	for _, c := range []struct {
		name string
		seed map[string]string
		path string
	}{
		{"unmatched ask → deny", nil, "/api/config/unmatched.1password?level=host&value=deny"},
		{"unmatched host deny → inherit under a global deny",
			map[string]string{"bedev/1password/unmatched": "deny", "/1password/unmatched": "deny"},
			"/api/config/unmatched.1password?level=host&value="},
		{"prompt all → deny", map[string]string{"bedev//prompt": "all"}, "/api/config/prompt?level=host&value=deny"},
		{"browser gate auto → ask", map[string]string{"bedev/browser/gate": "auto"}, "/api/config/gate?level=host&value=ask"},
		{"a setting that cannot loosen", nil, "/api/config/prompt?level=host&value=tui"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, s := looseningServer(t, c.seed)
			if got := ask(t, s, http.MethodPost, c.path); got.Code != http.StatusOK {
				t.Errorf("= %d (%s), want 200 without a confirm", got.Code, got.Body)
			}
		})
	}
}

// The confirmed write is still behind the guard: confirm=1 is not a credential.
func TestAConfirmedSettingWriteIsStillGuarded(t *testing.T) {
	_, s := looseningServer(t, map[string]string{"bedev/1password/unmatched": "deny"})
	path := "/api/config/unmatched.1password?level=host&value=ask&confirm=1"
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Host = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("without the credential = %d, want 401", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, path, nil)
	req.Host = "127.0.0.1:1"
	req.Header.Set("Origin", "http://127.0.0.1:3000")
	req.Header.Set("Authorization", bearerPrefix+s.session)
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("from another origin = %d, want 403", rec.Code)
	}
}

// looseningServer has a 1Password-shaped policy broker and a browser, so the
// catalogue lists unmatched, prompt and the browser's gate.
func looseningServer(t *testing.T, seed map[string]string) (*memStore, *Server) {
	t.Helper()
	store := newMemStore()
	for k, v := range seed {
		store.values[k] = v
	}
	vault := newVault(t, &testBook{}, authz.Schema{})
	site := &namedVault{gatedVault: newVault(t, &testBook{}, authz.Schema{}), id: "browser", title: "Browser"}
	return store, newTestServer(t, Options{Host: "bedev", Store: store, Services: []service.Service{vault, site}})
}

// The page turns the board's 428 on a settings write into the loosen-confirm,
// showing devtun's own sentence, and puts the control back when it is declined.
func TestThePageConfirmsALooseningSetting(t *testing.T) {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, want := range []string{
		`err.status === 428 && path.startsWith("/api/config/")`,
		`consequence: err.message,`,
		`run: () => act(path + "&confirm=1", done),`,
		`cancel: refreshConfig,`,
		`modalDismissed = c.cancel || null;`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
}
