package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// TestCaptureScreens renders the interface's screens, with realistic data, to
// plain text files — for reviewing a change to the layout by reading it rather
// than by running devtun against a box.
//
// It only runs when DEVTUN_CAPTURE_DIR names a directory:
//
//	DEVTUN_CAPTURE_DIR=/tmp/caps go test ./internal/tui -run TestCaptureScreens
//
// Selection is reverse video, which stripping the styling loses, so each file
// says which row is selected in its first line.
func TestCaptureScreens(t *testing.T) {
	dir := os.Getenv("DEVTUN_CAPTURE_DIR")
	if dir == "" {
		t.Skip("set DEVTUN_CAPTURE_DIR to write the screens")
	}
	for _, size := range [][2]int{{100, 30}, {140, 40}} {
		w, h := size[0], size[1]
		save := func(name string, m *Model, note string) {
			t.Helper()
			path := filepath.Join(dir, name+"-"+itoa(w)+"x"+itoa(h)+".txt")
			body := "# " + note + "\n" + plainView(m) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		fresh := func() *Model {
			m := captureModel(t)
			m.Update(tea.WindowSizeMsg{Width: w, Height: h})
			m.reload()
			return m
		}

		m := fresh()
		send(m, "3")
		save("access", m, "Access, nothing selected")

		send(m, "down")
		save("access-grant-selected", m, "Access, cursor on the first live grant (op://Personal/Docker/PAT); the key bar lists what works on it")

		send(m, "enter")
		save("access-detail-grant", m, "enter on a grant: the detail, with its actions")
		send(m, "esc")

		selectSubject(m, "** → **")
		send(m, "enter")
		save("access-detail-deny-rule", m, "enter on the hand-written ssh deny rule ** → **")
		send(m, "esc")

		selectSubject(m, "op://Private/Root Keys/**")
		save("access-global-selected", m, "cursor on a global rule: r and D are not in the key bar")
		send(m, ".")
		save("access-menu-global", m, ". (or right click) on a global rule: every action, the unavailable ones dimmed with the reason")
		send(m, "esc")

		selectSubject(m, "op://Personal/Stripe/secret key")
		send(m, "r")
		save("access-confirm-remove-refusal", m, "r on a deny rule: the loosen confirm (mockup F)")
		send(m, "n")

		selectSubject(m, "op://Personal/AWS root/password")
		send(m, "r")
		save("access-confirm-stop-refusing", m, "r on a stop-ask refusal")
		send(m, "n")

		send(m, "F")
		save("access-confirm-forget", m, "F while refusals are live: says what it drops")
		send(m, "n")

		send(m, ":")
		typeIn(m, "deny")
		save("palette-deny", m, ": deny — Deny ranks first now, Revoke is not offered")
		send(m, "esc")

		m.openPalette()
		save("palette-menu", m, "☰ commands clicked (or : with nothing typed): the global menu, this tab first")
		m.closePalette()

		m = fresh()
		m.d.secrets = []accessSource{{id: "1password", title: "1Password", ctrl: &stubSecrets{}}, {id: "ssh-agent", title: "SSH Agent", ctrl: &stubSecrets{}}}
		m.reload()
		send(m, "3")
		save("access-empty", m, "Access with nothing open and no rules")

		m = fresh()
		send(m, "1")
		send(m, "down")
		save("tunnels-selected", m, "Tunnels, first port selected")
		send(m, "enter")
		save("tunnels-detail", m, "enter (or a second click) on a port: detail with clickable actions")
		send(m, "esc")
		m.mouseOff = true
		save("tunnels-mouse-off", m, "m: the mouse released for text selection — the bottom border says so")
		m.mouseOff = false

		m = fresh()
		send(m, "2")
		send(m, "up")
		send(m, "enter")
		save("activity-detail", m, "Activity, enter on the newest line")
		send(m, "esc")

		send(m, "4")
		send(m, "down")
		save("services", m, "Services, a row selected")

		send(m, "5")
		save("config", m, "Config")

		m = fresh()
		send(m, "esc")
		save("quit-confirm", m, "esc: the quit question, with clickable buttons")
		send(m, "n")

		m = fresh()
		send(m, "?")
		save("help", m, "? help")
	}
}

// selectSubject moves the Access cursor onto the row whose subject is s.
func selectSubject(m *Model, s string) {
	for i, r := range m.accessRows {
		if r.heading == "" && r.subject() == s {
			m.setCursor(i)
			m.clampCursor()
			return
		}
	}
}

const captureKey = "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZ/DTMczCvj3tD2s"

// captureModel is a session with the shape of a real one: two brokers, live
// grants and refusals, rules devtun wrote, a hand-written ssh rule and two
// global rules.
func captureModel(t *testing.T) *Model {
	op := &stubSecrets{
		live: []authz.Grant{
			{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow, Expires: testNow.Add(3*time.Minute + 12*time.Second)},
			{Host: "bedev", Subject: "op://Barreleye/Azure DevOps/token", Action: authz.ActionAllow},
			{Host: "bedev", Subject: "op://Personal/AWS root/password", Action: authz.ActionDeny},
		},
		rules: []authz.Rule{
			{Host: "bedev", Subject: "op://Personal/GitHub/token", Action: authz.ActionAllow, Note: "approved interactively on 2026-08-29", Added: testNow.Add(-8 * 24 * time.Hour)},
			{Host: "bedev", Subject: "op://Barreleye/Sentry/dsn", Action: authz.ActionAllow, Note: "approved interactively on 2026-09-02", Added: testNow.Add(-4 * 24 * time.Hour)},
			{Host: "bedev", Subject: "op://Personal/Stripe/secret key", Action: authz.ActionDeny, Note: "refused interactively on 2026-09-05", Added: testNow.Add(-26 * time.Hour)},
			{Host: "bedev", Subject: "op item create --vault Barreleye --category login --title svc-x", Action: authz.ActionAllow, Added: testNow.Add(-20 * time.Hour)},
		},
		global: []authz.Rule{
			{Host: "**", Subject: "op://Private/Root Keys/**", Action: authz.ActionDeny},
			{Host: "**", Subject: "op://Shared/Dev/**", Action: authz.ActionAllow, Note: "dev-only creds"},
		},
	}
	ssh := &stubSecrets{
		live: []authz.Grant{{Host: "bedev", Subject: authz.HostWildcard, Action: authz.ActionAllow, HostWide: true}},
		rules: []authz.Rule{
			{Host: "bedev", Subject: captureKey + " → github.com", Action: authz.ActionAllow, Note: "approved interactively on 2026-08-20", Added: testNow.Add(-17 * 24 * time.Hour)},
			{Host: "bedev", Subject: "** → **", Action: authz.ActionDeny, Note: "nowhere else, from this box"},
		},
	}
	services := []service.Service{
		stubService{meta: service.Meta{ID: "tunnels", Title: "Tunnels", Glyph: "⇄", Short: "forward ports"}},
		stubService{meta: service.Meta{ID: "1password", Title: "1Password", Glyph: "❖", Short: "serve op"}},
		stubService{meta: service.Meta{ID: "ssh-agent", Title: "SSH Agent", Glyph: "⚿", Short: "sign with your keys"}},
	}
	all, _ := prompt.ParseSurfaces("all")
	m := newTestModel(t, deps{
		tunnels:       newStub(row(3000, 3000, "node vite"), row(5432, 5432, "postgres"), row(8080, 18080, "python3 -m http.server")),
		secrets:       []accessSource{{id: "1password", title: "1Password", ctrl: op}, {id: "ssh-agent", title: "SSH Agent", ctrl: ssh}},
		services:      services,
		store:         newTestStore(t),
		promptBackend: all,
		webURL:        "http://127.0.0.1:8765/#token",
	})
	for _, e := range []event.Event{
		{Time: testNow.Add(-90 * time.Second), Service: "tunnels", Kind: "started", Class: event.Network, Text: "Tunnels ready"},
		{Time: testNow.Add(-80 * time.Second), Service: "1password", Kind: "started", Class: event.Lifecycle, Text: "1Password ready"},
		{Time: testNow.Add(-80 * time.Second), Service: "ssh-agent", Kind: "started", Class: event.Lifecycle, Text: "SSH Agent ready"},
		{Time: testNow.Add(-40 * time.Second), Service: "1password", Kind: "denied", Class: event.Security,
			Text: "refused bedev op://Private/Root Keys/ssh — denied by rule ** → op://Private/Root Keys/**", Fields: []any{"why", "denied by rule ** → op://Private/Root Keys/**"}},
		{Time: testNow, Service: "1password", Kind: "allowed", Class: event.Security, Text: "gave bedev op://Personal/Docker/PAT (grant, 3m12s left)"},
	} {
		m.Update(eventMsg(e))
	}
	return m
}
