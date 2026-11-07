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
	"github.com/jclement/devtun/internal/sshagent"
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

		send(m, "X")
		save("access-confirm-clear-refusals", m, "X: clearing the stop-asking refusals asks first (F keeps them)")
		send(m, "n")

		selectSubject(m, captureKey+" → github.com")
		send(m, "enter")
		save("access-detail-outranked", m, "enter on the github.com allow: ⚠ never wins, and what beats it")
		send(m, "esc")

		m.setCursor(noSelection)
		send(m, "t")
		m.test.fields.values[0].SetValue("op://Private/Root Keys/gpg")
		save("access-test-deny", m, "t: test box — a request a global deny refuses")
		m.test.fields.values[0].SetValue("op://Personal/Docker/registry")
		save("access-test-ask", m, "t: test box — nothing matches, so it would ask")
		send(m, "esc")

		selectSubject(m, "op://Personal/GitHub/token")
		send(m, "w")
		send(m, "ctrl+t")
		save("access-form-widen", m, "w on a remembered rule, then ctrl+t: …/GitHub/token → …/GitHub/*")
		send(m, "enter")
		save("access-confirm-widen", m, "enter: widening an allow asks first, saying what it opens")
		send(m, "n")
		send(m, "esc")

		selectSubject(m, captureKey+" → github.com")
		send(m, "w")
		m.form.focus = 1
		send(m, "ctrl+t")
		save("access-form-ssh", m, "w on the ssh rule: key and destination as two fields; ctrl+t on the key → any key")
		send(m, "esc")

		m.setCursor(noSelection)
		send(m, "n")
		save("access-form-new", m, "n: a blank new rule")
		send(m, "esc")

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
		save("activity-detail", m, "Activity, enter on the newest line (a grant gave it)")
		send(m, "esc")
		for i, e := range m.logRows {
			if eventField(e, "rule") == "SSHDENY" {
				m.setCursor(i)
			}
		}
		m.clampCursor()
		send(m, "enter")
		save("activity-why-ssh", m, "Activity, enter on the refused git push: why, and what lost")
		send(m, "esc")
		for i, e := range m.logRows {
			if eventField(e, "rule") == "OPROOT" {
				m.setCursor(i)
			}
		}
		send(m, "enter")
		save("activity-why-global", m, "Activity, enter on a refusal by a global rule (mockup C)")
		send(m, "o")
		save("activity-o-jumps", m, "o from that detail: Access, with the deciding rule selected")

		m = fresh()
		reply := make(chan prompt.Choice, 1)
		req := prompt.Request{Host: "bedev", Subject: "op://Shared/Dev/token", TTL: 5 * time.Minute,
			Rows: []prompt.Row{{Label: "command", Value: "op read op://Shared/Dev/token"}}}
		m.Update(approvalMsg{request: req, options: prompt.MenuFor(req), reply: reply})
		save("approval-op", m, "an approval: host-wide options name the noun; w and the context line (mockup H)")
		send(m, "w")
		save("approval-w-form", m, "w in the approval: the form on the request; the request keeps waiting")
		send(m, "esc")
		sreq := prompt.Request{Host: "bedev", Subject: captureKey + " → gitlab.com", Noun: "key", Scope: "gitlab.com", TTL: 5 * time.Minute}
		m.answer(prompt.ChoiceDeny)
		m.Update(approvalMsg{request: sreq, options: prompt.MenuFor(sreq), reply: reply})
		save("approval-ssh", m, "an ssh approval: \"any signature from bedev\"")
		m.answer(prompt.ChoiceDeny)

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
			{ID: "GDOCKER", Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow, Expires: testNow.Add(3*time.Minute + 12*time.Second)},
			{Host: "bedev", Subject: "op://Barreleye/Azure DevOps/token", Action: authz.ActionAllow},
			{Host: "bedev", Subject: "op://Personal/AWS root/password", Action: authz.ActionDeny},
		},
		rules: []authz.Rule{
			{Host: "bedev", Subject: "op://Personal/GitHub/token", Action: authz.ActionAllow, Note: "approved interactively on 2026-08-29", Added: testNow.Add(-8 * 24 * time.Hour), Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "op://Barreleye/Sentry/dsn", Action: authz.ActionAllow, Note: "approved interactively on 2026-09-02", Added: testNow.Add(-4 * 24 * time.Hour), Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "op://Personal/Stripe/secret key", Action: authz.ActionDeny, Note: "refused interactively on 2026-09-05", Added: testNow.Add(-26 * time.Hour), Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "op item create --vault Barreleye --category login --title svc-x", Action: authz.ActionAllow, Added: testNow.Add(-20 * time.Hour), Source: authz.SourceRemembered},
			{Host: "bedev", Subject: "op://Private/Recovery/codes", Action: authz.ActionAllow, Note: "for the restore script", Source: authz.SourceHost},
		},
		global: []authz.Rule{
			{ID: "OPROOT", Host: "**", Subject: "op://Private/Root Keys/**", Action: authz.ActionDeny},
			{Host: "**", Subject: "op://Shared/Dev/**", Action: authz.ActionAllow, Note: "dev-only creds"},
		},
	}
	sshSchema := sshagent.Schema
	ssh := &stubSecrets{
		schema: &sshSchema,
		live: []authz.Grant{{Host: "bedev", Subject: authz.HostWildcard, Action: authz.ActionAllow, HostWide: true}},
		rules: []authz.Rule{
			{Host: "bedev", Subject: captureKey + " → github.com", Action: authz.ActionAllow, Note: "approved interactively on 2026-08-20", Added: testNow.Add(-17 * 24 * time.Hour), Source: authz.SourceRemembered},
			{ID: "SSHDENY", Host: "bedev", Subject: "** → **", Action: authz.ActionDeny, Note: "nowhere else, from this box", Source: authz.SourceHost},
		},
	}
	services := []service.Service{
		stubService{meta: service.Meta{ID: "tunnels", Title: "Tunnels", Glyph: "⇄", Short: "forward ports"}},
		policyService{stubService{meta: service.Meta{ID: "1password", Title: "1Password", Glyph: "❖", Short: "serve op"}}, op},
		policyService{stubService{meta: service.Meta{ID: "ssh-agent", Title: "SSH Agent", Glyph: "⚿", Short: "sign with your keys"}}, ssh},
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
		{Time: testNow.Add(-60 * time.Second), Service: "ssh-agent", Kind: "denied", Class: event.Security,
			Text:   "refused bedev a signature with " + captureKey + " → github.com — denied by rule",
			Fields: []any{"subject", captureKey + " → github.com", "why", "denied by rule", "by", "rule", "rule", "SSHDENY", "source", "host"}},
		{Time: testNow.Add(-40 * time.Second), Service: "1password", Kind: "denied", Class: event.Security,
			Text:   "refused bedev op://Private/Root Keys/ssh — denied by rule",
			Fields: []any{"subject", "op://Private/Root Keys/ssh", "why", "denied by rule", "by", "rule", "rule", "OPROOT", "source", "global"}},
		{Time: testNow.Add(-30 * time.Second), Service: "1password", Kind: "allowed", Class: event.Security, Text: "gave bedev op://Personal/Docker/registry (unmatched → asked, you said once)",
			Fields: []any{"subject", "op://Personal/Docker/registry", "by", "prompt"}},
		{Time: testNow, Service: "1password", Kind: "allowed", Class: event.Security, Text: "gave bedev op://Personal/Docker/PAT (grant, 3m12s left)",
			Fields: []any{"subject", "op://Personal/Docker/PAT", "by", "grant", "grant", "GDOCKER"}},
	} {
		m.Update(eventMsg(e))
	}
	return m
}
