package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
)

// A browser decision names the site as it was asked for — localhost:5173, not
// the 5174 the URL was rewritten to on this machine — and that is what
// "write a rule from this request" starts from, on the browser's own form.
func TestABrowserDecisionSeedsARuleForTheSiteAsAskedFor(t *testing.T) {
	op := &stubSecrets{}
	web := &stubSecrets{}
	all, _ := prompt.ParseSurfaces("all")
	m := newTestModel(t, deps{
		secrets: []accessSource{
			{id: "1password", title: "1Password", ctrl: op},
			{id: "browser", title: "Browser", ctrl: web},
		},
		promptBackend: all,
	})
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m.Update(eventMsg(event.Event{
		Time: testNow, Service: "browser", Kind: "opened", Class: event.Network,
		Text: "opened http://localhost:5174/app for vite on bedev",
		Fields: []any{"url", "http://localhost:5174/app", "requested", "http://localhost:5173/app",
			"caller", "vite", "host", "bedev", "subject", "localhost:5173", "by", "prompt"},
	}))
	send(m, "2")
	send(m, "up")
	send(m, "n")
	if m.form == nil {
		t.Fatal("n on a browser decision did not open the rule form")
	}
	if got := m.d.secrets[m.form.fields.src].id; got != "browser" {
		t.Errorf("the form is for %q, want the browser", got)
	}
	if got := m.form.fields.values[0].Value(); got != "localhost:5173" {
		t.Errorf("the form starts from %q, want the site as asked for (localhost:5173)", got)
	}
}
