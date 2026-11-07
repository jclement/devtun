package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/browser"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/gpgagent"
	"github.com/jclement/devtun/internal/onepassword"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/sshagent"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// An SSH signature refused used to lead with the 1Password ❖, because the
// glyph came from the event's class and both are security events.
func TestActivityLinesLeadWithTheirServicesGlyph(t *testing.T) {
	m := newTestModel(t, deps{})
	for _, e := range []event.Event{
		{Time: testNow, Service: "ssh-agent", Class: event.Security, Kind: "denied", Text: "refused bedev a signature"},
		{Time: testNow, Service: "1password", Class: event.Security, Kind: "allowed", Text: "gave bedev a secret"},
		{Time: testNow, Service: "browser", Class: event.Network, Kind: "opened", Text: "opened a page"},
	} {
		m.Update(eventMsg(e))
	}
	send(m, "2")
	view := bodyLines(m)
	for text, glyph := range map[string]string{"refused bedev a signature": "◈", "gave bedev a secret": "❖", "opened a page": "◱"} {
		found := false
		for _, line := range strings.Split(view, "\n") {
			if strings.Contains(line, text) {
				found = true
				if !strings.Contains(line, " "+glyph+" ") {
					t.Errorf("%q is not led by %s: %q", text, glyph, line)
				}
			}
		}
		if !found {
			t.Errorf("%q is not on screen:\n%s", text, view)
		}
	}
}

// ui restates each service's glyph to avoid an import cycle; this holds the
// copy to the original.
func TestServiceGlyphsMatchEachServicesMeta(t *testing.T) {
	for _, svc := range []service.Service{&onepassword.Service{}, &sshagent.Service{}, &gpgagent.Service{}, &browser.Service{}, &tunnels.Service{}} {
		meta := svc.Meta()
		if got := ui.ServiceGlyph(meta.ID); got != meta.Glyph {
			t.Errorf("%s: ui.ServiceGlyph says %q, its Meta says %q", meta.ID, got, meta.Glyph)
		}
	}
}

// With an overlay open, the key bar is that overlay's, not the list's.
func TestTheKeyBarBelongsToTheOpenModal(t *testing.T) {
	m, _ := accessFixture(t)
	selectSubject(m, "op://Work/CI/token")
	bar := func() string { return ansi.Strip(m.keyBar()) }

	send(m, "enter")
	if b := bar(); strings.Contains(b, "enter detail") || !strings.Contains(b, "esc close") {
		t.Errorf("detail open, the bar reads %q", b)
	}
	send(m, "esc")

	send(m, "w")
	if b := bar(); strings.Contains(b, "revoke") || !strings.Contains(b, "ctrl+t widen") || !strings.Contains(b, "enter save") {
		t.Errorf("form open, the bar reads %q", b)
	}
	// A click on the bar's esc closes the form — it must not ask to quit.
	m.frame()
	for _, z := range m.footerZones {
		if z.id == "esc" {
			click(m, z.x0, m.height-1)
		}
	}
	if m.form != nil || m.confirm != nil {
		t.Errorf("clicking esc on the bar: form open=%v, confirm=%v", m.form != nil, m.confirm != nil)
	}

	selectSubject(m, "op://Work/Stripe/key")
	send(m, "r")
	if b := bar(); !strings.Contains(b, "y remove it") || strings.Contains(b, "detail") {
		t.Errorf("confirm open, the bar reads %q", b)
	}
	send(m, "n")

	send(m, "t")
	if b := bar(); !strings.Contains(b, "ctrl+n") || strings.Contains(b, "revoke") {
		t.Errorf("test box open, the bar reads %q", b)
	}
}

// A toast replaces the key bar, so a click where a button used to be must do
// nothing — the zones recorded under it are stale.
func TestAClickOnAToastRunsNothing(t *testing.T) {
	m, s := accessFixture(t)
	selectSubject(m, "op://Work/CI/token")
	m.frame()
	var revoke zone
	for _, z := range m.footerZones {
		if z.id == "r" {
			revoke = z
		}
	}
	if revoke.x1 == 0 {
		t.Fatal("no revoke in the bar")
	}
	m.showToast(toastMsg{text: "something happened"})
	click(m, revoke.x0, m.height-1)
	if len(s.revoked) != 0 {
		t.Errorf("a click on a toast revoked %v", s.revoked)
	}
}
