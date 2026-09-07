package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/tunnels"
)

func TestTabsCycleAndJump(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})

	send(m, "tab")
	if m.tab != tabActivity {
		t.Errorf("tab moved to %v, want Activity", m.tab)
	}
	send(m, "shift+tab")
	if m.tab != tabTunnels {
		t.Errorf("shift+tab moved to %v, want Tunnels", m.tab)
	}
	send(m, "3")
	if m.tab != tabAccess {
		t.Errorf("3 moved to %v, want Access", m.tab)
	}
	// Wrapping is what makes tab usable without counting.
	m.tab = tabServices
	send(m, "tab")
	if m.tab != tabTunnels {
		t.Errorf("tab from the last tab moved to %v, want Tunnels", m.tab)
	}
}

// The arrows walk the tabs, which is what a hand reaches for first. No tab uses
// them for anything of its own, so there is nothing to trade away.
func TestArrowsWalkTheTabs(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})

	send(m, "right")
	if m.tab != tabActivity {
		t.Errorf("right moved to %v, want Activity", m.tab)
	}
	send(m, "left")
	if m.tab != tabTunnels {
		t.Errorf("left moved to %v, want Tunnels", m.tab)
	}
	// But not while something has the keyboard: the search box needs left and
	// right to edit with, and a tab switch under the cursor would be baffling.
	send(m, "/")
	send(m, "left")
	if m.tab != tabTunnels {
		t.Errorf("left switched tabs from inside the search box, to %v", m.tab)
	}
}

func TestClickingATabSelectsIt(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	m.frame() // the zones are recorded as the bar renders

	target := m.tabZones[int(tabAccess)]
	click(m, target.x0+1, rowTabs)
	if m.tab != tabAccess {
		t.Errorf("clicking the Access tab selected %v", m.tab)
	}
	if !strings.Contains(plainView(m), "▸Access") {
		t.Errorf("the tab bar does not mark the selection:\n%s", plainView(m))
	}
}

// Each tab keeps its own cursor: switching away and back should not lose your
// place in a two-thousand line log.
func TestEachTabKeepsItsOwnCursor(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(
		row(3000, 3000, "a"), row(3001, 3001, "b"), row(3002, 3002, "c"))})

	send(m, "down")
	send(m, "down")
	if m.cursors[tabTunnels] != 1 {
		t.Fatalf("the tunnels cursor is at %d, want 1", m.cursors[tabTunnels])
	}
	send(m, "2")
	if m.cursor() != noSelection {
		t.Errorf("the activity tab arrived with a selection at %d", m.cursor())
	}
	send(m, "1")
	if m.cursor() != 1 {
		t.Errorf("returning to Tunnels lost the cursor: %d", m.cursor())
	}
}

// x is the key the footer advertises, and hiding a port has to actually take
// it off the table — otherwise it is a preference nobody can see the effect of.
func TestHideTakesTheRowOffTheTableAndShowHiddenBringsItBack(t *testing.T) {
	stub := newStub(row(3000, 3000, "node vite"), row(5432, 5432, "postgres"))
	m := newTestModel(t, deps{tunnels: stub})

	// Select the postgres row.
	send(m, "down")
	send(m, "down")
	if got := m.selectedPort(); got != 5432 {
		t.Fatalf("selected remote %d, want 5432", got)
	}

	send(m, "x")
	// Assert on the rows rather than the frame: the confirmation toast names
	// the process too, and would satisfy a substring check on the whole view.
	for _, r := range m.rows {
		if r.RemotePort == 5432 {
			t.Errorf("the hidden row is still on the table:\n%s", plainView(m))
		}
	}
	if mode := stub.rows[1].Mode; mode != tunnels.ModeHidden {
		t.Errorf("the port was recorded as %q, want hidden", mode)
	}

	send(m, "H")
	view := plainView(m)
	if !strings.Contains(view, "postgres") {
		t.Errorf("H did not list the hidden port:\n%s", view)
	}
	if !strings.Contains(view, "hidden by you") {
		t.Errorf("a hidden row does not say why it is not forwarded:\n%s", view)
	}
	if !strings.Contains(view, "✕") {
		t.Errorf("a hidden row is not marked in the mode column:\n%s", view)
	}

	// From here x is the way back.
	m.cursors[tabTunnels] = noSelection
	send(m, "down")
	send(m, "down")
	send(m, "x")
	if mode := stub.rows[1].Mode; mode != tunnels.ModeAuto {
		t.Errorf("x on a hidden row left it %q, want auto", mode)
	}
}

// Hiding is remembered, which means it goes through the service rather than
// living in the model.
func TestShowHiddenIsPersistedThroughTheService(t *testing.T) {
	stub := newStub(row(3000, 3000, "node"))
	m := newTestModel(t, deps{tunnels: stub})

	send(m, "H")
	if !stub.ViewPrefs().ShowHidden {
		t.Error("ctrl+h did not record the preference")
	}
	send(m, "H")
	if stub.ViewPrefs().ShowHidden {
		t.Error("ctrl+h did not record the preference the second time")
	}
}

func TestSortingIsRecordedForTheHost(t *testing.T) {
	stub := newStub(row(3000, 3000, "node"))
	m := newTestModel(t, deps{tunnels: stub})

	send(m, "s")
	if got := stub.ViewPrefs().Sort; got != m.sortKey.String() {
		t.Errorf("the sort was recorded as %q, want %q", got, m.sortKey.String())
	}
	send(m, "r")
	if !stub.ViewPrefs().Reverse {
		t.Error("reversing was not recorded")
	}
}

func TestActivityFilterCyclesByClass(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	m.Update(eventMsg(event.Event{Time: testNow, Service: "1password", Class: event.Security, Text: "a secret"}))
	m.Update(eventMsg(event.Event{Time: testNow, Service: "tunnels", Class: event.Network, Text: "a tunnel"}))
	send(m, "2")

	if view := plainView(m); !strings.Contains(view, "a secret") || !strings.Contains(view, "a tunnel") {
		t.Fatalf("the unfiltered tab is missing something:\n%s", view)
	}

	send(m, "f") // security
	if !strings.Contains(bodyLines(m), "a secret") {
		t.Errorf("the security filter dropped a security event:\n%s", bodyLines(m))
	}
	if strings.Contains(bodyLines(m), "a tunnel") {
		t.Errorf("the security filter kept a network event in the list:\n%s", bodyLines(m))
	}

	send(m, "f") // network
	send(m, "f") // lifecycle
	send(m, "f") // back to everything
	if m.logFilter != "" {
		t.Errorf("the filter cycle ended on %q, want everything", m.logFilter)
	}
}

func TestActivitySearchFiltersTheScrollback(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	m.Update(eventMsg(event.Event{Time: testNow, Service: "tunnels", Class: event.Network, Text: "opened 5173"}))
	m.Update(eventMsg(event.Event{Time: testNow, Service: "tunnels", Class: event.Network, Text: "opened 8080"}))
	send(m, "2")

	send(m, "/")
	for _, r := range "5173" {
		send(m, string(r))
	}
	send(m, "enter")

	if m.search[tabActivity] != "5173" {
		t.Fatalf("the search recorded %q", m.search[tabActivity])
	}
	if len(m.logRows) != 1 || !strings.Contains(m.logRows[0].Text, "5173") {
		t.Errorf("the search left %d rows: %+v", len(m.logRows), m.logRows)
	}
}

func TestSecretsTabListsRulesAndRevokesTheSelectedOne(t *testing.T) {
	secrets := &stubSecrets{rules: []authz.Rule{
		{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow},
		{Host: "bedev", Subject: "op://Work/Deploy/key", Action: authz.ActionDeny},
	}}
	m := newTestModel(t, deps{tunnels: newStub(), secrets: oneSource(secrets)})
	send(m, "3")

	view := plainView(m)
	for _, want := range []string{"op://Personal/Docker/PAT", "op://Work/Deploy/key", "allow", "deny"} {
		if !strings.Contains(view, want) {
			t.Errorf("the secrets tab is missing %q:\n%s", want, view)
		}
	}

	send(m, "down")
	send(m, "down") // the second rule
	send(m, "r")
	if len(secrets.revoked) != 1 || secrets.revoked[0] != 1 {
		t.Errorf("revoked %v, want the rule at index 1", secrets.revoked)
	}
	if strings.Contains(bodyLines(m), "op://Work/Deploy/key") {
		t.Errorf("the revoked rule is still listed:\n%s", bodyLines(m))
	}
}

// The one rule of the Access tab: a secret value must never reach the
// clipboard. y copies the reference — the name of the secret, not the secret.
func TestSecretsYankCopiesTheReferenceOnly(t *testing.T) {
	secrets := &stubSecrets{rules: []authz.Rule{
		{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow},
	}}
	m := newTestModel(t, deps{tunnels: newStub(), secrets: oneSource(secrets)})
	send(m, "3")
	send(m, "down")

	if cmd := m.copyReference(); cmd == nil {
		t.Fatal("y copied nothing")
	}
	if !strings.Contains(m.toast.text, "op://Personal/Docker/PAT") {
		t.Errorf("the toast reports %q, want the reference", m.toast.text)
	}
	// There is nowhere for a value to come from: the tab is built from rules,
	// which carry a subject and no secret material at all.
	if strings.Contains(plainView(m), "hunter2") {
		t.Error("a secret value reached the screen")
	}
}

func TestServicesTabShowsWhyAServiceIsUnavailable(t *testing.T) {
	services := []service.Service{
		stubService{meta: service.Meta{ID: "tunnels", Title: "Tunnels", Glyph: "⇄", Short: "forward ports"}},
		stubService{meta: service.Meta{ID: "1password", Title: "1Password", Glyph: "🔒", Short: "serve op"}},
	}
	store := newStubStore()
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: store})

	m.Update(eventMsg(event.Event{Time: testNow, Service: "tunnels", Kind: "started", Class: event.Network, Text: "Tunnels ready"}))
	m.Update(eventMsg(event.Event{
		Time: testNow, Service: "1password", Kind: "unavailable", Class: event.Lifecycle,
		Text: "1Password is unavailable: op is not installed",
	}))
	send(m, "4")

	view := plainView(m)
	for _, want := range []string{"Tunnels", "running", "1Password", "unavailable", "op is not installed"} {
		if !strings.Contains(view, want) {
			t.Errorf("the services tab is missing %q:\n%s", want, view)
		}
	}
}

func TestServicesToggleIsPersisted(t *testing.T) {
	services := []service.Service{
		stubService{meta: service.Meta{ID: "1password", Title: "1Password", Glyph: "🔒"}},
	}
	store := newStubStore()
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: store})
	send(m, "4")
	send(m, "down")
	send(m, "e")

	if store.enabled["1password"] {
		t.Error("e did not switch the service off")
	}
	send(m, "e")
	if !store.enabled["1password"] {
		t.Error("e did not switch it back on")
	}
}

// The settings popup is built from each service's own Configurable, so a
// fourth service gets a row without this package changing.
func TestSettingsPopupOffersServiceSettings(t *testing.T) {
	value := "false"
	services := []service.Service{configurableService{
		stubService{meta: service.Meta{ID: "tunnels", Title: "Tunnels"}},
		[]service.Setting{{
			Key: "show_hidden", Title: "Show hidden ports", Help: "list the ports you hid",
			Get: func() string { return value },
			Set: func(v string) { value = v },
		}},
	}}
	m := newTestModel(t, deps{tunnels: newStub(), services: services})

	send(m, "c")
	if !strings.Contains(plainView(m), "Show hidden ports") {
		t.Fatalf("the service's setting is not in the popup:\n%s", plainView(m))
	}
	// Walk to the row rather than counting presses: the popup also lists a
	// toggle per service, and this test is about the seam, not the order.
	if !moveMenuTo(m, "Show hidden ports") {
		t.Fatalf("the setting is not a menu row")
	}
	send(m, "enter")
	if value != "true" {
		t.Errorf("the setting was not written through the service: %q", value)
	}
	// And back again: left steps the other way, so an overshoot costs one key
	// rather than a lap of the options.
	send(m, "left")
	if value != "false" {
		t.Errorf("left did not step the setting back: %q", value)
	}
}

// The services are switchable from the popup as well as from their tab: `c` is
// where people look for "turn that off for this box".
func TestSettingsPopupTogglesAService(t *testing.T) {
	store := newStubStore()
	services := []service.Service{stubService{meta: service.Meta{ID: "1password", Title: "1Password"}}}
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: store, host: "bedev"})

	send(m, "c")
	if !moveMenuTo(m, "1Password") {
		t.Fatalf("no row for the service:\n%s", plainView(m))
	}
	send(m, "enter")
	if store.enabled["1password"] {
		t.Error("the popup did not switch the service off")
	}
	send(m, "enter")
	if !store.enabled["1password"] {
		t.Error("the popup did not switch it back on")
	}
}

// moveMenuTo walks the settings popup to the row whose title contains want.
func moveMenuTo(m *Model, want string) bool {
	items := m.menuItems()
	for range items {
		if strings.Contains(items[m.menu.cursor].title, want) {
			return true
		}
		send(m, "down")
	}
	return false
}

// configurableService is a stub service that also exposes settings.
type configurableService struct {
	stubService
	settings []service.Setting
}

func (c configurableService) Settings() []service.Setting { return c.settings }

func TestQuittingAsksFirstAndCtrlCDoesNot(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})

	send(m, "esc")
	if !m.confirming {
		t.Fatal("esc did not ask")
	}
	if !strings.Contains(plainView(m), "quit?") {
		t.Errorf("the confirmation is not on screen:\n%s", plainView(m))
	}
	send(m, "n")
	if m.confirming || m.quit {
		t.Error("answering no did not put things back")
	}

	send(m, "ctrl+c")
	if !m.quit {
		t.Error("ctrl+c did not quit immediately")
	}
}

func TestPausingIsReportedInTheHeader(t *testing.T) {
	stub := newStub(row(3000, 3000, "node"))
	m := newTestModel(t, deps{tunnels: stub})

	send(m, "p")
	if !stub.Policy().Paused {
		t.Fatal("p did not pause")
	}
	if !strings.Contains(plainView(m), "PAUSED") {
		t.Errorf("pausing is not visible in the header:\n%s", plainView(m))
	}
}

func TestClickingAColumnHeaderSorts(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"), row(8080, 8080, "python"))})
	m.frame()

	var age column
	for _, c := range m.columns() {
		if c.kind == colAge {
			age = c
		}
	}
	click(m, age.x+1, rowBody)
	if m.sortKey != SortAge {
		t.Errorf("clicking AGE sorted by %v", m.sortKey)
	}
	click(m, age.x+1, rowBody)
	if !m.reverse {
		t.Error("clicking the same header again did not reverse")
	}
}

func TestClickingTheModeCellCyclesIt(t *testing.T) {
	stub := newStub(row(3000, 3000, "node"))
	m := newTestModel(t, deps{tunnels: stub})
	m.frame()

	var mode column
	for _, c := range m.columns() {
		if c.mode {
			mode = c
		}
	}
	click(m, mode.x, rowBody+1)
	if stub.rows[0].Mode != tunnels.ModeOn {
		t.Errorf("clicking M left the mode %q", stub.rows[0].Mode)
	}
}

func TestWheelScrollsTheList(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(
		row(3000, 3000, "a"), row(3001, 3001, "b"), row(3002, 3002, "c"))})

	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if m.cursor() != 0 {
		t.Errorf("the wheel left the cursor at %d", m.cursor())
	}
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if m.cursor() != 1 {
		t.Errorf("the wheel left the cursor at %d", m.cursor())
	}
}

func TestAgeAndTrafficFormatting(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{4 * time.Second, "4s"},
		{12 * time.Minute, "12m"},
		{3*time.Hour + 7*time.Minute, "3h07"},
	}
	for _, c := range cases {
		if got := FormatAge(c.d); got != c.want {
			t.Errorf("FormatAge(%v) = %q, want %q", c.d, got, c.want)
		}
	}
	if got := FormatBytes(1288490); got != "1.2 MB" {
		t.Errorf("FormatBytes = %q, want 1.2 MB", got)
	}
	if got := FormatUptime(14*time.Minute + 22*time.Second); got != "00:14:22" {
		t.Errorf("FormatUptime = %q, want 00:14:22", got)
	}
}

// The key bar is clickable, which is what makes every action discoverable
// without knowing a shortcut — so a click has to run the same thing the key
// does, including where the same letter means different things per tab.
func TestClickingTheKeyBarRunsTheTabsOwnAction(t *testing.T) {
	secrets := &stubSecrets{rules: []authz.Rule{
		{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow},
		{Host: "bedev", Subject: "op://Work/Deploy/key", Action: authz.ActionAllow},
	}}
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node")), secrets: oneSource(secrets)})
	send(m, "3")
	send(m, "down")
	m.frame() // the zones are recorded as the bar renders

	var revoke zone
	for _, z := range m.footerZones {
		if z.id == "r" {
			revoke = z
		}
	}
	if revoke.x1 == 0 {
		t.Fatal("the secrets key bar does not offer revoke")
	}
	click(m, revoke.x0, m.height-1)

	if len(secrets.revoked) != 1 {
		t.Errorf("clicking r on the Access tab revoked %v", secrets.revoked)
	}
}

// A live "allow anything from bedev for 5 minutes" is the most consequential
// state devtun holds. It has to be visible, and revocable one at a time.
func TestSecretsTabListsLiveGrantsFirst(t *testing.T) {
	secrets := &stubSecrets{
		rules: []authz.Rule{{Host: "bedev", Subject: "op://Work/CI", Action: authz.ActionAllow}},
		live: []authz.Grant{
			{Host: "bedev", Subject: "op://Personal/Docker/PAT", Expires: time.Now().Add(5 * time.Minute)},
			{Host: "bedev", Subject: authz.HostWildcard, HostWide: true},
		},
	}
	m := newTestModel(t, deps{secrets: oneSource(secrets)})
	send(m, "3")

	view := plainView(m)
	if !strings.Contains(view, "op://Personal/Docker/PAT") {
		t.Errorf("a live grant is not listed:\n%s", view)
	}
	// A host-wide grant is a different kind of thing and must not read like a
	// grant for one secret.
	if !strings.Contains(view, "anything from bedev") {
		t.Errorf("a host-wide grant should say so:\n%s", view)
	}
	if !strings.Contains(view, "this session") {
		t.Errorf("a grant with no expiry should say it lasts the session:\n%s", view)
	}

	// Grants sort above rules: they are shorter-lived and more consequential.
	grantAt := strings.Index(view, "op://Personal/Docker/PAT")
	ruleAt := strings.Index(view, "op://Work/CI")
	if grantAt < 0 || ruleAt < 0 || grantAt > ruleAt {
		t.Errorf("grants should be listed before rules:\n%s", view)
	}
}

// `r` should not make the user care whether the row is a grant or a rule.
func TestRevokeWorksOnAGrant(t *testing.T) {
	secrets := &stubSecrets{
		live: []authz.Grant{{Host: "bedev", Subject: "op://Personal/Docker/PAT"}},
	}
	m := newTestModel(t, deps{secrets: oneSource(secrets)})
	send(m, "3")
	send(m, "down")
	send(m, "r")

	if len(secrets.revokedBy) != 1 {
		t.Fatalf("want the grant revoked, got %v", secrets.revokedBy)
	}
	if len(secrets.revoked) != 0 {
		t.Errorf("a grant must not be revoked through the rule path: %v", secrets.revoked)
	}
	// Assert on the rows, not the frame: the success toast names the subject
	// too, and would happily satisfy a substring check on the whole view.
	for _, row := range m.accessRows {
		if row.isGrant && row.grant.Subject == "op://Personal/Docker/PAT" {
			t.Error("the revoked grant is still listed")
		}
	}
}

// A tab that shows only the rules devtun wrote sends somebody hunting for one
// that is right there in their own config file.
func TestSecretsTabShowsGlobalRulesButWillNotRevokeThem(t *testing.T) {
	secrets := &stubSecrets{
		rules:  []authz.Rule{{Host: "bedev", Subject: "op://Work/CI", Action: authz.ActionAllow}},
		global: []authz.Rule{{Host: "**", Subject: "op://Private/**", Action: authz.ActionDeny}},
	}
	m := newTestModel(t, deps{secrets: oneSource(secrets)})
	send(m, "3")

	view := plainView(m)
	if !strings.Contains(view, "op://Private/**") {
		t.Errorf("a global rule is not listed:\n%s", view)
	}
	if !strings.Contains(view, "from your config") {
		t.Errorf("a global rule should say where it came from:\n%s", view)
	}

	// Select the global rule — it is listed after the host's own — and try.
	send(m, "down")
	send(m, "down")
	send(m, "r")

	if len(secrets.revoked) != 0 {
		t.Errorf("a global rule must not be revoked through the interface: %v", secrets.revoked)
	}
	// Assert on the toast itself, not the rendered frame. Whether a message
	// fits the footer depends on the terminal width and, before this was
	// fixed, on how long the machine's home directory happened to be — which
	// is not what this test is about.
	if !m.hasToast || !strings.Contains(m.toast.text, "config file") {
		t.Errorf("the refusal should say where to edit it instead, got %q", m.toast.text)
	}
}

// A refusal is live state too, and reading it as a grant would invert what it
// says.
func TestLiveRefusalReadsAsARefusal(t *testing.T) {
	secrets := &stubSecrets{live: []authz.Grant{
		{Host: "bedev", Subject: "op://Private/Root", Action: authz.ActionDeny},
	}}
	m := newTestModel(t, deps{secrets: oneSource(secrets)})
	send(m, "3")

	view := plainView(m)
	if !strings.Contains(view, "refuse") {
		t.Errorf("a deny grant should read as a refusal:\n%s", view)
	}
	if strings.Contains(view, "grant  ") {
		t.Errorf("a deny grant must not be labelled as a grant:\n%s", view)
	}
}

// b opens the selected port in a browser. o and space do too, but b is the
// letter people guess and the one the key bar has room to advertise.
func TestBOpensThePortInABrowser(t *testing.T) {
	var opened string
	m := newTestModel(t, deps{
		tunnels: newStub(row(3000, 3000, "node vite")),
		openURL: func(_ context.Context, url string) error { opened = url; return nil },
	})
	send(m, "down")
	send(m, "b")
	if opened != "http://127.0.0.1:3000" {
		t.Errorf("b opened %q", opened)
	}
}

// A port whose protocol nobody has established asks before opening, rather than
// guessing and handing the browser a page that will not load.
func TestBAsksForTheProtocolWhenItIsUnknown(t *testing.T) {
	unknown := row(8080, 8080, "python3 -m http.server")
	unknown.Scheme = tunnels.SchemeUnknown
	var opened string
	m := newTestModel(t, deps{
		tunnels: newStub(unknown),
		openURL: func(_ context.Context, url string) error { opened = url; return nil },
	})
	send(m, "down")
	send(m, "b")
	if !m.protocolPrompt {
		t.Fatal("b did not ask which protocol to use")
	}
	send(m, "s")
	if opened != "https://127.0.0.1:8080" {
		t.Errorf("choosing https opened %q", opened)
	}
}

// D rewrites an allow you regret as a deny, which is the edit people want in a
// hurry: not just "stop allowing this" but "and stop asking me too".
func TestDenyTightensTheSelectedRule(t *testing.T) {
	secrets := &stubSecrets{rules: []authz.Rule{
		{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow},
	}}
	m := newTestModel(t, deps{tunnels: newStub(), secrets: oneSource(secrets)})
	send(m, "3")
	send(m, "down")
	send(m, "D")

	if len(secrets.denied) != 1 {
		t.Fatalf("D did not rewrite the rule, denied = %v", secrets.denied)
	}
	if secrets.rules[0].Action != authz.ActionDeny {
		t.Errorf("the rule is still %q", secrets.rules[0].Action)
	}
}

// It only ever tightens, and it never pretends to edit a file devtun did not
// write. The global rules are listed so you can see what is deciding; changing
// one there would be rewriting something you typed.
func TestDenyRefusesWhatItCannotTighten(t *testing.T) {
	secrets := &stubSecrets{
		live:   []authz.Grant{{Host: "bedev", Subject: "op://Personal/Docker/PAT"}},
		global: []authz.Rule{{Host: "*", Subject: "op://Private/**", Action: authz.ActionAllow}},
	}
	m := newTestModel(t, deps{tunnels: newStub(), secrets: oneSource(secrets)})
	send(m, "3")

	// The grant is listed first, the global rule last.
	send(m, "down")
	send(m, "D")
	if len(secrets.denied) != 0 {
		t.Errorf("D rewrote a live grant as a rule")
	}
	send(m, "down")
	send(m, "D")
	if len(secrets.denied) != 0 {
		t.Errorf("D rewrote a rule from the config file")
	}
	if !strings.Contains(plainView(m), "edit it there") {
		t.Errorf("nothing said why:\n%s", plainView(m))
	}
}
