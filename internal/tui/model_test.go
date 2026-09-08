package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
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
	m.tab = tabCount - 1
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
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: newTestStore(t)})

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
	store := newTestStore(t)
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: store})
	send(m, "4")
	send(m, "down")
	send(m, "e")

	if store.Enabled("bedev", "1password", true) {
		t.Error("e did not switch the service off")
	}
	send(m, "e")
	if !store.Enabled("bedev", "1password", false) {
		t.Error("e did not switch it back on")
	}
}

// c is in people's fingers from when the settings were a popup, so it still
// leads to them — now by selecting the tab rather than covering the screen.
func TestCReachesTheConfigTab(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(), store: newTestStore(t)})

	send(m, "c")
	if m.tab != tabConfig {
		t.Fatalf("c selected %v, want Config", m.tab)
	}
	view := bodyLines(m)
	// The setting the owner went looking for, at the top of the tab, with the
	// two things a value on this screen has to carry.
	for _, want := range []string{"Approvals", "Approvals appear", "auto", "default"} {
		if !strings.Contains(view, want) {
			t.Errorf("the Config tab is missing %q:\n%s", want, view)
		}
	}
}

// The whole argument for a Config tab over a popup: a value is only useful
// alongside which file said so.
func TestConfigProvenanceNamesTheLevelAValueCameFrom(t *testing.T) {
	store := newTestStore(t)
	m := newTestModel(t, deps{tunnels: newStub(), store: store})
	send(m, "c")

	if got := configRowText(t, m, "prompt"); !strings.Contains(got, "auto") || !strings.Contains(got, "default") {
		t.Errorf("with nothing configured the row reads %q, want devtun's own default", got)
	}

	if err := store.SetSetting("", "", hostcfg.KeyPrompt, "dialog"); err != nil {
		t.Fatal(err)
	}
	m.reload()
	if got := configRowText(t, m, "prompt"); !strings.Contains(got, "dialog") || !strings.Contains(got, "global") {
		t.Errorf("a global setting reads %q, want dialog from the global file", got)
	}

	if err := store.SetSetting("bedev", "", hostcfg.KeyPrompt, "tui"); err != nil {
		t.Fatal(err)
	}
	m.reload()
	if got := configRowText(t, m, "prompt"); !strings.Contains(got, "tui") || !strings.Contains(got, "host") {
		t.Errorf("a host setting reads %q, want tui from the host file", got)
	}

	// And clearing the host's answer falls back to the global one, provenance
	// and all: a cleared level must not pin what it happened to be showing.
	moveConfigTo(t, m, "prompt")
	send(m, "left") // tui → auto
	send(m, "left") // auto → inherit, which clears the host's answer
	if got := configRowText(t, m, "prompt"); !strings.Contains(got, "dialog") || !strings.Contains(got, "global") {
		t.Errorf("a cleared host reads %q, want the global answer back", got)
	}
}

// The setting the owner could not find, doing the thing he wanted it to do: it
// has to change where this session asks, not only what a future one would read.
func TestThePromptSettingChangesWhereThisSessionAsks(t *testing.T) {
	var applied []prompt.Backend
	store := newTestStore(t)
	m := newTestModel(t, deps{
		tunnels:       newStub(),
		store:         store,
		promptBackend: prompt.BackendAuto,
		applyPrompt:   func(b prompt.Backend) { applied = append(applied, b) },
	})

	send(m, "c")
	moveConfigTo(t, m, "prompt")
	send(m, "right") // inherit → auto
	send(m, "right") // auto → tui

	if got := store.Setting("bedev", "", hostcfg.KeyPrompt); got != "tui" {
		t.Errorf("the host file records %q, want tui", got)
	}
	if len(applied) == 0 || applied[len(applied)-1] != prompt.BackendTUI {
		t.Errorf("the session was told %v, want the prompter rebuilt as tui", applied)
	}

	// And left is the way back, without a lap of the options: clearing the host
	// value leaves the row inheriting rather than pinning what it showed.
	send(m, "left")
	send(m, "left")
	if got := store.Setting("bedev", "", hostcfg.KeyPrompt); got != "" {
		t.Errorf("stepping back to inherit left %q in the host file", got)
	}
}

// g aims an edit at the other file, and the two must stay independent: setting
// one box's preference cannot quietly rewrite the answer every other box uses.
func TestTargetingWritesToTheFileThatIsArmed(t *testing.T) {
	dir := t.TempDir()
	store := hostcfg.Open(dir)
	if err := store.SetSetting("", "", hostcfg.KeyPrompt, "dialog"); err != nil {
		t.Fatal(err)
	}
	m := newTestModel(t, deps{tunnels: newStub(), store: store})
	send(m, "c")
	moveConfigTo(t, m, "prompt")

	// Armed at the host by default: the host file gains a value, the global one
	// keeps the one it had.
	send(m, "right")
	if got := store.Setting("", "", hostcfg.KeyPrompt); got != "dialog" {
		t.Errorf("editing the host rewrote the global setting to %q", got)
	}
	if got := store.Setting("bedev", "", hostcfg.KeyPrompt); got != "auto" {
		t.Errorf("the host file records %q, want auto", got)
	}

	// And with g armed the other way, the global file is what moves.
	send(m, "g")
	send(m, "right")
	if got := store.Setting("", "", hostcfg.KeyPrompt); got == "dialog" {
		t.Error("g did not aim the edit at the global file")
	}
	if got := store.Setting("bedev", "", hostcfg.KeyPrompt); got != "auto" {
		t.Errorf("editing the global file changed the host's value to %q", got)
	}

	// It is two files on disk, not two maps: the tab saves as it goes, so a
	// laptop that dies before the session ends keeps the setting.
	global, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("the global file was not written: %v", err)
	}
	if !strings.Contains(string(global), "prompt:") {
		t.Errorf("the global file holds no prompt setting:\n%s", global)
	}
	host, err := os.ReadFile(filepath.Join(dir, "hosts", "bedev.yaml"))
	if err != nil {
		t.Fatalf("the host file was not written: %v", err)
	}
	if !strings.Contains(string(host), "prompt: auto") {
		t.Errorf("the host file holds no prompt setting:\n%s", host)
	}
}

// A hide list that will not parse fails silently and in the wrong direction:
// the ports it was written to hide are forwarded, and only on the next
// connection, long after anyone would connect the two.
func TestABadPortListIsRefusedRatherThanSaved(t *testing.T) {
	store := newTestStore(t)
	m := newTestModel(t, deps{tunnels: newStub(), store: store})
	send(m, "c")
	moveConfigTo(t, m, "hide.host")

	send(m, "enter")
	if m.editor != editorConfigValue {
		t.Fatalf("enter on a list did not open the editor, editor = %v", m.editor)
	}
	typeIn(m, "not-a-port")
	send(m, "enter")

	if got := store.Setting("bedev", "tunnels", hostcfg.KeyHide); got != "" {
		t.Errorf("a list that will not parse was saved as %q", got)
	}
	if !m.hasToast || !m.toast.bad {
		t.Errorf("nothing said the list was refused, toast = %q", m.toast.text)
	}

	// And one that parses is kept, ranges included — the reason the list exists
	// at all is the ephemeral range no per-port key can cover.
	send(m, "enter")
	typeIn(m, "5432,32768-60999")
	send(m, "enter")
	if got := store.Setting("bedev", "tunnels", hostcfg.KeyHide); got != "5432,32768-60999" {
		t.Errorf("the host's hide list is %q", got)
	}
}

// `dialog` on a machine with nothing to draw one with falls back to asking in
// this window. That is right, and completely invisible from a screen that
// renders the word "dialog" and stops there.
func TestThePromptRowSaysWhatThisMachineCanActuallyDo(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(), store: newTestStore(t)})
	none := ""
	m.dialogPick = &none
	send(m, "c")
	m.reload()

	row := configRowText(t, m, "prompt")
	if !strings.Contains(row, "no dialog program here") {
		t.Errorf("the row does not say a dialog cannot be drawn here:\n%s", row)
	}
	for _, name := range prompt.ChooserNames() {
		if !strings.Contains(row, name) {
			t.Errorf("the row does not name %q as what to install:\n%s", name, row)
		}
	}

	// Choosing it anyway is allowed — the file may be right on the machine it
	// is synced to next — but it must not pass without a word.
	moveConfigTo(t, m, "prompt")
	for range 3 { // inherit → auto → tui → dialog
		send(m, "right")
	}
	if !strings.Contains(m.toast.text, "no dialog program") || !m.toast.bad {
		t.Errorf("choosing dialog with nothing to draw it said %q", m.toast.text)
	}
}

// The rows are still the services' own, discovered by interface, so a sixth
// service gets its settings on this tab without this package changing.
func TestServiceSettingsAreStillDiscoveredByInterface(t *testing.T) {
	value := "false"
	services := []service.Service{configurableService{
		stubService{meta: service.Meta{ID: "tunnels", Title: "Tunnels"}},
		[]service.Setting{{
			Key: "show_hidden", Title: "Show hidden ports", Help: "list the ports you hid",
			Get: func() string { return value },
			Set: func(v string) { value = v },
		}},
	}}
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: newTestStore(t)})

	send(m, "c")
	if !strings.Contains(bodyLines(m), "Show hidden ports") {
		t.Fatalf("the service's setting is not on the tab:\n%s", bodyLines(m))
	}
	moveConfigTo(t, m, "tunnels.show_hidden")
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

// Whether a service runs at all is a setting like any other here, and it is the
// one with two levels people actually use: off everywhere, on for this box.
func TestAServiceIsSwitchableAtEitherLevel(t *testing.T) {
	store := newTestStore(t)
	services := []service.Service{stubService{meta: service.Meta{ID: "1password", Title: "1Password"}}}
	m := newTestModel(t, deps{tunnels: newStub(), services: services, store: store})

	send(m, "c")
	moveConfigTo(t, m, "1password")
	send(m, "right") // inherit → on
	send(m, "right") // on → off
	if got := store.Setting("bedev", hostcfg.SectionServices, "1password"); got != "false" {
		t.Errorf("the host file records %q, want the service off", got)
	}
	if got := store.Setting("", hostcfg.SectionServices, "1password"); got != "" {
		t.Errorf("switching it off here wrote %q to the global file", got)
	}

	send(m, "g")
	send(m, "right")
	if got := store.Setting("", hostcfg.SectionServices, "1password"); got != "true" {
		t.Errorf("the global file records %q, want the service on", got)
	}
	// The host still wins, which is what the provenance column has to say.
	if store.Enabled("bedev", "1password", true) {
		t.Error("the host's explicit off stopped winning")
	}
	if got := configRowText(t, m, "1password"); !strings.Contains(got, "host") {
		t.Errorf("the row reads %q, want the host named as what is deciding", got)
	}
}

// Headings are structure, not settings: a cursor that could land on one arms
// keys with nothing to act on.
func TestTheCursorSkipsSectionHeadings(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(), store: newTestStore(t)})
	send(m, "c")
	if m.cfgRows[0].setting != nil {
		t.Fatal("the tab does not start with a heading, so this proves nothing")
	}

	for range len(m.cfgRows) + 2 {
		send(m, "down")
		if s := m.selectedSetting(); s == nil {
			t.Fatalf("the cursor landed on the heading at row %d", m.cursor())
		}
	}
	for range len(m.cfgRows) + 2 {
		send(m, "up")
		if s := m.selectedSetting(); s == nil {
			t.Fatalf("moving up landed on the heading at row %d", m.cursor())
		}
	}
}

// configRowText is the rendered line for one setting, with styling stripped.
func configRowText(t *testing.T, m *Model, key string) string {
	t.Helper()
	for _, row := range m.cfgRows {
		if row.setting != nil && row.setting.key == key {
			return ansi.Strip(m.configLine(row, false))
		}
	}
	t.Fatalf("no config row keyed %q", key)
	return ""
}

// moveConfigTo walks the Config tab to the row with this key, rather than
// counting presses: the sections list services and this package's own settings,
// and a test about one of them should not break when another is added.
func moveConfigTo(t *testing.T, m *Model, key string) {
	t.Helper()
	for range len(m.cfgRows) + 1 {
		if s := m.selectedSetting(); s != nil && s.key == key {
			return
		}
		send(m, "down")
	}
	t.Fatalf("never reached the row keyed %q:\n%s", key, bodyLines(m))
}

// typeIn sends a string to whichever inline editor is open.
func typeIn(m *Model, text string) {
	for _, r := range text {
		send(m, string(r))
	}
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
	// The header used to be the first body row. The summary strip now sits
	// above it, so the test asks where the data starts rather than counting
	// from the top of the body — what it is really asserting is that a click
	// on a column title sorts, not which line the titles are drawn on.
	header := m.listTop() - 1
	click(m, age.x+1, header)
	if m.sortKey != SortAge {
		t.Errorf("clicking AGE sorted by %v", m.sortKey)
	}
	click(m, age.x+1, header)
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
	// listTop, not rowBody+1: the first data row moved down when the summary
	// strip arrived, and the assertion is about the M cell, not the offset.
	click(m, mode.x, m.listTop())
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

// --- regressions the audit turned up ---------------------------------------

// The owner's complaint: you could not select or copy anything, because mouse
// reporting is on and the terminal hands drags to devtun instead.
func TestMouseCanBeTurnedOffSoTheTerminalCanSelect(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub(row(3000, 3000, "node"))})
	if m.View().MouseMode == 0 {
		t.Fatal("mouse reporting is off by default, so rows would not be clickable")
	}

	send(m, "m")
	if m.View().MouseMode != 0 {
		t.Error("m did not release the mouse")
	}
	if !strings.Contains(plainView(m), "select text") {
		t.Errorf("nothing said what just happened:\n%s", plainView(m))
	}

	send(m, "m")
	if m.View().MouseMode == 0 {
		t.Error("m did not take the mouse back")
	}
}

// A grant keeps its subject in .grant and leaves .rule zero. Reading .rule
// copied the empty string and wiped the clipboard, while the toast said
// "copied" — and grants are the first rows on the tab.
func TestCopyingAGrantCopiesItsSubject(t *testing.T) {
	secrets := &stubSecrets{live: []authz.Grant{
		{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow},
	}}
	m := newTestModel(t, deps{tunnels: newStub(), secrets: oneSource(secrets)})
	send(m, "3")
	send(m, "down")
	send(m, "y")

	view := plainView(m)
	if !strings.Contains(view, "copied op://Personal/Docker/PAT") {
		t.Errorf("the grant's subject was not copied:\n%s", view)
	}
}

// The reconnect box was the one overlay you could act straight through: a
// click still moved the cursor and x still hid a port, behind a box saying the
// connection was gone.
func TestTheReconnectBoxCannotBeActedThrough(t *testing.T) {
	stub := newStub(row(3000, 3000, "node"), row(8080, 8080, "python3"))
	m := newTestModel(t, deps{tunnels: stub})
	m.status = session.Status{State: session.Disconnected}
	m.everConnected = true

	if !m.overlayOpen() {
		t.Fatal("a lost connection is a modal and must report itself as one")
	}

	// Every visible row is still auto: nothing behind the box was touched.
	click(m, 5, m.listTop())
	send(m, "x")
	for _, st := range stub.States() {
		if st.Mode == tunnels.ModeHidden {
			t.Errorf("port %d was hidden from behind the reconnect box", st.RemotePort)
		}
	}
	if m.cursor() != noSelection {
		t.Errorf("a click behind the box moved the cursor to %d", m.cursor())
	}
}

// r meant reverse-sort, revoke, or reconnect depending on whether the link
// happened to be up. R means reconnect, always.
func TestReconnectHasAKeyOfItsOwn(t *testing.T) {
	var retried int
	m := newTestModel(t, deps{
		tunnels: newStub(row(3000, 3000, "node")),
		retry:   func() { retried++ },
	})

	send(m, "R")
	if retried != 1 {
		t.Errorf("R did not reconnect while connected (%d)", retried)
	}
}
