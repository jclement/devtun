package tui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/browser"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
)

// --- #1: changing an existing rule's match confirms, deny or not ----------

// denyEditFixture is a remembered deny for op://Work/** with an allow beneath
// it that would win anything the deny stops covering.
func denyEditFixture(t *testing.T) (*Model, *stubSecrets) {
	t.Helper()
	op := &stubSecrets{rules: []authz.Rule{
		{Host: "bedev", Subject: "op://Work/**", Action: authz.ActionDeny, Source: authz.SourceRemembered},
		{Host: "bedev", Subject: "op://Work/Deploy/key", Action: authz.ActionAllow, Source: authz.SourceHost},
	}}
	all, _ := prompt.ParseSurfaces("all")
	m := newTestModel(t, deps{secrets: oneSource(op), promptBackend: all})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	send(m, "3")
	return m, op
}

func TestNarrowingADenyConfirmsBeforeItLoosens(t *testing.T) {
	m, op := denyEditFixture(t)
	selectSubject(m, "op://Work/**")
	send(m, "w")
	m.form.fields.values[0].SetValue("op://Work/CI/token")
	send(m, "enter")
	if m.confirm == nil || len(op.updated) != 0 {
		t.Fatal("narrowing a deny was saved without a confirm")
	}
	if !strings.Contains(m.confirm.title, "deny") || !strings.Contains(plainView(m), "stops being") {
		t.Errorf("the confirm does not say what stops being refused:\n%s", plainView(m))
	}
	send(m, "y")
	if len(op.updated) != 1 || *op.updated[0].Subject != "op://Work/CI/token" {
		t.Errorf("the update was %+v", op.updated)
	}
}

func TestMovingADenyThroughTheMenuConfirms(t *testing.T) {
	m, op := denyEditFixture(t)
	selectSubject(m, "op://Work/**")
	send(m, ".")
	for i, it := range m.menu.items {
		if it.key == "w" {
			m.menu.cursor = i
		}
	}
	send(m, "enter")
	if m.form == nil {
		t.Fatal("the menu did not open the form")
	}
	m.form.fields.values[0].SetValue("op://Elsewhere/**")
	send(m, "enter")
	if m.confirm == nil || len(op.updated) != 0 {
		t.Fatal("moving a deny was saved without a confirm")
	}
	send(m, "n")
	if m.form == nil || len(op.updated) != 0 {
		t.Error("n on the confirm did not go back to the form")
	}
}

// A note-only edit, and a genuinely new deny, change nothing anyone can reach
// and stay immediate.
func TestNoteOnlyEditsAndNewDeniesStayImmediate(t *testing.T) {
	m, op := denyEditFixture(t)
	selectSubject(m, "op://Work/**")
	send(m, "w")
	m.form.note.SetValue("nothing from Work, ever")
	send(m, "enter")
	if m.confirm != nil || len(op.updated) != 1 {
		t.Errorf("a note-only edit asked (confirm=%v) or did not save (%d)", m.confirm != nil, len(op.updated))
	}

	m.setCursor(noSelection)
	send(m, "n")
	m.form.fields.values[0].SetValue("op://Private/**")
	m.form.effect = authz.ActionDeny
	send(m, "enter")
	if m.confirm != nil || len(op.addedRules) != 1 {
		t.Error("a new deny asked first")
	}
}

// --- #3: the form is routed by the request's broker, and locked to it ------

func twoBrokerModel(t *testing.T) (*Model, *stubSecrets, *stubSecrets) {
	t.Helper()
	op := &stubSecrets{}
	web := &stubSecrets{}
	bs := browser.Schema
	web.schema = &bs
	m := newTestModel(t, deps{secrets: []accessSource{
		{id: "1password", title: "1Password", ctrl: op},
		{id: "browser", title: "Browser", ctrl: web},
	}})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	return m, op, web
}

func askWith(m *Model, r prompt.Request) chan prompt.Choice {
	reply := make(chan prompt.Choice, 1)
	r.TTL = time.Minute
	m.Update(approvalMsg{request: r, options: prompt.MenuFor(r), reply: reply})
	return reply
}

// Both brokers have single-field subjects; the old guess picked 1Password.
func TestABrowserApprovalOpensABrowserForm(t *testing.T) {
	m, op, web := twoBrokerModel(t)
	reply := askWith(m, prompt.Request{Service: "browser", Host: "bedev", Subject: "github.com", Noun: "site"})
	send(m, "w")
	if m.form == nil || m.form.fields.source(m).id != "browser" {
		t.Fatalf("w opened a form for %v", m.form)
	}
	// The broker is locked: switching it is refused.
	m.form.focus = focusService
	send(m, "right")
	if m.form.fields.source(m).id != "browser" {
		t.Error("the broker of an approval's form could be switched")
	}
	send(m, "enter")
	send(m, "y")
	if len(web.addedRules) != 1 || len(op.addedRules) != 0 {
		t.Errorf("rules written: browser %d, 1password %d", len(web.addedRules), len(op.addedRules))
	}
	if got := <-reply; got != prompt.ChoiceAllowOnce {
		t.Errorf("the browser request was answered %v", got)
	}
}

// A subject that happens to contain another broker's separator still goes to
// the broker that asked.
func TestASeparatorInTheSubjectDoesNotMisroute(t *testing.T) {
	m, _, _ := sourcedFixture(t) // 1password and ssh-agent
	askWith(m, prompt.Request{Service: "1password", Host: "bedev", Subject: "op item create --title a → b"})
	send(m, "w")
	if m.form == nil || m.form.fields.source(m).id != "1password" {
		t.Fatalf("a 1Password request with an arrow in it opened %+v", m.form)
	}
}

// No service id, no form: the approval stays as it was.
func TestARequestWithNoBrokerGetsNoForm(t *testing.T) {
	m, _, _ := twoBrokerModel(t)
	askWith(m, prompt.Request{Host: "bedev", Subject: "github.com"})
	send(m, "w")
	if m.form != nil || m.approval == nil {
		t.Errorf("w on an unattributed request: form=%v approval=%v", m.form != nil, m.approval != nil)
	}
	if strings.Contains(plainView(m), "w write a broader rule") {
		t.Error("the prompt offers w for a request it cannot route")
	}
}

// A covering rule answers only a request from the same broker and host.
func TestARuleAnswersOnlyItsOwnBrokersRequest(t *testing.T) {
	m, _, _ := twoBrokerModel(t)
	reply := askWith(m, prompt.Request{Service: "browser", Host: "otherbox", Subject: "github.com", Noun: "site"})
	send(m, "w")
	send(m, "enter")
	send(m, "y")
	select {
	case got := <-reply:
		t.Errorf("a request from another host was answered %v", got)
	default:
	}
	if m.approval == nil {
		t.Error("the unanswered request did not come back")
	}
}

// --- #5: cancellation reaches an approval parked in the form ---------------

func TestACancelledApprovalNeverComesBack(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	reply := askWith(m, prompt.Request{Service: "1password", Host: "bedev", Subject: "op://Shared/Dev/token"})
	send(m, "w")
	// It times out, or is answered on the board, while the form is open.
	m.Update(approvalCancelMsg{reply: reply})
	if !strings.Contains(plainView(m), "has gone") {
		t.Errorf("the form does not say its request has gone:\n%s", plainView(m))
	}
	send(m, "esc")
	if m.approval != nil {
		t.Fatal("esc restored a cancelled approval")
	}
	if len(op.addedRules) != 0 {
		t.Error("something was written")
	}
}

// The confirm is open when the cancellation lands: saving still writes the
// rule, answers nothing, and a second approval afterwards is the one shown.
func TestCancellationDuringTheConfirmThenASecondApproval(t *testing.T) {
	m, op, _ := sourcedFixture(t)
	first := askWith(m, prompt.Request{Service: "1password", Host: "bedev", Subject: "op://Shared/Dev/token"})
	send(m, "w")
	send(m, "enter") // an allow: the confirm opens
	if m.confirm == nil {
		t.Fatal("no confirm")
	}
	m.Update(approvalCancelMsg{reply: first})
	send(m, "y")
	if len(op.addedRules) != 1 {
		t.Fatalf("the rule was not written: %+v", op.addedRules)
	}
	select {
	case got := <-first:
		t.Errorf("a cancelled approval was answered %v", got)
	default:
	}
	if m.approval != nil {
		t.Fatal("the cancelled approval came back after the save")
	}

	second := askWith(m, prompt.Request{Service: "1password", Host: "bedev", Subject: "op://Other/x/y"})
	if m.approval == nil || m.approval.request.Subject != "op://Other/x/y" {
		t.Fatalf("the second approval is not on screen: %+v", m.approval)
	}
	send(m, "7") // No
	if got := <-second; got != prompt.ChoiceDeny {
		t.Errorf("the second approval was answered %v", got)
	}
	if m.approval != nil || m.form != nil {
		t.Error("something stale is still open")
	}
}

// A new question while one is parked in the form means the parked one is
// over; it is detached, not resurrected after the new one is answered.
func TestANewApprovalDetachesAParkedOne(t *testing.T) {
	m, _, _ := sourcedFixture(t)
	askWith(m, prompt.Request{Service: "1password", Host: "bedev", Subject: "op://A/b/c"})
	send(m, "w")
	b := askWith(m, prompt.Request{Service: "1password", Host: "bedev", Subject: "op://B/b/c"})
	send(m, "7")
	<-b
	if m.form == nil || m.form.answering != nil {
		t.Fatal("the parked approval is still attached to the form")
	}
	send(m, "esc")
	if m.approval != nil {
		t.Error("esc brought back the parked approval")
	}
}

// --- #2 (TUI): a Config edit that loosens unmatched confirms ---------------

func TestConfigConfirmsAnUnmatchedChangeThatLoosens(t *testing.T) {
	op := &stubSecrets{}
	store := newTestStore(t)
	if err := store.SetSetting("bedev", "1password", "unmatched", "deny"); err != nil {
		t.Fatal(err)
	}
	services := []service.Service{policyService{stubService{meta: service.Meta{ID: "1password", Title: "1Password", Glyph: "❖"}}, op}}
	m := newTestModel(t, deps{services: services, secrets: oneSource(op), store: store})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	send(m, "5")
	for i, r := range m.cfgRows {
		if r.setting != nil && r.setting.Key == "unmatched.1password" {
			m.setCursor(i)
		}
	}
	send(m, "left") // deny → ask
	if m.confirm == nil {
		t.Fatal("deny → ask was applied without a confirm")
	}
	if got := store.Setting("bedev", "1password", "unmatched"); got != "deny" {
		t.Fatalf("written before the confirm: %q", got)
	}
	send(m, "y")
	if got := store.Setting("bedev", "1password", "unmatched"); got != "ask" {
		t.Fatalf("after y the setting is %q", got)
	}
	send(m, "right") // ask → deny: tightens, immediate
	if m.confirm != nil {
		t.Error("ask → deny asked first")
	}
	if got := store.Setting("bedev", "1password", "unmatched"); got != "deny" {
		t.Errorf("ask → deny left %q", got)
	}
}

// --- wording: removal says what actually happens next ----------------------

func TestRemovingARefusalSaysWhatActuallyHappensNext(t *testing.T) {
	// An allow underneath: it would win at once.
	m, _ := denyEditFixture(t)
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	op := m.d.secrets[0].ctrl.(*stubSecrets)
	op.rules = append(op.rules, authz.Rule{Host: "bedev", Subject: "op://Work/Deploy/key", Action: authz.ActionDeny, Source: authz.SourceRemembered})
	m.reload()
	for i, r := range m.accessRows {
		if r.subject() == "op://Work/Deploy/key" && r.action() == authz.ActionDeny {
			m.setCursor(i)
		}
	}
	send(m, "r")
	view := plainView(m)
	if !strings.Contains(view, "It stays refused") {
		t.Errorf("with op://Work/** still denying it, the confirm should say it stays refused:\n%s", view)
	}
	send(m, "n")

	// A global deny names all hosts as who it applies to.
	g := &stubSecrets{global: []authz.Rule{{Host: "dev-*", Subject: "op://X/**", Action: authz.ActionDeny}}}
	all, _ := prompt.ParseSurfaces("all")
	m2 := newTestModel(t, deps{secrets: oneSource(g), promptBackend: all})
	m2.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	send(m2, "3")
	r, ok := accessRowBySubject(m2, "op://X/**")
	if !ok {
		t.Fatal("no global row")
	}
	c := m2.loosenConfirm(r)
	text := strings.Join(c.body, "\n")
	if !strings.Contains(text, "hosts dev-*") || !strings.Contains(text, "asked about it again") {
		t.Errorf("the confirm should name hosts dev-* and that it will be asked:\n%s", text)
	}
}

func accessRowBySubject(m *Model, s string) (accessRow, bool) {
	for _, r := range m.accessRows {
		if r.heading == "" && r.subject() == s {
			return r, true
		}
	}
	return accessRow{}, false
}
