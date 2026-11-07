package tui

import (
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/ui"
)

// The test box and the rule form.
//
// They share a shape: pick a broker, fill in its subject one named field at a
// time — the broker's schema says what the fields are — and watch the store's
// own answer change as you type. The test box only asks; the form writes. The
// form's preview is the test box's answer, so what it says a rule will do is
// what the store will actually do with it, not a second opinion.

// fieldSet is a broker choice plus one text input per subject field.
type fieldSet struct {
	src    int
	values []textInput
}

func (m *Model) newFieldSet(src int, subject string) fieldSet {
	fs := fieldSet{src: src}
	fs.reset(m, subject)
	return fs
}

// reset re-splits a subject into the current broker's fields.
func (fs *fieldSet) reset(m *Model, subject string) {
	schema := m.d.secrets[fs.src].ctrl.Schema()
	parts := schema.Split(subject)
	fs.values = make([]textInput, len(schema.Fields))
	for i := range fs.values {
		if i < len(parts) {
			fs.values[i].SetValue(parts[i])
		}
	}
}

func (fs fieldSet) source(m *Model) accessSource { return m.d.secrets[fs.src] }

func (fs fieldSet) subject(m *Model) string {
	vals := make([]string, len(fs.values))
	for i := range fs.values {
		vals[i] = strings.TrimSpace(fs.values[i].Value())
	}
	return fs.source(m).ctrl.Schema().Join(vals)
}

// cycleFormBroker steps the form's broker, unless it is locked to the
// approval it came from.
func (m *Model) cycleFormBroker(delta int) {
	if m.form.answering != nil {
		_ = m.showToast(toastMsg{text: "this rule is for the " + m.form.fields.source(m).title + " request waiting on it", bad: true})
		return
	}
	m.form.fields.cycleBroker(m, delta)
}

// cycleBroker steps to the next broker, keeping what was typed where it still
// makes sense.
func (fs *fieldSet) cycleBroker(m *Model, delta int) {
	n := len(m.d.secrets)
	if n < 2 {
		return
	}
	subject := fs.subject(m)
	fs.src = ((fs.src+delta)%n + n) % n
	fs.reset(m, subject)
}

// renderFields draws the broker picker and the fields, with focus marked.
// focus counts the picker as 0 and the fields from 1.
func (m *Model) renderFields(fs fieldSet, focus int) string {
	var b strings.Builder
	label := func(s string, on bool) string {
		if on {
			return ui.Banner.Render("▸ " + pad(s, 12))
		}
		return ui.Muted.Render("  " + pad(s, 12))
	}
	var chips []string
	for i, src := range m.d.secrets {
		name := ui.ShortService(src.id)
		if i == fs.src {
			chips = append(chips, ui.Button.Render(" "+name+" "))
		} else {
			chips = append(chips, ui.Muted.Render(" "+name+" "))
		}
	}
	b.WriteString(label("service", focus == 0) + strings.Join(chips, " ") + "\n")
	schema := fs.source(m).ctrl.Schema()
	for i, f := range schema.Fields {
		in := fs.values[i]
		value := ui.Secret.Render(in.Value())
		if focus == i+1 {
			value = ui.Secret.Render(in.Render())
		}
		b.WriteString(label(f.Label, focus == i+1) + value + "\n")
		if focus == i+1 && f.Help != "" {
			b.WriteString(strings.Repeat(" ", 14) + ui.Muted.Render(f.Help) + "\n")
		}
	}
	return b.String()
}

// verdictText is the store's answer to one subject, in words.
func (m *Model) verdictText(src accessSource, subject string) string {
	if strings.TrimSpace(subject) == "" {
		return ui.Muted.Render("type a subject to see what it would get")
	}
	if err := src.ctrl.PolicyErr(); err != nil {
		return ui.Error.Render("✕ DENY — a policy file cannot be read: " + firstLine(err.Error()))
	}
	ex := src.ctrl.Explain(m.d.host, subject)
	var b strings.Builder
	var decided *authz.Matched
	for i := range ex.Matches {
		if ex.Matches[i].Decided {
			decided = &ex.Matches[i]
		}
	}
	switch {
	case decided != nil && ex.Verdict.Action == authz.ActionDeny:
		b.WriteString(ui.Error.Render("→ ✕ DENY") + "  by  " + m.matchLine(src, *decided))
	case decided != nil:
		b.WriteString(ui.OK.Render("→ ✓ ALLOW") + "  by  " + m.matchLine(src, *decided))
	case ex.Verdict.Action == authz.ActionDeny:
		b.WriteString(ui.Error.Render("→ ✕ DENY") + ui.Muted.Render(" — nothing matches, and unmatched is deny"))
	default:
		word := "ASK"
		if !m.promptNow.Any() {
			word = "DENY (nowhere to ask)"
		}
		b.WriteString(ui.Warn.Render("→ ? would "+word) + ui.Muted.Render(" — nothing matches"))
	}
	b.WriteString("\n")
	var lost []authz.Matched
	for _, mt := range ex.Matches {
		if !mt.Decided {
			lost = append(lost, mt)
		}
	}
	if len(lost) > 0 {
		b.WriteString(ui.Muted.Render("  outranks:") + "\n")
		for _, mt := range lost {
			b.WriteString("      " + m.matchLine(src, mt) + "\n")
		}
	}
	return b.String()
}

// seenSubjects is what a broker has been asked for this session, newest
// first, from the decision events in the log.
func (m *Model) seenSubjects(src accessSource) []string {
	seen := map[string]bool{}
	var out []string
	for i := len(m.log) - 1; i >= 0; i-- {
		e := m.log[i]
		if e.Service != src.id || e.Class != event.Security {
			continue
		}
		if s := eventField(e, "subject"); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// --- the test box ---------------------------------------------------------

// testState is the test box: what would this request get, and why?
type testState struct {
	fields fieldSet
	focus  int
}

// openTest opens the test box, starting from the selected row's subject.
func (m *Model) openTest() tea.Cmd {
	if len(m.d.secrets) == 0 {
		return m.showToast(toastMsg{text: "no broker is running — there is nothing to test", bad: true})
	}
	src, subject := 0, ""
	if r, ok := m.selectedAccess(); ok {
		src = m.sourceIndex(r.source.id)
		if !r.isGrant || !r.grant.HostWide {
			subject = r.subject()
		}
	} else if seen := m.seenSubjects(m.d.secrets[0]); len(seen) > 0 {
		subject = seen[0]
	}
	m.menu, m.showDetail = nil, false
	m.test = &testState{fields: m.newFieldSet(src, subject), focus: 1}
	return nil
}

func (m *Model) sourceIndex(id string) int {
	for i, src := range m.d.secrets {
		if src.id == id {
			return i
		}
	}
	return 0
}

func (m *Model) testBox() string {
	t := m.test
	if t == nil {
		return ""
	}
	src := t.fields.source(m)
	var b strings.Builder
	b.WriteString(ui.Banner.Render("test") + ui.Muted.Render(" · what would "+m.d.host+" get? nothing is fetched or signed") + "\n\n")
	b.WriteString(m.renderFields(t.fields, t.focus))
	b.WriteString("\n" + m.verdictText(src, t.fields.subject(m)))
	b.WriteString("\n" + chip("ctrl+n", "write a rule from this", false) + "\n")
	b.WriteString("\n" + ui.Muted.Render("tab next field · ←→ on service switches broker · esc close"))
	return m.boxOf(b.String())
}

func (m *Model) handleTestKey(msg tea.KeyPressMsg) tea.Cmd {
	t := m.test
	switch msg.String() {
	case "esc", "ctrl+c":
		m.test = nil
		return nil
	case "tab", "down":
		t.focus = (t.focus + 1) % (len(t.fields.values) + 1)
		return nil
	case "shift+tab", "up":
		t.focus = (t.focus + len(t.fields.values)) % (len(t.fields.values) + 1)
		return nil
	case "ctrl+n":
		subject, src := t.fields.subject(m), t.fields.src
		m.test = nil
		return m.openForm(formSeed{src: src, subject: subject, effect: authz.ActionAllow})
	}
	if t.focus == 0 {
		switch msg.String() {
		case "left", "h":
			t.fields.cycleBroker(m, -1)
		case "right", "l", "space":
			t.fields.cycleBroker(m, 1)
		}
		return nil
	}
	t.fields.values[t.focus-1].Update(msg)
	return nil
}

func (m *Model) testButtons() []button {
	return []button{{needle: " ctrl+n  write a rule from this ", id: "ctrl+n"}}
}

// --- the rule form --------------------------------------------------------

// formLasts is how long what the form makes will last: written down, or a
// live grant for the session or a few minutes.
type formLasts int

const (
	lastsAlways formLasts = iota
	lastsSession
	lastsMinutes
)

// formGrantTTL is how long a "for a while" grant made from the form lasts.
const formGrantTTL = 5 * time.Minute

func (l formLasts) String() string {
	switch l {
	case lastsSession:
		return "this session"
	case lastsMinutes:
		return "5m"
	}
	return "always"
}

// formState is the new / widen form.
type formState struct {
	fields fieldSet
	effect authz.Action
	lasts  formLasts
	note   textInput
	focus  int
	// editing is the rule being changed in place, for `w` on a rule you may
	// edit. Empty makes a new one.
	editing  string
	original authz.Rule
	// answering is an approval the form was opened from. Saving a rule that
	// covers its request answers it; cancelling goes back to it. The broker
	// is locked to the request's while it is set: a rule for one broker must
	// never answer another's question.
	answering *approvalState
	// orphaned says the approval the form came from has gone — answered on
	// another surface, or timed out — so saving writes the rule and answers
	// nothing.
	orphaned bool
}

// formSeed is what a form starts with.
type formSeed struct {
	src       int
	subject   string
	effect    authz.Action
	editing   *authz.Rule
	answering *approvalState
}

// The form's focus order, after the subject fields.
const (
	focusService = 0
)

func (f *formState) focusEffect() int { return len(f.fields.values) + 1 }
func (f *formState) focusLasts() int  { return len(f.fields.values) + 2 }
func (f *formState) focusNote() int   { return len(f.fields.values) + 3 }
func (f *formState) focusCount() int  { return len(f.fields.values) + 4 }

func (m *Model) openForm(seed formSeed) tea.Cmd {
	if len(m.d.secrets) == 0 {
		return m.showToast(toastMsg{text: "no broker is running — there is nothing to write a rule for", bad: true})
	}
	f := &formState{fields: m.newFieldSet(seed.src, seed.subject), effect: seed.effect, answering: seed.answering}
	if f.effect == "" {
		f.effect = authz.ActionAllow
	}
	if seed.editing != nil {
		f.editing, f.original = seed.editing.ID, *seed.editing
		f.note.SetValue(seed.editing.Note)
	}
	// The cursor starts on the last field: widening op://Personal/Docker/PAT
	// to its item is a change to the end of it, and so is pointing a key at a
	// different destination.
	f.focus = len(f.fields.values)
	m.menu, m.showDetail, m.test = nil, false, nil
	m.form = f
	return nil
}

// openNewRule is `n`: a blank form, or one seeded from the selected row.
func (m *Model) openNewRule() tea.Cmd {
	seed := formSeed{effect: authz.ActionAllow}
	if r, ok := m.selectedAccess(); ok && (!r.isGrant || !r.grant.HostWide) {
		seed.src, seed.subject = m.sourceIndex(r.source.id), r.subject()
	}
	if m.tab == tabActivity {
		if e, ok := m.selectedEvent(); ok {
			if src, found := m.sourceFor(e); found {
				seed.src, seed.subject = m.sourceIndex(src.id), eventField(e, "subject")
			}
		}
	}
	return m.openForm(seed)
}

// openWiden is `w` on a row: the form, pre-filled, editing the rule in place
// when it is one you may edit and making a new one otherwise.
func (m *Model) openWiden() tea.Cmd {
	r, ok := m.selectedAccess()
	if !ok {
		return m.needSelection()
	}
	if why := m.widenBlocked(); why != "" {
		return m.showToast(toastMsg{text: why, bad: true})
	}
	seed := formSeed{src: m.sourceIndex(r.source.id), subject: r.subject(), effect: r.action()}
	if !r.isGrant && r.rule.Editable() {
		rule := r.rule
		seed.editing = &rule
	}
	return m.openForm(seed)
}

// widenBlocked says why `w` cannot act on the selected row, or "".
func (m *Model) widenBlocked() string {
	r, ok := m.selectedAccess()
	switch {
	case !ok:
		return "pick a row first"
	case r.isGrant && r.grant.HostWide:
		return "it already covers everything"
	}
	return ""
}

// widenField cycles the focused field's last part: exact → * → **. It is the
// one-key way to go from a secret to its item, or from one key to any key,
// without knowing the glob rules.
func (m *Model) widenField() {
	f := m.form
	i := f.focus - 1
	if i < 0 || i >= len(f.fields.values) {
		i = len(f.fields.values) - 1
	}
	in := &f.fields.values[i]
	v := in.Value()
	schema := f.fields.source(m).ctrl.Schema()
	if !schema.PathLike {
		// A field with no path in it is either exact or anything.
		if v == authz.HostWildcard {
			if orig := schema.Split(f.original.Subject); i < len(orig) && f.original.Subject != "" {
				in.SetValue(orig[i])
			}
			return
		}
		in.SetValue(authz.HostWildcard)
		return
	}
	cut := strings.LastIndex(v, "/")
	head, last := v[:cut+1], v[cut+1:]
	switch last {
	case "*":
		in.SetValue(head + "**")
	case "**":
		// Up a level: op://Personal/Docker/** → op://Personal/*
		parent := strings.TrimSuffix(head, "/")
		if p := strings.LastIndex(parent, "/"); p >= 0 && !strings.HasSuffix(parent, ":/") {
			in.SetValue(parent[:p+1] + "*")
		}
	default:
		in.SetValue(head + "*")
	}
}

func (m *Model) formBox() string {
	f := m.form
	if f == nil {
		return ""
	}
	src := f.fields.source(m)
	title := "new rule"
	if f.editing != "" {
		title = "change a rule"
	}
	var b strings.Builder
	b.WriteString(ui.Banner.Render(title) + ui.Muted.Render(" · "+src.title+" · for "+m.formHosts(f)) + "\n")
	switch {
	case f.answering != nil:
		b.WriteString(ui.Muted.Render("for the request waiting on it — a rule that covers it answers it; esc goes back") + "\n")
	case f.orphaned:
		b.WriteString(ui.Warn.Render("the request this came from has gone (answered elsewhere, or timed out) — saving only writes the rule") + "\n")
	}
	b.WriteString("\n")
	b.WriteString(m.renderFields(f.fields, f.focus))
	b.WriteString(strings.Repeat(" ", 14) + chip("ctrl+t", "widen: exact → * → **", false) + "\n")

	choice := func(label string, focus bool, opts []string, on int) string {
		lead := ui.Muted.Render("  " + pad(label, 12))
		if focus {
			lead = ui.Banner.Render("▸ " + pad(label, 12))
		}
		var parts []string
		for i, o := range opts {
			if i == on {
				parts = append(parts, ui.Button.Render(" "+o+" "))
			} else {
				parts = append(parts, ui.Muted.Render(" "+o+" "))
			}
		}
		return lead + strings.Join(parts, " ") + "\n"
	}
	eff := 0
	if f.effect == authz.ActionDeny {
		eff = 1
	}
	b.WriteString(choice("effect", f.focus == f.focusEffect(), []string{"allow", "deny"}, eff))
	b.WriteString(choice("lasts", f.focus == f.focusLasts(), []string{"always", "this session", "5m"}, int(f.lasts)))
	noteLabel := ui.Muted.Render("  " + pad("note", 12))
	note := f.note.Value()
	if f.focus == f.focusNote() {
		noteLabel, note = ui.Banner.Render("▸ "+pad("note", 12)), f.note.Render()
	}
	b.WriteString(noteLabel + note + "\n\n")

	subject := f.fields.subject(m)
	b.WriteString(ui.Muted.Render("  means     ") + m.meaning(accessRow{rule: authz.Rule{Subject: subject}, source: src}) + "\n")
	b.WriteString(m.formPreview(src, subject))
	b.WriteString("\n" + ui.Muted.Render("  writes    ") + m.formWrites(f) + "\n")
	b.WriteString("\n" + ui.Muted.Render("enter save · tab next · ←→ on a choice · esc cancel"))
	return m.boxOf(b.String())
}

// formWrites says where saving will put what the form makes.
func (m *Model) formWrites(f *formState) string {
	switch {
	case f.lasts != lastsAlways:
		return "a live grant — in memory, gone when devtun quits"
	case f.editing != "":
		return "changes the rule in " + m.sourceWhere(f.original)
	}
	return "hosts/" + m.d.host + ".yaml · remembered: (devtun's rules, not yours)"
}

// formPreview lists what the pattern would match among the subjects seen this
// session, and whether a deny would beat it.
func (m *Model) formPreview(src accessSource, pattern string) string {
	if strings.TrimSpace(pattern) == "" {
		return ""
	}
	schema := src.ctrl.Schema()
	effect := authz.ActionAllow
	if m.form != nil {
		effect = m.form.effect
	}
	var hits []string
	for _, s := range m.seenSubjects(src) {
		if covers(schema, effect, pattern, s) {
			hits = append(hits, s)
		}
	}
	var b strings.Builder
	b.WriteString(ui.Muted.Render("  matches   "))
	switch {
	case len(hits) == 0:
		b.WriteString(ui.Muted.Render("nothing asked for this session"))
	default:
		shown := hits
		if len(shown) > 3 {
			shown = shown[:3]
		}
		for i, h := range shown {
			if i > 0 {
				b.WriteString(ui.Muted.Render(" · "))
			}
			b.WriteString(ui.Secret.Render(elideMiddle(h, 40)))
		}
		if extra := len(hits) - len(shown); extra > 0 {
			b.WriteString(ui.Muted.Render(" · +" + itoa(extra) + " more"))
		}
	}
	b.WriteString("\n")
	if strings.ContainsAny(pattern, "*?[") {
		b.WriteString(ui.Muted.Render("            and anything else that fits the pattern, asked for or not") + "\n")
	}
	if m.form != nil && m.form.effect == authz.ActionAllow {
		ex := src.ctrl.Explain(m.d.host, pattern)
		for _, mt := range ex.Matches {
			if denyMatch(mt) {
				b.WriteString("  " + ui.Warn.Render("⚠ a deny beats it:") + " " + m.matchLine(src, mt) + "\n")
			}
		}
	}
	return b.String()
}

func (m *Model) formButtons() []button {
	return []button{{needle: " ctrl+t  widen: exact → * → ** ", id: "ctrl+t"}}
}

func (m *Model) handleFormKey(msg tea.KeyPressMsg) tea.Cmd {
	f := m.form
	switch msg.String() {
	case "esc", "ctrl+c":
		m.closeForm()
		return nil
	case "tab", "down":
		f.focus = (f.focus + 1) % f.focusCount()
		return nil
	case "shift+tab", "up":
		f.focus = (f.focus + f.focusCount() - 1) % f.focusCount()
		return nil
	case "ctrl+t":
		m.widenField()
		return nil
	case "enter":
		return m.saveForm()
	}
	switch {
	case f.focus == focusService:
		switch msg.String() {
		case "left", "h":
			m.cycleFormBroker(-1)
		case "right", "l", "space":
			m.cycleFormBroker(1)
		}
	case f.focus == f.focusEffect():
		switch msg.String() {
		case "left", "right", "h", "l", "space":
			if f.effect == authz.ActionAllow {
				f.effect = authz.ActionDeny
			} else {
				f.effect = authz.ActionAllow
			}
		}
	case f.focus == f.focusLasts():
		switch msg.String() {
		case "left", "h":
			f.lasts = (f.lasts + 2) % 3
		case "right", "l", "space":
			f.lasts = (f.lasts + 1) % 3
		}
	case f.focus == f.focusNote():
		f.note.Update(msg)
	default:
		f.fields.values[f.focus-1].Update(msg)
	}
	return nil
}

// closeForm cancels the form, going back to the approval it came from.
func (m *Model) closeForm() {
	if m.form != nil && m.form.answering != nil && m.approval == nil {
		m.approval = m.form.answering
	}
	m.form = nil
}

// saveForm writes what the form describes. A deny only tightens and is saved
// at once; anything that allows goes through a confirm saying what it opens.
func (m *Model) saveForm() tea.Cmd {
	f := m.form
	src := f.fields.source(m)
	subject := f.fields.subject(m)
	for _, v := range f.fields.values {
		if strings.TrimSpace(v.Value()) == "" {
			return m.showToast(toastMsg{text: "every field needs a value — ** means anything", bad: true})
		}
	}
	save := func(mm *Model) tea.Cmd { return mm.commitForm(f, src, subject) }
	matchChanged := f.editing != "" && f.original.Subject != subject
	switch {
	case f.editing != "" && !matchChanged && f.original.Action == f.effect:
		// Same rule, same pattern, same effect — a note changed. Nothing
		// opens.
		return save(m)
	case f.effect == authz.ActionDeny && !matchChanged:
		// A new deny, or an allow turned into a deny over the same
		// pattern: both only tighten.
		return save(m)
	case f.effect == authz.ActionDeny:
		// An existing rule's match moved. For a deny that loosens whatever
		// the old pattern refused and the new one does not — narrowing or
		// moving a refusal is a loosening, however much it looks like an
		// edit to a deny.
		return m.ask(m.denyEditConfirm(f, src, subject, save))
	}
	return m.ask(m.allowConfirm(f, src, subject, save))
}

// allowConfirm is the question before anything that lets a request through
// without a prompt.
func (m *Model) allowConfirm(f *formState, src accessSource, subject string, run func(*Model) tea.Cmd) confirmState {
	schema := src.ctrl.Schema()
	n := 0
	for _, s := range m.seenSubjects(src) {
		if covers(schema, authz.ActionAllow, subject, s) {
			n++
		}
	}
	lasts := "always — written to " + m.formWrites(f)
	if f.lasts != lastsAlways {
		lasts = f.lasts.String() + " — a live grant"
	}
	body := []string{
		ui.OK.Render("✓") + " " + ui.Muted.Render(ui.ShortService(src.id)) + " " + ui.Secret.Render(subject),
		"  " + ui.Muted.Render(lasts),
		"",
		capitalize(m.formHosts(f)) + " " + gets(m.formHosts(f)) + " what this matches without being asked.",
	}
	if strings.ContainsAny(subject, "*?[") {
		body = append(body, ui.Muted.Render("That is "+itoa(n)+" thing"+plural(n)+" asked for this session, and anything else that fits."))
	}
	if f.editing != "" && f.original.Subject != subject {
		body = append(body, ui.Muted.Render("It replaces "+f.original.Subject))
	}
	title := "Allow this?"
	if f.editing != "" {
		title = "Widen this rule?"
	}
	return confirmState{title: title, body: body, yes: "allow it", no: "go back", danger: true, run: run}
}

// denyEditConfirm is the question before changing what an existing deny
// matches.
func (m *Model) denyEditConfirm(f *formState, src accessSource, subject string, run func(*Model) tea.Cmd) confirmState {
	body := []string{
		ui.Error.Render("✕") + " " + ui.Muted.Render(ui.ShortService(src.id)) + " " + ui.Secret.Render(f.original.Subject),
		"  " + ui.Muted.Render("becomes ") + ui.Secret.Render(subject),
		"  " + ui.Muted.Render(m.sourceWhere(f.original)+" · applies to "+m.formHosts(f)),
		"",
		"Whatever the old pattern refused and the new one does not stops being",
		"refused here: another rule decides it — an allow lets it through without",
		"asking, or it is asked about, or refused if nothing matches and unmatched is deny.",
	}
	return confirmState{title: "Change what this deny refuses?", body: body, yes: "change it", no: "go back", danger: true, run: run}
}

// formHosts is who a rule from the form applies to: the edited rule's own
// host pattern when it has one — the form never changes it — or this host.
func (m *Model) formHosts(f *formState) string {
	if f.editing == "" || f.original.Host == "" || f.original.Host == m.d.host {
		return m.d.host
	}
	return hostScope(f.original.Host)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func gets(who string) string {
	if strings.HasPrefix(who, "hosts ") || who == "all hosts" {
		return "get"
	}
	return "gets"
}

// commitForm performs the write.
func (m *Model) commitForm(f *formState, src accessSource, subject string) tea.Cmd {
	note := strings.TrimSpace(f.note.Value())
	var err error
	switch {
	case f.lasts != lastsAlways:
		ttl := time.Duration(0)
		if f.lasts == lastsMinutes {
			ttl = formGrantTTL
		}
		_, err = src.ctrl.AddGrant(authz.GrantSpec{Host: m.d.host, Subject: subject, Action: f.effect, TTL: ttl})
	case f.editing != "":
		id := f.editing
		if f.original.Subject != subject || f.original.Note != note {
			var r authz.Rule
			r, err = src.ctrl.UpdateRule(id, authz.RuleEdit{Subject: &subject, Note: &note})
			id = r.ID
		}
		if err == nil && f.original.Action != f.effect {
			_, err = src.ctrl.SetRuleAction(id, f.effect)
		}
	default:
		_, err = src.ctrl.AddRule(authz.Rule{Host: m.d.host, Subject: subject, Action: f.effect, Note: note})
	}
	if err != nil {
		// The form stays open over a failed write, with what was typed.
		m.form = f
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	m.form = nil
	m.reloadAccess()
	m.clampCursor()

	verb := "allowing"
	if f.effect == authz.ActionDeny {
		verb = "denying"
	}
	toast := m.showToast(toastMsg{text: "now " + verb + " " + subject + " (" + f.lasts.String() + ")"})

	// From an approval: if what was written covers the request waiting on
	// it, that request gets the matching answer; otherwise it is back on
	// screen, still waiting.
	if a := f.answering; a != nil {
		sameBroker := a.request.Service == src.id
		sameHost := a.request.Host == m.d.host
		if sameBroker && sameHost && covers(src.ctrl.Schema(), f.effect, subject, a.request.Subject) {
			m.approval = a
			choice := prompt.ChoiceAllowOnce
			if f.effect == authz.ActionDeny {
				choice = prompt.ChoiceDeny
			}
			return tea.Batch(m.answer(choice), toast)
		}
		m.approval = a
	}
	return toast
}

// --- from the approval -----------------------------------------------------

// widenFromApproval is `w` in the approval prompt: the form, seeded with the
// request, without adding a tenth item to the 1–9 menu. The request keeps
// waiting while the form is open.
func (m *Model) widenFromApproval() tea.Cmd {
	a := m.approval
	src, ok := m.sourceForRequest(a.request)
	if !ok {
		return m.showToast(toastMsg{text: "this request does not say which broker asked — answer it, then write the rule on Access", bad: true})
	}
	m.approval = nil
	return m.openForm(formSeed{src: src, subject: a.request.Subject, effect: authz.ActionAllow, answering: a})
}

// sourceForRequest is the broker a prompt request came from, by the service
// id the broker put on it. There is no guessing: two brokers have
// single-field subjects, and a guess that picked 1Password for a browser
// request would write the wrong broker's rule and answer the wrong question.
// A request with no service id gets no form.
func (m *Model) sourceForRequest(r prompt.Request) (int, bool) {
	if r.Service == "" {
		return 0, false
	}
	for i, src := range m.d.secrets {
		if src.id == r.Service {
			return i, true
		}
	}
	return 0, false
}

// covers is whether a rule with this effect and pattern applies to a subject,
// the way the store decides it: an allow through Allows, which will not let a
// wildcard cover a literal-only value such as an SSH key's "(arbitrary
// data)", and a deny through plain Match, which will.
func covers(schema authz.Schema, effect authz.Action, pattern, subject string) bool {
	if effect == authz.ActionAllow {
		return schema.Allows(pattern, subject)
	}
	return schema.Match(pattern, subject)
}
