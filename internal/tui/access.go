package tui

import (
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/ui"
)

// accessRow is one line of the Access tab: a section heading, or something
// currently standing between this host and what devtun brokers. That is a live
// grant somebody clicked through, a rule in this host's file, or a rule in the
// global file — and the tab groups them in that order, by how long they last,
// so the heading above a row already answers "can I change this here?".
type accessRow struct {
	// heading is set on a section heading, which is structure rather than
	// something to select; count is how many rows it heads.
	heading string
	count   int

	// rule carries its own stable ID, which is what `r` and `D` act on —
	// never its position, which another surface can shift between this
	// screen's render and the keypress.
	rule authz.Rule
	// grant is set instead of rule for a live allowance or refusal.
	grant   *authz.Grant
	isGrant bool
	// source is which broker this row belongs to, since the tab shows more
	// than one and `r` has to revoke through the right door.
	source accessSource
	// global marks a rule that came from the top-level config. It is shown so
	// the tab answers "what is deciding", and it cannot be revoked here: devtun
	// did not write it, and quietly editing a file the user hand-wrote would be
	// a worse surprise than saying no.
	global bool

	// outranked is set on an allow that a deny also matches: it never wins,
	// or — for a pattern with wildcards — does not win for everything it
	// names. exact says which: true when the allow names one subject, so
	// "never wins" is a fact rather than a likelihood. by is what beats it.
	outranked bool
	exact     bool
	by        []authz.Matched
}

// action is the row's effect: allow or deny, for a grant and a rule alike.
func (r accessRow) action() authz.Action {
	if r.isGrant {
		return r.grant.Action
	}
	return r.rule.Action
}

// subject is the raw pattern or subject the row covers.
func (r accessRow) subject() string {
	if r.isGrant {
		return r.grant.Subject
	}
	return r.rule.Subject
}

// label is the row's kind in a word, as the KIND column prints it.
func (r accessRow) label() string {
	switch {
	case r.isGrant && r.grant.Action == authz.ActionDeny:
		// "No, and stop asking" — a refusal held for the session, which is a
		// different promise from a deny written to a file.
		return "stop-ask"
	case r.isGrant:
		return "grant"
	case r.rule.Source == authz.SourceRemembered && r.rule.Action == authz.ActionDeny:
		// An answer to a prompt, kept: "never" and "always" are the words
		// the prompt used, so the row says what was clicked.
		return "never"
	case r.rule.Source == authz.SourceRemembered:
		return "always"
	default:
		return string(r.rule.Action)
	}
}

// svc is the broker's short name, the same one the log uses, so a row here
// and the line in the log that it decided are visibly about the same thing.
func (r accessRow) svc() string { return ui.ShortService(r.source.id) }

// Section headings. They say where a row lives, because that is what decides
// whether it can be changed here and what changing it means.
const (
	headLive       = "LIVE — this session only, gone when devtun quits"
	headRemembered = "WRITTEN BY DEVTUN — "
	headHost       = "YOU WROTE — "
	headGlobal     = "ALL HOSTS — you wrote it in config.yaml · read-only here"
)

// reloadAccess pulls the live grants and every rule, grouped.
//
// Grants come first because they are the answer to "what is open right now",
// which is the question this tab exists for. A rule is a decision you made
// deliberately and can read on disk; a grant is one you clicked through a
// minute ago and may well have forgotten.
func (m *Model) reloadAccess() {
	selected, hadSelection := m.selectedAccess()
	if len(m.d.secrets) == 0 {
		m.accessRows = nil
		return
	}
	q := strings.ToLower(strings.TrimSpace(m.search[tabAccess]))
	matches := func(text string) bool {
		return q == "" || strings.Contains(strings.ToLower(text), q)
	}

	var live, remembered, host, global []accessRow
	for _, src := range m.d.secrets {
		for _, g := range src.ctrl.Grants() {
			grant := g
			if !matches(src.title + " " + g.Host + " " + g.Subject) {
				continue
			}
			live = append(live, accessRow{grant: &grant, isGrant: true, source: src})
		}
	}
	// The global rules last, because they are the least likely to be what you
	// came to change — but present, because a tab that shows only half of what
	// is deciding will send somebody hunting for a rule that is right there.
	for _, src := range m.d.secrets {
		for _, r := range src.ctrl.Rules() {
			if !matches(src.title + " " + r.Host + " " + r.Subject + " " + r.Note) {
				continue
			}
			switch r.Source {
			case authz.SourceGlobal:
				global = append(global, accessRow{rule: r, source: src, global: true})
			case authz.SourceRemembered:
				remembered = append(remembered, accessRow{rule: r, source: src})
			default:
				host = append(host, accessRow{rule: r, source: src})
			}
		}
	}

	var rows []accessRow
	for _, group := range []struct {
		title string
		rows  []accessRow
	}{
		{headLive, live},
		{headRemembered + "hosts/" + m.d.host + ".yaml · remembered:", remembered},
		{headHost + "hosts/" + m.d.host + ".yaml · rules:", host},
		{headGlobal, global},
	} {
		if len(group.rows) == 0 {
			continue
		}
		for i := range group.rows {
			m.markOutranked(&group.rows[i])
		}
		rows = append(rows, accessRow{heading: group.title, count: len(group.rows)})
		rows = append(rows, group.rows...)
	}
	m.accessRows = rows

	// Keep the cursor on the same thing rather than the same row number: a
	// grant lapsing above it would otherwise slide the selection onto its
	// neighbour, and the next `r` would revoke the wrong thing.
	if hadSelection {
		m.cursors[tabAccess] = noSelection
		for i, r := range rows {
			if r.heading == "" && sameAccess(r, selected) {
				m.cursors[tabAccess] = i
				break
			}
		}
	}
}

// sameAccess reports whether two rows are the same grant or rule.
func sameAccess(a, b accessRow) bool {
	if a.source.id != b.source.id || a.isGrant != b.isGrant || a.global != b.global {
		return false
	}
	if a.isGrant {
		return a.grant.ID == b.grant.ID
	}
	return a.rule.ID == b.rule.ID
}

// markOutranked asks the store whether a deny beats an allow row.
//
// The question is put with the allow's own pattern as the subject. For a
// pattern with no wildcard that is the one request it allows, so the answer
// is exact: a deny decided it, and the allow never wins. For a wildcard
// pattern a deny matching the pattern's own text means at least part of what
// it allows is refused — worth a warning, and worded as one.
func (m *Model) markOutranked(r *accessRow) {
	if r.action() != authz.ActionAllow || (r.isGrant && r.grant.HostWide) {
		return
	}
	subject := r.subject()
	ex := r.source.ctrl.Explain(m.d.host, subject)
	for _, mt := range ex.Matches {
		if denyMatch(mt) {
			r.by = append(r.by, mt)
		}
	}
	r.outranked = len(r.by) > 0
	r.exact = !strings.ContainsAny(subject, "*?[")
}

// denyMatch reports whether an explanation entry is a refusal.
func denyMatch(mt authz.Matched) bool {
	switch {
	case mt.Rule != nil:
		return mt.Rule.Action == authz.ActionDeny
	case mt.Grant != nil:
		return mt.Grant.Action == authz.ActionDeny
	}
	return false
}

// selectedAccess is the highlighted row, when one is.
func (m *Model) selectedAccess() (accessRow, bool) {
	i := m.cursors[tabAccess]
	if i < 0 || i >= len(m.accessRows) || m.accessRows[i].heading != "" {
		return accessRow{}, false
	}
	return m.accessRows[i], true
}

// --- layout ----------------------------------------------------------------

// accessCols is the column plan for one width. MATCHES takes what is left
// after the fixed columns, up to what a long pattern needs; anything beyond
// that goes to the note, which is the gloss and gives way first.
type accessCols struct{ match, kind, life, note int }

const (
	accessLead = 9 // " ✓  op   " — the effect glyph and the SVC column
)

func (m *Model) accessColumns() accessCols {
	c := accessCols{kind: 10, life: 12}
	rest := m.listWidth() - accessLead - c.kind - c.life
	c.match = min(max(rest, 10), 58)
	c.note = max(rest-c.match-2, 0)
	if c.note < 10 {
		c.note = 0
	}
	return c
}

// accessHeader is the column titles over the list.
func (m *Model) accessHeader() string {
	c := m.accessColumns()
	line := "    " + pad("SVC", 5) + pad("MATCHES", c.match) + "  " + pad("KIND", c.kind) + pad("LIFETIME", c.life)
	if c.note > 0 {
		line += "NOTE"
	}
	for _, r := range m.accessRows {
		if r.outranked {
			// The marker is one cell in the list; the header spells it out.
			const legend = "⚠ a deny wins"
			room := m.listWidth() - ansi.StringWidth(legend) - 1
			line = clampWidth(line, room)
			line += strings.Repeat(" ", max(room-ansi.StringWidth(line), 0)+1) + legend
			break
		}
	}
	return ui.Header.Render(clampWidth(line, m.listWidth()))
}

func (m *Model) accessView() string {
	header := m.boxLine(m.withTrack(m.accessHeader(), " "))
	if len(m.d.secrets) == 0 {
		return header + "\n" + m.emptyView(m.bodyHeight()-1, "no broker is running for this host — nothing here asks for access")
	}
	var body string
	if len(m.accessRows) == 0 && m.search[tabAccess] == "" {
		body = m.accessEmptyView(m.listHeight())
	} else {
		var lines []string
		end := min(m.offset()+m.listHeight(), len(m.accessRows))
		for i := m.offset(); i < end; i++ {
			lines = append(lines, m.accessLine(m.accessRows[i], i == m.cursor()))
		}
		body = m.listView(lines, m.listHeight(), "nothing matches "+m.search[tabAccess])
	}
	return header + "\n" + body + "\n" + m.boxLine(m.fallbackLine())
}

// accessEmptyView says what an empty tab means and what to do about it,
// rather than a blank rectangle that could equally be a failure to load.
func (m *Model) accessEmptyView(h int) string {
	ask := "Every request from it is asked about — you'll see a prompt."
	if !m.promptNow.Any() {
		ask = "Every request from it is refused: approvals are off (prompt: deny)."
	}
	for _, src := range m.d.secrets {
		if w, _ := m.unmatchedWord(src); w != "ask" {
			ask = "What nothing matches is refused or asked, per broker — see the last line."
			break
		}
	}
	text := []string{
		ui.Banner.Render("Nothing is open, and no rule is written down for " + m.d.host + "."),
		ui.Muted.Render(ask),
		"",
		ui.Banner.Render("n") + ui.Muted.Render("  write a rule now — allow or deny something before it is asked for"),
		ui.Banner.Render("t") + ui.Muted.Render("  test what a request would get"),
		"",
		ui.Muted.Render("Rules also come from answering a prompt with \"always\" or \"never\","),
		ui.Muted.Render("and from hosts/" + m.d.host + ".yaml and config.yaml.  A deny always beats an allow."),
	}
	lines := make([]string, h)
	top := max((h-len(text))/2, 0)
	for i := range lines {
		content := ""
		if j := i - top; j >= 0 && j < len(text) {
			content = "   " + text[j]
		}
		lines[i] = m.boxLine(content)
	}
	return strings.Join(lines, "\n")
}

// fallbackLine is the rule nobody wrote: what each broker does when nothing
// matches. It decides most requests, so it is on screen like any other rule.
// A broker whose policy file cannot be read takes the line over instead —
// while that lasts, it refuses everything, and nothing else on the tab is
// telling the truth about that broker.
func (m *Model) fallbackLine() string {
	for _, src := range m.d.secrets {
		if err := src.ctrl.PolicyErr(); err != nil {
			return clampWidth(" "+ui.Danger.Render("⚠ "+ui.ShortService(src.id)+" refuses everything: ")+
				ui.Error.Render(firstLine(err.Error())), m.inner())
		}
	}
	var b strings.Builder
	b.WriteString(" " + ui.Header.Render("NOTHING MATCHES →") + " ")
	for _, src := range m.d.secrets {
		word, style := m.unmatchedWord(src)
		b.WriteString(" " + ui.Muted.Render(ui.ShortService(src.id)+":") + " " + style.Render(word) + "  ")
	}
	b.WriteString(ui.Muted.Render("(Config ▸ Policy to change)"))
	return clampWidth(b.String(), m.inner())
}

// unmatchedWord is what a broker does with a request nothing matches: its
// unmatched policy, except that "ask" with nowhere to ask is a refusal and is
// shown as one.
func (m *Model) unmatchedWord(src accessSource) (string, lipgloss.Style) {
	u := src.ctrl.Unmatched()
	switch {
	case u.Err != nil:
		return "deny (bad value)", ui.Error
	case u.Action == authz.ActionDeny:
		return "deny", ui.Error
	case !m.promptNow.Any():
		return "deny (nowhere to ask)", ui.Error
	}
	return "ask", ui.Warn
}

// accessLine renders one row. The subject carries ui.Secret, the same
// treatment a vault reference gets in the log and in the approval prompt: it
// is the one string on screen you must never misread as something else.
func (m *Model) accessLine(r accessRow, selected bool) string {
	if r.heading != "" {
		left := " " + r.heading
		right := itoa(r.count) + " "
		gap := max(m.listWidth()-ansi.StringWidth(left)-ansi.StringWidth(right), 1)
		return ui.Header.Render(clampWidth(left+strings.Repeat(" ", gap)+right, m.listWidth()))
	}
	c := m.accessColumns()

	glyph, effect := ui.OK.Render("✓"), ui.OK
	if r.action() == authz.ActionDeny {
		glyph, effect = ui.Error.Render("✕"), ui.Error
	}
	lead := " "
	if selected {
		// A pointer as well as the reverse video: on a terminal with no
		// colour, or in a screenshot pasted as text, reverse video is gone
		// and the row the next r acts on would be anyone's guess.
		lead = "▸"
	}
	match := m.glossSubject(r, c.match)
	matchStyle := ui.Secret
	if r.isGrant && r.grant.HostWide {
		// A grant covering everything from a host is not the same kind of
		// thing as one covering a secret, and should not look like one.
		matchStyle = ui.Danger
	}

	life, lifeStyle := m.lifetime(r)
	warn := " "
	if r.outranked {
		warn = ui.Warn.Render("⚠")
	}
	line := lead + glyph + warn + " " + ui.Muted.Render(pad(r.svc(), 5)) +
		matchStyle.Render(pad(match, c.match)) + "  " +
		effect.Render(pad(r.label(), c.kind)) + lifeStyle.Render(pad(life, c.life))
	switch {
	case c.note > 0 && r.outranked:
		line += ui.Warn.Render(pad(outrankedNote(r), c.note))
	case c.note > 0 && !r.isGrant && r.rule.Note != "":
		line += ui.Muted.Render(pad(r.rule.Note, c.note))
	}

	line = clampWidth(line, m.listWidth())
	if selected {
		if w := ansi.StringWidth(line); w < m.listWidth() {
			line += strings.Repeat(" ", m.listWidth()-w)
		}
		return ui.Selected.Reverse(true).Render(ansi.Strip(line))
	}
	return line
}

// outrankedNote is the NOTE column's one line on an outranked allow.
func outrankedNote(r accessRow) string {
	if r.exact {
		return "never wins — a deny matches it"
	}
	return "partly refused — a deny matches it"
}

// lifetime is the LIFETIME column: how long a grant has left, how old a rule
// is, or — for a global rule — where it applies.
func (m *Model) lifetime(r accessRow) (string, lipgloss.Style) {
	switch {
	case r.isGrant && r.grant.Expires.IsZero():
		// A grant with no expiry lasts as long as devtun does, which is a
		// materially different promise from five minutes and has to read
		// differently — "session" rather than a countdown that never moves.
		return "session", ui.Muted
	case r.isGrant:
		return FormatAge(r.grant.Expires.Sub(m.d.now())) + " left", ui.Warn
	case r.global:
		return hostScope(r.rule.Host), ui.Muted
	case !r.rule.Added.IsZero():
		return ago(m.d.now().Sub(r.rule.Added)), ui.Muted
	}
	return "—", ui.Muted
}

// hostScope reads a rule's host pattern as where it applies.
func hostScope(host string) string {
	switch host {
	case "", "*", "**":
		return "all hosts"
	}
	return "hosts " + host
}

// ago is an age in prose — "8d ago" — rather than FormatAge's table format,
// whose "8d00" reads as a typo in a sentence.
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + "h ago"
	}
	return itoa(int(d.Hours())/24) + "d ago"
}

// --- reading a subject -----------------------------------------------------

// glossSubject is the MATCHES column: the pattern, shortened so the part that
// says what it is about survives. That is the end of it — the field of an
// op:// reference, the destination of a signature — so it is the middle that
// gives way, never the tail.
func (m *Model) glossSubject(r accessRow, width int) string {
	if r.isGrant && r.grant.HostWide {
		return hostWideGloss(r.source.id, r.grant.Host)
	}
	s := r.subject()
	if r.source.id == "ssh-agent" {
		if key, dest, ok := splitSSH(s); ok {
			return elideMiddle(shortKey(key), max(width-ansi.StringWidth(dest)-3, 8)) + " → " + sshDest(dest)
		}
	}
	return elideMiddle(s, width)
}

// hostWideGloss names what a host-wide grant covers in the broker's own noun.
// "anything from bedev" read as though it covered 1Password and the agent
// alike; it never did — a grant belongs to one broker.
func hostWideGloss(service, host string) string {
	switch service {
	case "1password":
		return "any secret from " + host
	case "ssh-agent":
		return "any signature from " + host + ", to anywhere"
	case "browser":
		return "any site " + host + " opens"
	}
	return "anything from " + host
}

// sourceWhere names the file a rule lives in, and the key within it.
func (m *Model) sourceWhere(r authz.Rule) string {
	switch r.Source {
	case authz.SourceGlobal:
		return "config.yaml · rules:"
	case authz.SourceRemembered:
		return "hosts/" + m.d.host + ".yaml · remembered:"
	}
	return "hosts/" + m.d.host + ".yaml · rules:"
}

// sourceWho says who wrote a rule, the way the detail box puts it.
func sourceWho(r authz.Rule) string {
	switch r.Source {
	case authz.SourceRemembered:
		return "devtun wrote it"
	case authz.SourceGlobal:
		return "you wrote it · all hosts"
	}
	return "you wrote it"
}

// splitSSH splits an agent subject, `<key type> <fingerprint> → <dest>`, at
// its last arrow.
func splitSSH(s string) (key, dest string, ok bool) {
	i := strings.LastIndex(s, " → ")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(" → "):], true
}

// shortKey keeps a key's type and the tail of its fingerprint, which is the
// part people compare, and drops the forty characters nobody reads.
func shortKey(key string) string {
	switch key {
	case "**", "*":
		return "any key"
	}
	typ, fp, ok := strings.Cut(key, " ")
	if !ok {
		return key
	}
	typ = strings.TrimPrefix(typ, "ssh-")
	if fp == "**" || fp == "*" {
		return "any " + typ + " key"
	}
	if len(fp) > 8 {
		fp = "…" + fp[len(fp)-7:]
	}
	return typ + " " + fp
}

func sshDest(dest string) string {
	if dest == "**" || dest == "*" {
		return "anywhere"
	}
	return dest
}

// splitAccount splits a 1Password subject scoped to an account,
// "[work] op://…", into the account and the rest. A bare subject means the
// default account.
func splitAccount(s string) (account, rest string, ok bool) {
	if !strings.HasPrefix(s, "[") {
		return "", s, false
	}
	end := strings.Index(s, "] ")
	if end < 0 {
		return "", s, false
	}
	return s[1:end], s[end+2:], true
}

// elideMiddle shortens s to w cells by cutting from the middle.
func elideMiddle(s string, w int) string {
	n := ansi.StringWidth(s)
	if n <= w || w < 5 {
		return s
	}
	head := (w - 1) / 2
	tail := w - 1 - head
	return ansi.Truncate(s, head, "") + "…" + ansi.TruncateLeft(s, n-tail, "")
}

// meaning is the detail box's plain-language reading of what a row covers.
func (m *Model) meaning(r accessRow) string {
	if r.isGrant && r.grant.HostWide {
		return hostWideGloss(r.source.id, r.grant.Host) + " — every request, no questions"
	}
	s := r.subject()
	if r.source.id == "ssh-agent" {
		if key, dest, ok := splitSSH(s); ok {
			who := "this one key"
			if strings.Contains(key, "*") {
				who = shortKey(key)
			}
			where := "signing in to " + dest
			switch {
			case dest == "**" || dest == "*":
				// A wildcard never covers arbitrary data: only a rule
				// naming "(arbitrary data)" allows it.
				where = "signing in anywhere (not arbitrary data — that needs a rule naming it)"
			case strings.Contains(dest, "*"):
				where = "signing in to anything matching " + dest
			case dest == "(arbitrary data)":
				where = "signing arbitrary data — anything the box hands it, not a login"
			case strings.HasPrefix(dest, "sshsig:"):
				where = "making SSHSIG signatures in the " + strings.TrimPrefix(dest, "sshsig:") + " namespace (git signing uses \"git\")"
			case dest == "(destination unknown)":
				where = "signing for a login whose destination devtun could not see"
			}
			return who + ", " + where
		}
	}
	if account, rest, ok := splitAccount(s); ok {
		inner := m.meaning(accessRow{rule: authz.Rule{Subject: rest}, source: r.source})
		if account == "*" {
			return inner + " — in any 1Password account"
		}
		return inner + " — in the " + account + " account"
	}
	if strings.HasPrefix(s, "op://") {
		parts := strings.Split(strings.TrimPrefix(s, "op://"), "/")
		if !strings.Contains(s, "*") && len(parts) == 3 {
			return "the " + parts[2] + " field of " + parts[1] + ", in the " + parts[0] + " vault — exactly this secret"
		}
		if base, ok := strings.CutSuffix(s, "/**"); ok && !strings.Contains(base, "*") {
			return "everything under " + base + "/"
		}
		if len(parts) == 3 && parts[2] == "*" && !strings.Contains(parts[0]+parts[1], "*") {
			return "any field of " + parts[1] + ", in the " + parts[0] + " vault"
		}
		return "any reference matching this pattern — * is one path segment, ** any depth"
	}
	if strings.HasPrefix(s, "op ") {
		return "this exact op command line"
	}
	if strings.Contains(s, "*") {
		return "anything matching this pattern — * stops at /, ** does not"
	}
	return "exactly this"
}

// --- keys and actions ------------------------------------------------------

func (m *Model) handleAccessKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "enter", "d":
		return m.toggleDetail()
	case "r":
		return m.revokeSelected()
	case "D":
		return m.denySelected()
	case "y":
		return m.copyReference()
	case "F":
		return m.forgetGrants()
	case "X":
		return m.clearRefusals()
	case "n":
		return m.openNewRule()
	case "w":
		return m.openWiden()
	case "t":
		return m.openTest()
	}
	return nil
}

// readOnlyReason is what a global rule says when asked to change. It names
// the file, so the message is a direction and not just a refusal.
const readOnlyReason = "global rule — edit it in config.yaml"

// revokeBlocked says why `r` cannot act on the selected row, or "".
func (m *Model) revokeBlocked() string {
	r, ok := m.selectedAccess()
	switch {
	case !ok:
		return "pick a rule or grant first"
	case r.global:
		return readOnlyReason
	}
	return ""
}

// denyBlocked says why `D` cannot act on the selected row, or "".
func (m *Model) denyBlocked() string {
	r, ok := m.selectedAccess()
	switch {
	case !ok:
		return "pick a rule first"
	case r.isGrant:
		// A grant is not a rule and has no action to rewrite. Revoking it is
		// the whole of what can be done, and r already does that.
		return "a live grant — r takes it back"
	case r.global:
		return readOnlyReason
	case r.rule.Action == authz.ActionDeny:
		return "already a deny"
	}
	return ""
}

// copyBlocked says why `y` has nothing to copy, or "".
func (m *Model) copyBlocked() string {
	r, ok := m.selectedAccess()
	switch {
	case !ok:
		return "pick a row first"
	case r.isGrant && r.grant.HostWide:
		return "it covers everything — there is no one reference to copy"
	case r.subject() == "":
		return "nothing on this row to copy"
	}
	return ""
}

// forgetBlocked says why `F` has nothing to do, or "".
func (m *Model) forgetBlocked() string {
	// Not "no grants": values can be cached with nothing live to show for
	// it, and forgetting those is half of what F is for.
	if len(m.d.secrets) == 0 {
		return "no broker is running"
	}
	return ""
}

// revokeSelected takes back a rule or grant.
//
// Taking back an allow only ever tightens, so it is one keystroke. Taking back
// a deny — a rule, or a "stop asking" refusal — opens the door again, and that
// is the accident deny-beats-allow exists to prevent; it goes through a
// confirm that says exactly what will be asked about again.
func (m *Model) revokeSelected() tea.Cmd {
	if len(m.d.secrets) == 0 {
		return m.needSelection()
	}
	row, ok := m.selectedAccess()
	if !ok {
		return m.needSelection()
	}
	if why := m.revokeBlocked(); why != "" {
		return m.showToast(toastMsg{text: why, bad: true})
	}
	if row.action() == authz.ActionDeny {
		return m.ask(m.loosenConfirm(row))
	}
	return m.doRevoke(row)
}

// loosenConfirm is the question before removing a refusal.
func (m *Model) loosenConfirm(row accessRow) confirmState {
	title, what := "Remove a refusal?", "deny rule · "+m.sourceWhere(row.rule)
	var who string
	if row.isGrant {
		title, what = "Stop refusing?", "\"No, and stop asking\" · this session"
		who = row.grant.Host
	} else {
		// The rule's own host pattern, not this session's host: a rule in
		// the global file, or one written for "dev-*", reaches further.
		who = hostScope(row.rule.Host)
		if row.rule.Host == m.d.host {
			who = m.d.host
		}
		what += " · applies to " + who
	}
	if !row.isGrant && !row.rule.Added.IsZero() {
		what += " · added " + ago(m.d.now().Sub(row.rule.Added))
	}
	body := []string{
		ui.Error.Render("✕") + " " + ui.Muted.Render(row.svc()) + " " + ui.Secret.Render(row.subject()),
		"  " + ui.Muted.Render(what),
		"",
	}
	body = append(body, m.afterRemoval(row, who)...)
	return confirmState{
		title:  title,
		body:   body,
		yes:    "remove it",
		no:     "keep refusing",
		danger: true,
		run:    func(mm *Model) tea.Cmd { return mm.doRevoke(row) },
	}
}

// afterRemoval says what a request this refusal covers would get once it is
// gone, from the store's own explanation with this refusal left out — rather
// than promising a prompt that an allow underneath, or an unmatched deny,
// would never show. The subject is the refusal's own pattern, so for a
// wildcard it describes the representative request, and says so.
func (m *Model) afterRemoval(row accessRow, who string) []string {
	ex := row.source.ctrl.Explain(m.d.host, row.subject())
	var next *authz.Matched
	for i := range ex.Matches {
		mt := ex.Matches[i]
		if (mt.Rule != nil && !row.isGrant && mt.Rule.ID == row.rule.ID) ||
			(mt.Grant != nil && row.isGrant && mt.Grant.ID == row.grant.ID) {
			continue
		}
		// Evaluation order: the first remaining match decides.
		next = &mt
		break
	}
	var out []string
	switch {
	case next != nil && denyMatch(*next):
		out = append(out, "It stays refused — another deny matches it:", "    "+m.matchLine(row.source, *next))
	case next != nil:
		out = append(out, capitalize(who)+" "+gets(who)+" it without being asked — an allow matches it:", "    "+m.matchLine(row.source, *next))
	default:
		word, _ := m.unmatchedWord(row.source)
		if word == "ask" {
			out = append(out, capitalize(who)+" will be asked about it again, and a Yes will hand it over.")
		} else {
			out = append(out, "Nothing else matches, and this broker refuses what nothing matches ("+word+") —", "so it stays refused unless a rule allows it later.")
		}
	}
	if strings.ContainsAny(row.subject(), "*?[") {
		out = append(out, ui.Muted.Render("For a pattern this is the likely outcome, not the only one: other requests it covers may meet other rules."))
	}
	return out
}

// doRevoke removes a row through whichever door it lives behind: a grant is
// in memory and addressed by what it covers, a rule is a line in a file
// addressed by ID. `r` should not make the user care which.
func (m *Model) doRevoke(row accessRow) tea.Cmd {
	if row.isGrant {
		if !row.source.ctrl.RevokeGrant(row.grant.ID) {
			return m.showToast(toastMsg{text: "that grant has already lapsed", bad: true})
		}
		m.reloadAccess()
		m.clampCursor()
		return m.showToast(toastMsg{text: "revoked the " + row.label() + " for " + m.glossSubject(row, 60)})
	}
	if err := row.source.ctrl.RemoveRule(row.rule.ID); err != nil {
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	m.reloadAccess()
	m.clampCursor()
	return m.showToast(toastMsg{text: "revoked " + row.rule.Subject})
}

// denySelected turns the selected allow rule into a refusal.
//
// This is the one edit the tab offers, and it goes one way on purpose. Rewriting
// a rule you regret as a deny is the change people actually want to make in a
// hurry — "I clicked always and I should not have, and I do not want to be asked
// again either". It only tightens, so it needs no confirm.
//
// D, not d: it rewrites policy, and an upper-case key is not pressed by accident
// while scrolling.
func (m *Model) denySelected() tea.Cmd {
	row, ok := m.selectedAccess()
	if len(m.d.secrets) == 0 || !ok {
		return m.needSelection()
	}
	if why := m.denyBlocked(); why != "" {
		return m.showToast(toastMsg{text: why, bad: row.rule.Action != authz.ActionDeny || row.isGrant || row.global})
	}
	if _, err := row.source.ctrl.SetRuleAction(row.rule.ID, authz.ActionDeny); err != nil {
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	m.reloadAccess()
	return m.showToast(toastMsg{text: "now denying " + row.rule.Subject})
}

// copyReference yanks the reference — the *name* of the secret, never its
// value.
//
// This is not an oversight to be fixed later. A secret value on the clipboard
// is a secret in every paste buffer, screenshot tool and clipboard manager on
// the machine, and devtun's entire argument is that the value stays in the
// vault. The reference is what you actually want anyway: it is what you paste
// into a script.
func (m *Model) copyReference() tea.Cmd {
	row, ok := m.selectedAccess()
	if !ok {
		return m.needSelection()
	}
	if why := m.copyBlocked(); why != "" {
		return m.showToast(toastMsg{text: why, bad: true})
	}
	ref := row.subject()
	return tea.Batch(yank(ref), m.showToast(toastMsg{text: "copied " + ref}))
}

// forgetGrants drops the live approvals, and everything cached under one,
// across every broker.
//
// It is the "lock it back up" action, and it only ever tightens: refusals —
// every "No, and stop asking" — survive it, because a panic button that
// re-opened questions you had closed would be the opposite of one. So it is
// one keystroke. Clearing the refusals is its own action, X, behind a confirm.
func (m *Model) forgetGrants() tea.Cmd {
	if len(m.d.secrets) == 0 {
		return nil
	}
	var grants, cached int
	for _, src := range m.d.secrets {
		g, c := src.ctrl.Forget()
		grants, cached = grants+g, cached+c
	}
	m.reloadAccess()
	m.clampCursor()
	text := "forgot " + itoa(grants) + " grant" + plural(grants) + " and " + itoa(cached) + " cached value" + plural(cached)
	if grants == 0 && cached == 0 {
		text = "nothing to forget"
	}
	if n := m.liveRefusals(); n > 0 {
		text += " · kept " + itoa(n) + " refusal" + plural(n) + " (X clears them)"
	}
	return m.showToast(toastMsg{text: text})
}

// liveRefusals counts the "stop asking" refusals held right now.
func (m *Model) liveRefusals() int {
	n := 0
	for _, src := range m.d.secrets {
		for _, g := range src.ctrl.Grants() {
			if g.Action == authz.ActionDeny {
				n++
			}
		}
	}
	return n
}

// refusalsBlocked says why X has nothing to do, or "".
func (m *Model) refusalsBlocked() string {
	if m.liveRefusals() == 0 {
		return "no \"stop asking\" refusals are live"
	}
	return ""
}

// clearRefusals drops every live "stop asking" refusal, after asking: each
// one is a question you closed, and this opens all of them again.
func (m *Model) clearRefusals() tea.Cmd {
	n := m.liveRefusals()
	if n == 0 {
		return m.showToast(toastMsg{text: m.refusalsBlocked(), bad: true})
	}
	return m.ask(confirmState{
		title: "Clear " + itoa(n) + " refusal" + plural(n) + "?",
		body: []string{
			itoa(n) + " \"No, and stop asking\" answer" + plural(n) + " " + goes(n) + ":",
			m.d.host + " will be asked about " + pluralThose(n) + " again, and a Yes will hand it over.",
			ui.Muted.Render("Deny rules on disk still refuse what they match."),
		},
		yes:    "clear them",
		no:     "keep refusing",
		danger: true,
		run: func(mm *Model) tea.Cmd {
			total := 0
			for _, src := range mm.d.secrets {
				total += src.ctrl.ForgetRefusals()
			}
			mm.reloadAccess()
			mm.clampCursor()
			return mm.showToast(toastMsg{text: "cleared " + itoa(total) + " refusal" + plural(total)})
		},
	})
}

func goes(n int) string {
	if n == 1 {
		return "goes"
	}
	return "go"
}

func pluralThose(n int) string {
	if n == 1 {
		return "that one"
	}
	return "those"
}

// --- detail ----------------------------------------------------------------

// rankingText is the detail's account of how a row stands against the rest:
// for an allow, what beats it; for a deny, what it beats. Both come from the
// store's own Explain, asked with the row's pattern as the subject.
func (m *Model) rankingText(r accessRow) string {
	var b strings.Builder
	if r.action() == authz.ActionAllow {
		if !r.outranked {
			return ""
		}
		if r.exact {
			b.WriteString("\n  " + ui.Warn.Render("⚠ This never wins. A deny matches every request it would allow:") + "\n")
		} else {
			b.WriteString("\n  " + ui.Warn.Render("⚠ A deny matches this pattern, so at least some of what it allows is refused:") + "\n")
		}
		for _, mt := range r.by {
			b.WriteString("      " + m.matchLine(r.source, mt) + "\n")
		}
		b.WriteString("  " + ui.Muted.Render("A deny always beats an allow. To allow only some things, set this broker's") + "\n")
		b.WriteString("  " + ui.Muted.Render("\"unmatched\" to deny (Config ▸ Policy) and drop the catch-all deny.") + "\n")
		return b.String()
	}
	if r.isGrant && r.grant.HostWide {
		return ""
	}
	// What a deny beats is every allow that lists it among what outranks
	// it — computed when the rows were loaded, so the two views agree.
	var beats []authz.Matched
	for _, other := range m.accessRows {
		for _, mt := range other.by {
			if (mt.Rule != nil && !r.isGrant && mt.Rule.ID == r.rule.ID) ||
				(mt.Grant != nil && r.isGrant && mt.Grant.ID == r.grant.ID) {
				if other.isGrant {
					beats = append(beats, authz.Matched{Grant: other.grant})
				} else {
					rule := other.rule
					beats = append(beats, authz.Matched{Rule: &rule})
				}
			}
		}
	}
	b.WriteString("\n  " + ui.Muted.Render("A deny always beats an allow, wherever the allow is written.") + "\n")
	if len(beats) > 0 {
		b.WriteString("  " + ui.Muted.Render("It beats:") + "\n")
		for _, mt := range beats {
			b.WriteString("      " + m.matchLine(r.source, mt) + "\n")
		}
	}
	return b.String()
}

// matchLine is one rule or grant from an explanation, in a line.
func (m *Model) matchLine(src accessSource, mt authz.Matched) string {
	switch {
	case mt.Rule != nil:
		glyph := ui.OK.Render("✓ allow")
		if mt.Rule.Action == authz.ActionDeny {
			glyph = ui.Error.Render("✕ deny ")
		}
		return glyph + "  " + ui.Secret.Render(m.glossSubject(accessRow{rule: *mt.Rule, source: src}, 48)) +
			"  " + ui.Muted.Render(sourceWho(*mt.Rule)+" · "+m.sourceWhere(*mt.Rule))
	case mt.Grant != nil:
		row := accessRow{grant: mt.Grant, isGrant: true, source: src}
		glyph := ui.OK.Render("✓ grant")
		if mt.Grant.Action == authz.ActionDeny {
			glyph = ui.Error.Render("✕ stop-ask")
		}
		life, _ := m.lifetime(row)
		return glyph + "  " + ui.Secret.Render(m.glossSubject(row, 48)) + "  " + ui.Muted.Render("live · "+life)
	}
	return ""
}

// accessDetailBox is everything known about the selected row, and what can be
// done to it — including what cannot, and why.
func (m *Model) accessDetailBox() string {
	r, ok := m.selectedAccess()
	if !ok {
		return ""
	}
	row := func(label, value string) string {
		if value == "" {
			return ""
		}
		return "  " + ui.Muted.Render(pad(label, 10)) + value + "\n"
	}

	kind, where := "rule", sourceWho(r.rule)+" · "+m.sourceWhere(r.rule)
	switch {
	case r.isGrant:
		kind, where = r.label(), "in memory, this session"
	case r.global:
		where += " · read-only here"
	}

	glyph := ui.OK.Render("✓ allow")
	if r.action() == authz.ActionDeny {
		glyph = ui.Error.Render("✕ deny ")
	}

	var b strings.Builder
	b.WriteString(ui.Banner.Render(kind) + ui.Muted.Render(" · "+r.source.title+" · "+where) + "\n\n")
	subject := r.subject()
	if r.isGrant && r.grant.HostWide {
		subject = hostWideGloss(r.source.id, r.grant.Host)
	}
	b.WriteString("  " + glyph + "  " + ui.Secret.Render(subject) + "\n\n")
	b.WriteString(row("means", m.meaning(r)))
	if r.isGrant {
		life, _ := m.lifetime(r)
		if life == "session" {
			life = "until devtun quits"
		}
		b.WriteString(row("lasts", life))
		b.WriteString(row("host", r.grant.Host))
	} else {
		applies := hostScope(r.rule.Host)
		if r.rule.Host == m.d.host {
			applies = m.d.host + " only"
		}
		b.WriteString(row("applies", applies))
		if !r.rule.Added.IsZero() {
			b.WriteString(row("added", r.rule.Added.Format("2006-01-02")+" · "+ago(m.d.now().Sub(r.rule.Added))))
		}
		b.WriteString(row("note", r.rule.Note))
	}
	b.WriteString(m.rankingText(r))
	return m.detailFrame(b.String())
}
