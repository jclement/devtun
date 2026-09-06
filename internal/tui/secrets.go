package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/ui"
)

// secretRow is one line of the Secrets tab: something currently standing
// between this host and the vault. That is either a rule written to disk or a
// live grant somebody clicked through, and the tab shows both — a grant is the
// more consequential of the two and the shorter-lived, so it is listed first.
type secretRow struct {
	rule authz.Rule
	// index is the rule's position in the broker's own list, which is what
	// Revoke takes. Filtering the view must not change what `r` revokes, so the
	// index travels with the row rather than being its position on screen.
	index int
	// grant is set instead of rule for a live allowance.
	grant   *authz.Grant
	isGrant bool
	// source is which broker this row belongs to, since the tab shows more
	// than one and `r` has to revoke through the right door.
	source secretSource
	// global marks a rule that came from the top-level config. It is shown so
	// the tab answers "what is deciding", and it cannot be revoked here: devtun
	// did not write it, and quietly editing a file the user hand-wrote would be
	// a worse surprise than saying no.
	global bool
}

// reloadSecrets pulls the live grants and the host's persistent rules.
//
// Grants come first because they are the answer to "what is open right now",
// which is the question this tab exists for. A rule is a decision you made
// deliberately and can read on disk; a grant is one you clicked through a
// minute ago and may well have forgotten.
func (m *Model) reloadSecrets() {
	if len(m.d.secrets) == 0 {
		m.secretRows = nil
		return
	}
	q := strings.ToLower(strings.TrimSpace(m.search[tabSecrets]))
	matches := func(text string) bool {
		return q == "" || strings.Contains(strings.ToLower(text), q)
	}

	// Grants from every broker first, then rules from every broker. Grants are
	// shorter-lived and more consequential, and grouping by lifetime rather
	// than by broker is what makes the tab answer "what is open right now" at a
	// glance.
	rows := make([]secretRow, 0, 8)
	for _, src := range m.d.secrets {
		for _, g := range src.ctrl.Grants() {
			grant := g
			if !matches(src.title + " " + g.Host + " " + g.Subject) {
				continue
			}
			rows = append(rows, secretRow{grant: &grant, isGrant: true, source: src})
		}
	}
	for _, src := range m.d.secrets {
		for i, r := range src.ctrl.Rules() {
			if !matches(src.title + " " + r.Host + " " + r.Subject + " " + r.Note) {
				continue
			}
			rows = append(rows, secretRow{rule: r, index: i, source: src})
		}
	}
	// The global rules last, because they are the least likely to be what you
	// came to change — but present, because a tab that shows only half of what
	// is deciding will send somebody hunting for a rule that is right there.
	for _, src := range m.d.secrets {
		for _, r := range src.ctrl.GlobalRules() {
			if !matches(src.title + " " + r.Host + " " + r.Subject + " " + r.Note) {
				continue
			}
			rows = append(rows, secretRow{rule: r, source: src, global: true})
		}
	}
	m.secretRows = rows
}

func (m *Model) secretsView() string {
	var lines []string
	end := min(m.offset()+m.listHeight(), len(m.secretRows))
	for i := m.offset(); i < end; i++ {
		lines = append(lines, m.secretLine(m.secretRows[i], i == m.cursor()))
	}

	empty := "nothing is open — every request is asked about"
	if len(m.d.secrets) == 0 {
		empty = "no broker is running for this host"
	} else if m.search[tabSecrets] != "" {
		empty = "nothing matches " + m.search[tabSecrets]
	}
	return m.listView(lines, m.listHeight(), empty)
}

// secretLine renders one rule. The subject carries ui.Secret, the same
// treatment a vault reference gets in the log and in the approval prompt: it
// is the one string on screen you must never misread as something else.
func (m *Model) secretLine(r secretRow, selected bool) string {
	if r.isGrant {
		return m.grantLine(*r.grant, selected)
	}
	action := ui.OK.Render(pad(string(r.rule.Action), 6))
	if r.rule.Action == authz.ActionDeny {
		action = ui.Error.Render(pad(string(r.rule.Action), 6))
	}

	host := pad(r.rule.Host, 14)
	subject := ui.Secret.Render(r.rule.Subject)
	line := " " + action + "  " + ui.Muted.Render(host) + "  " + subject
	if !r.rule.Added.IsZero() {
		line += ui.Muted.Render("  added " + FormatAge(m.d.now().Sub(r.rule.Added)) + " ago")
	}
	if r.rule.Note != "" {
		line += ui.Muted.Render("  · " + r.rule.Note)
	}
	if r.global {
		// Say where it came from, so its being unrevocable here makes sense
		// before somebody presses `r` and finds out.
		line += ui.Muted.Render("  · from your config")
	}

	line = clampWidth(line, m.inner())
	if selected {
		if w := ansi.StringWidth(line); w < m.inner() {
			line += strings.Repeat(" ", m.inner()-w)
		}
		return ui.Selected.Reverse(true).Render(ansi.Strip(line))
	}
	return line
}

// grantLine renders a live allowance, with how long it has left.
//
// A grant with no expiry lasts as long as devtun does, which is a materially
// different promise from five minutes and has to read differently — "this
// session" rather than a countdown that never moves.
func (m *Model) grantLine(g authz.Grant, selected bool) string {
	left := ui.Muted.Render("this session")
	if !g.Expires.IsZero() {
		left = ui.Warn.Render(FormatAge(g.Expires.Sub(m.d.now())) + " left")
	}

	subject := ui.Secret.Render(g.Subject)
	if g.HostWide {
		// A grant covering everything from a host is not the same kind of
		// thing as one covering a secret, and should not look like one.
		subject = ui.Danger.Render("anything from " + g.Host)
	}

	// A refusal is live state too, and reading it as a grant would invert what
	// it says. The word and the colour both change.
	label, style := "grant", ui.Warn
	if g.Action == authz.ActionDeny {
		label, style = "refuse", ui.Error
	}
	line := " " + style.Render(pad(label, 6)) + "  " + ui.Muted.Render(pad(g.Host, 14)) + "  " + subject
	line += "  " + left

	line = clampWidth(line, m.inner())
	if selected {
		if w := ansi.StringWidth(line); w < m.inner() {
			line += strings.Repeat(" ", m.inner()-w)
		}
		return ui.Selected.Reverse(true).Render(ansi.Strip(line))
	}
	return line
}

func (m *Model) handleSecretsKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "r":
		return m.revokeSelected()
	case "y":
		return m.copyReference()
	case "F":
		return m.forgetGrants()
	}
	return nil
}

// revokeSelected takes back a rule this host was granted.
func (m *Model) revokeSelected() tea.Cmd {
	i := m.cursor()
	if len(m.d.secrets) == 0 || i < 0 || i >= len(m.secretRows) {
		return m.needSelection()
	}
	row := m.secretRows[i]

	// A grant and a rule are revoked through different doors: one lives in
	// memory and is addressed by what it covers, the other is a line in a file
	// addressed by position. `r` should not make the user care which.
	if row.global {
		return m.showToast(toastMsg{
			text: "that rule came from your config file — edit it there",
			bad:  true,
		})
	}
	if row.isGrant {
		if !row.source.ctrl.RevokeGrant(row.grant.Host, row.grant.Subject) {
			return m.showToast(toastMsg{text: "that grant has already lapsed", bad: true})
		}
		m.reloadSecrets()
		m.clampCursor()
		return m.showToast(toastMsg{text: "revoked the grant for " + row.grant.Subject})
	}

	if err := row.source.ctrl.Revoke(row.index); err != nil {
		return m.showToast(toastMsg{text: err.Error(), bad: true})
	}
	m.reloadSecrets()
	m.clampCursor()
	return m.showToast(toastMsg{text: "revoked " + row.rule.Subject})
}

// copyReference yanks the op:// reference — the *name* of the secret, never
// its value.
//
// This is not an oversight to be fixed later. A secret value on the clipboard
// is a secret in every paste buffer, screenshot tool and clipboard manager on
// the machine, and devtun's entire argument is that the value stays in the
// vault. The reference is what you actually want anyway: it is what you paste
// into a script.
func (m *Model) copyReference() tea.Cmd {
	i := m.cursor()
	if i < 0 || i >= len(m.secretRows) {
		return m.needSelection()
	}
	ref := m.secretRows[i].rule.Subject
	return tea.Batch(yank(ref), m.showToast(toastMsg{text: "copied " + ref}))
}

// forgetGrants drops every live grant, and everything cached under one, across
// every broker.
//
// It is the "lock it back up" action. Individual grants can now be revoked with
// `r`, so this is the panic button rather than the only option — and a panic
// button that left one broker still holding an open door would be worse than
// none, which is why it sweeps all of them.
func (m *Model) forgetGrants() tea.Cmd {
	if len(m.d.secrets) == 0 {
		return nil
	}
	var grants, cached int
	for _, src := range m.d.secrets {
		g, c := src.ctrl.Forget()
		grants, cached = grants+g, cached+c
	}
	if grants == 0 && cached == 0 {
		return m.showToast(toastMsg{text: "nothing to forget"})
	}
	return m.showToast(toastMsg{text: "forgot " + itoa(grants) + " grant" + plural(grants) +
		" and " + itoa(cached) + " cached value" + plural(cached)})
}
