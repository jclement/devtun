package tui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/onepassword/policy"
	"github.com/jclement/devtun/internal/ui"
)

// secretRow is one line of the Secrets tab: something currently standing
// between this host and the vault. That is either a rule written to disk or a
// live grant somebody clicked through, and the tab shows both — a grant is the
// more consequential of the two and the shorter-lived, so it is listed first.
type secretRow struct {
	rule policy.Rule
	// index is the rule's position in the broker's own list, which is what
	// Revoke takes. Filtering the view must not change what `r` revokes, so the
	// index travels with the row rather than being its position on screen.
	index int
	// grant is set instead of rule for a live allowance.
	grant   *policy.Grant
	isGrant bool
}

// reloadSecrets pulls the live grants and the host's persistent rules.
//
// Grants come first because they are the answer to "what is open right now",
// which is the question this tab exists for. A rule is a decision you made
// deliberately and can read on disk; a grant is one you clicked through a
// minute ago and may well have forgotten.
func (m *Model) reloadSecrets() {
	if m.d.secrets == nil {
		m.secretRows = nil
		return
	}
	q := strings.ToLower(strings.TrimSpace(m.search[tabSecrets]))
	matches := func(text string) bool {
		return q == "" || strings.Contains(strings.ToLower(text), q)
	}

	rows := make([]secretRow, 0, 8)
	for _, g := range m.d.secrets.Grants() {
		grant := g
		if !matches(g.Host + " " + g.Subject) {
			continue
		}
		rows = append(rows, secretRow{grant: &grant, isGrant: true})
	}
	for i, r := range m.d.secrets.Rules() {
		if !matches(r.Host + " " + r.Subject + " " + r.Note) {
			continue
		}
		rows = append(rows, secretRow{rule: r, index: i})
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
	if m.d.secrets == nil {
		empty = "the 1Password broker is not running on this host"
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
	if r.rule.Action == policy.ActionDeny {
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
func (m *Model) grantLine(g policy.Grant, selected bool) string {
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

	line := " " + ui.Warn.Render(pad("grant", 6)) + "  " + ui.Muted.Render(pad(g.Host, 14)) + "  " + subject
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
	if m.d.secrets == nil || i < 0 || i >= len(m.secretRows) {
		return m.needSelection()
	}
	row := m.secretRows[i]

	// A grant and a rule are revoked through different doors: one lives in
	// memory and is addressed by what it covers, the other is a line in a file
	// addressed by position. `r` should not make the user care which.
	if row.isGrant {
		if !m.d.secrets.RevokeGrant(row.grant.Host, row.grant.Subject) {
			return m.showToast(toastMsg{text: "that grant has already lapsed", bad: true})
		}
		m.reloadSecrets()
		m.clampCursor()
		return m.showToast(toastMsg{text: "revoked the grant for " + row.grant.Subject})
	}

	if err := m.d.secrets.Revoke(row.index); err != nil {
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

// forgetGrants drops every live grant and everything cached under one.
//
// It is the "lock it back up" action, and it is the only thing the interface
// can say about grants at all: the broker holds them in memory and offers no
// way to enumerate them, so the count in the toast is the first and last time
// they are visible.
func (m *Model) forgetGrants() tea.Cmd {
	if m.d.secrets == nil {
		return nil
	}
	grants, cached := m.d.secrets.Forget()
	if grants == 0 && cached == 0 {
		return m.showToast(toastMsg{text: "nothing to forget"})
	}
	return m.showToast(toastMsg{text: "forgot " + itoa(grants) + " grant" + plural(grants) +
		" and " + itoa(cached) + " cached value" + plural(cached)})
}
