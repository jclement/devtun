// Package ui holds every Lipgloss style devtun uses, plus the terminal
// capability checks that decide between a coloured presentation and plain
// output fit for a pipe or a log file.
//
// Styles live here rather than inline so the palette changes in one place, and
// so the log renderer, the approval prompt and the TUI cannot disagree about
// what a vault reference looks like. That agreement is not cosmetic: the whole
// argument for putting secrets and tunnels in one window is that you can still
// tell them apart, and you can only tell them apart if the treatment is
// identical everywhere.
//
// Lipgloss v2 has no adaptive colour type — the caller resolves light-vs-dark
// once and bakes it in. Init does that and is called from main before anything
// is printed. The package works without it; the defaults assume a dark
// terminal, so tests and the shim need no setup.
package ui

import (
	"image/color"
	"os"

	"charm.land/lipgloss/v2"
	"golang.org/x/term"

	"github.com/jclement/devtun/internal/event"
)

// Styles, rebuilt by Init once the background is known.
var (
	Banner      lipgloss.Style
	Muted       lipgloss.Style
	OK          lipgloss.Style
	Warn        lipgloss.Style
	Error       lipgloss.Style
	Secret      lipgloss.Style
	Host        lipgloss.Style
	Panel       lipgloss.Style
	SecretPanel lipgloss.Style
	Warning     lipgloss.Style
	// Tunnel is the network palette: the counterweight to Secret, and the
	// contrast between them is the one that has to survive a glance.
	Tunnel lipgloss.Style
	// Active marks a tunnel with traffic flowing through it right now.
	Active lipgloss.Style
	// Fresh marks something that has just appeared.
	Fresh lipgloss.Style
	// Header is the tab bar and column headings.
	Header lipgloss.Style
	// Selected is the highlighted row.
	Selected lipgloss.Style
	// Danger is the LAN-EXPOSED banner and anything else that should stop you.
	Danger lipgloss.Style
)

// Raw palette colours, for callers that need a colour rather than a style —
// Huh themes and Bubbles components take these.
var (
	ColorAccent color.Color
	ColorOK     color.Color
	ColorWarn   color.Color
	ColorError  color.Color
	ColorMuted  color.Color
	ColorSecret color.Color
	ColorTunnel color.Color
)

func init() { apply(true) }

// Init detects the terminal background and rebuilds the palette to suit it.
// Detection is skipped unless stdin and stdout are both terminals, because the
// query writes an escape sequence and waits for a reply — which, into a pipe,
// is a hang.
func Init() {
	// A pipe gets no colour. Detection has to happen here rather than at each
	// call site, because otherwise every one of them has to remember — and the
	// one that forgets writes escape sequences into somebody's log file, or
	// into the help text they redirected to a file to read later.
	if !IsTTY() {
		NoColor()
		return
	}
	dark := true
	if IsInteractive() {
		dark = lipgloss.HasDarkBackground(os.Stdin, os.Stdout)
	}
	apply(dark)
}

// NoColor strips the palette back to plain text, for --no-color and for a
// terminal that cannot do better.
func NoColor() {
	Banner = lipgloss.NewStyle()
	Muted = lipgloss.NewStyle()
	OK = lipgloss.NewStyle()
	Warn = lipgloss.NewStyle()
	Error = lipgloss.NewStyle()
	Secret = lipgloss.NewStyle()
	Host = lipgloss.NewStyle()
	Panel = lipgloss.NewStyle()
	SecretPanel = lipgloss.NewStyle()
	Warning = lipgloss.NewStyle()
	Tunnel = lipgloss.NewStyle()
	Active = lipgloss.NewStyle()
	Fresh = lipgloss.NewStyle()
	Header = lipgloss.NewStyle()
	Selected = lipgloss.NewStyle()
	Danger = lipgloss.NewStyle()
}

func apply(dark bool) {
	pick := lipgloss.LightDark(dark)

	ColorAccent = pick(lipgloss.Color("#0550AE"), lipgloss.Color("#7AA2F7"))
	ColorOK = pick(lipgloss.Color("#1A7F37"), lipgloss.Color("#9ECE6A"))
	ColorWarn = pick(lipgloss.Color("#9A6700"), lipgloss.Color("#E0AF68"))
	ColorError = pick(lipgloss.Color("#CF222E"), lipgloss.Color("#F7768E"))
	ColorMuted = pick(lipgloss.Color("#6E7781"), lipgloss.Color("#565F89"))
	// Secret is violet and Tunnel is cyan: far enough apart in hue that the
	// two classes separate even in peripheral vision, which is the only kind
	// of attention a log scrolling past actually gets.
	ColorSecret = pick(lipgloss.Color("#8250DF"), lipgloss.Color("#BB9AF7"))
	ColorTunnel = pick(lipgloss.Color("#0F6FA8"), lipgloss.Color("#7DCFFF"))

	Banner = lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)
	Muted = lipgloss.NewStyle().Foreground(ColorMuted)
	OK = lipgloss.NewStyle().Foreground(ColorOK)
	Warn = lipgloss.NewStyle().Foreground(ColorWarn)
	Error = lipgloss.NewStyle().Foreground(ColorError)
	Secret = lipgloss.NewStyle().Bold(true).Foreground(ColorSecret)
	Tunnel = lipgloss.NewStyle().Foreground(ColorTunnel)
	Host = lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)
	Active = lipgloss.NewStyle().Bold(true).Foreground(ColorOK)
	Fresh = lipgloss.NewStyle().Foreground(ColorAccent)
	Header = lipgloss.NewStyle().Bold(true).Foreground(ColorMuted)
	Selected = lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)
	Danger = lipgloss.NewStyle().Bold(true).Foreground(ColorError)
	Panel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColorAccent).Padding(0, 1)
	// SecretPanel frames the approval prompt. It is violet because violet
	// means "vault" everywhere else here, and an approval that looks like
	// every other overlay is one people dismiss by reflex.
	SecretPanel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColorSecret).Padding(0, 1)
	Warning = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColorWarn).Padding(0, 1)
}

// ClassStyle returns the style an event of this class is rendered in. One
// function, used by the log renderer and the TUI alike, so the two can never
// drift.
func ClassStyle(c event.Class) lipgloss.Style {
	switch c {
	case event.Security:
		return Secret
	case event.Network:
		return Tunnel
	case event.Diagnostic:
		return Muted
	default:
		return Banner
	}
}

// ClassGlyph returns the single-width marker for a class. Security gets a lock
// because it is the one you must never mistake for anything else.
func ClassGlyph(c event.Class) string {
	switch c {
	case event.Security:
		return "🔒"
	case event.Network:
		return "⇄"
	case event.Diagnostic:
		return "·"
	default:
		return "⧉"
	}
}

// GlyphCells is how many terminal cells ClassGlyph occupies.
//
// It is a table rather than a measurement on purpose. Width libraries disagree
// about emoji — lipgloss reports U+1F512 as one cell while every terminal draws
// it as two — and the symptom is subtle: every secret line sits one column
// right of every tunnel line, which quietly destroys the alignment the log
// exists to have. We choose the glyphs, so we can simply know.
func GlyphCells(c event.Class) int {
	if c == Security {
		return 2 // 🔒 is an emoji-presentation code point
	}
	return 1
}

// Security re-exports the class so GlyphCells reads without an import cycle in
// callers that only need the width.
const Security = event.Security

// LevelStyle returns the style for a severity, for the parts of a line that
// carry severity rather than class.
func LevelStyle(l event.Level) lipgloss.Style {
	switch l {
	case event.Warn:
		return Warn
	case event.Error:
		return Error
	case event.Debug:
		return Muted
	default:
		return lipgloss.NewStyle()
	}
}

// IsInteractive reports whether stdin and stdout are both terminals, which is
// the precondition for asking a human anything.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// IsTTY reports whether stdout is a terminal, which is what decides between a
// rendered presentation and machine-readable output.
func IsTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
