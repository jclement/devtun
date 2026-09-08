package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/event"
)

// A styled string written into a pipe is escape sequences in somebody's log
// file, so the palette has to be able to go away completely.
func TestNoColorProducesPlainText(t *testing.T) {
	t.Cleanup(func() { apply(true) })
	NoColor()

	for name, style := range map[string]interface{ Render(...string) string }{
		"Secret": Secret, "Tunnel": Tunnel, "Error": Error,
		"Muted": Muted, "Banner": Banner, "Danger": Danger,
	} {
		got := style.Render("text")
		if got != "text" {
			t.Errorf("%s should render plainly, got %q", name, got)
		}
		if strings.Contains(got, "\x1b") {
			t.Errorf("%s still emits escape sequences", name)
		}
	}
}

// The entire argument for putting secrets and tunnels in one window is that
// you can still tell them apart. If these ever collide, that argument is gone.
func TestClassesAreVisuallyDistinct(t *testing.T) {
	t.Cleanup(func() { apply(true) })
	apply(true)

	glyphs := map[string]event.Class{}
	for _, c := range []event.Class{event.Security, event.Network, event.Lifecycle, event.Diagnostic} {
		g := ClassGlyph(c)
		if prev, clash := glyphs[g]; clash {
			t.Errorf("%q and %q share the glyph %q", c, prev, g)
		}
		glyphs[g] = c
	}

	if ClassStyle(event.Security).Render("x") == ClassStyle(event.Network).Render("x") {
		t.Error("security and network events render identically")
	}
}

// Never define a colour only under one background: a light terminal that fell
// back to an unset colour is unreadable, not merely different.
func TestPaletteIsCompleteInBothThemes(t *testing.T) {
	t.Cleanup(func() { apply(true) })

	for _, dark := range []bool{true, false} {
		apply(dark)
		for name, c := range map[string]any{
			"accent": ColorAccent, "ok": ColorOK, "warn": ColorWarn,
			"error": ColorError, "muted": ColorMuted,
			"secret": ColorSecret, "tunnel": ColorTunnel,
		} {
			if c == nil {
				t.Errorf("colour %q is unset with dark=%v", name, dark)
			}
		}
	}
}

func TestOpenURLRefusesNonWebSchemes(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"ssh://box",
		"javascript:alert(1)",
		"vscode://open",
	} {
		if err := OpenURL(t.Context(), raw); err == nil {
			t.Errorf("%q should be refused before it reaches a launcher", raw)
		}
	}
}

// Every glyph devtun draws must be one terminal cell and must not be an
// emoji-presentation code point.
//
// Both halves matter and each was violated. An emoji renders in the terminal's
// colour-emoji font — different weight, different baseline, different family
// from the ⇄ and ◱ beside it — which looks wrong on a monospace board. And it
// is two cells wide while lipgloss reports one, so a whole class of line ends
// up a column right of every other line.
//
// This is the enforcement. A glyph added anywhere in devtun should be added
// here too, and an emoji should fail before it is ever seen.
func TestEveryGlyphIsOneCell(t *testing.T) {
	glyphs := map[string]string{
		"security":   ClassGlyph(event.Security),
		"network":    ClassGlyph(event.Network),
		"lifecycle":  ClassGlyph(event.Lifecycle),
		"diagnostic": ClassGlyph(event.Diagnostic),
		// The service glyphs, copied from each service's Meta. They cannot be
		// read from here without an import cycle, so they are restated — and a
		// mismatch is caught by the reader, which is the trade this makes.
		"tunnels":   "⇄",
		"1password": "❖",
		"ssh-agent": "◈",
		"gpg-agent": "✎",
		"browser":   "◱",
	}

	for name, glyph := range glyphs {
		if got := ansi.StringWidth(glyph); got != 1 {
			t.Errorf("%s glyph %q measures %d cells, want 1", name, glyph, got)
		}
		for _, r := range glyph {
			// The emoji planes. A code point up here is drawn by the colour
			// font whatever its declared width, which is the part that looks
			// wrong even when the arithmetic happens to work out.
			if r >= 0x1F300 {
				t.Errorf("%s glyph %q is an emoji (U+%04X); devtun draws text glyphs", name, glyph, r)
			}
		}
	}
}
