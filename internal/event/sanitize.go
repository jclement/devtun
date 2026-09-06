package event

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitize makes a string from the remote box safe to draw on a terminal.
//
// Process names, command lines, caller fields, vault references and URLs all
// originate on a machine devtun treats as only semi-trusted, and all of them
// end up in event text that a renderer writes straight to a terminal. A string
// is not just data there: an escape sequence in a process name can move the
// cursor, erase the line, repaint what an approval prompt appears to say, or —
// with OSC 52 — write to the clipboard of the machine reading the log.
//
// The rule is that everything from over there is text and nothing from over
// there is an instruction. So: control characters go, C1 escapes go, and the
// oddities that make one string look like another go too — bidirectional
// overrides can reverse the visible order of a vault reference, and a
// zero-width space can hide inside one.
//
// This is applied on ingestion rather than at each renderer, because there are
// several renderers and only one boundary.
func Sanitize(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// Invalid UTF-8 arrived; do not pass the replacement through as if
			// it were content.
			b.WriteByte('?')
		case r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// Includes \n and \r: a newline lets one remote string forge what
			// looks like a second log line.
			b.WriteByte(' ')
		case isFormatting(r):
			// Zero-width and bidirectional controls: invisible, and able to
			// make op://Personal/X read as something else entirely.
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// isFormatting reports the invisible and direction-altering code points.
func isFormatting(r rune) bool {
	switch {
	case r == 0x200B, r == 0x200C, r == 0x200D, r == 0xFEFF: // zero width, BOM
		return true
	case r >= 0x202A && r <= 0x202E: // bidirectional overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // bidirectional isolates
		return true
	case r == 0x00AD: // soft hyphen
		return true
	}
	// Cf is the general "format" category, which covers the rest of the
	// invisible steering characters without enumerating them.
	return unicode.Is(unicode.Cf, r)
}

// SanitizeTo trims a sanitised string to at most n runes, which keeps a hostile
// remote from pushing everything else off the line.
func SanitizeTo(s string, n int) string {
	s = Sanitize(s)
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
