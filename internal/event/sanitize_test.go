package event

import (
	"strings"
	"testing"
)

// A string from the remote box is text, never an instruction. The clipboard
// case is the one that matters most: OSC 52 in a process name would write to
// the clipboard of whoever is *reading the log*.
func TestSanitizeStripsTerminalControl(t *testing.T) {
	// A control character becomes a space rather than vanishing: the remaining
	// gap is evidence that something was stripped, where silent deletion would
	// leave a plausible-looking string with no sign it had been tampered with.
	cases := map[string]string{
		"\x1b]52;c;cGF5bG9hZA==\x07evil": "]52;c;cGF5bG9hZA== evil",
		"vite\x1b[2K\x1b[1Gnot vite":     "vite [2K [1Gnot vite",
		"node\nfake log line":            "node fake log line",
		"node\rrewritten":                "node rewritten",
		"tabs\there":                     "tabs here",
		"\x07bell":                       "bell",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(Sanitize(in), "\x1b\x07\n\r") {
			t.Errorf("Sanitize(%q) left a control character: %q", in, Sanitize(in))
		}
	}
}

// A bidirectional override can reverse the visible order of a vault reference,
// so op://Personal/X can be made to read as something else entirely.
func TestSanitizeStripsInvisibleAndDirectionCharacters(t *testing.T) {
	for _, in := range []string{
		"op://Personal/\u202etekcoP/X", // right-to-left override
		"op://Per\u200bsonal/X",        // zero-width space
		"op://Personal/\u2066X\u2069",  // bidi isolate
		"node\ufeff",                   // byte order mark
	} {
		got := Sanitize(in)
		for _, r := range got {
			if isFormatting(r) {
				t.Errorf("Sanitize(%q) left an invisible steering character in %q", in, got)
			}
		}
	}
}

// Ordinary text must survive untouched, or sanitising would cost more than it
// buys.
func TestSanitizeLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"node vite --host",
		"op://Personal/Docker/PAT",
		"python3 -m http.server 8080",
		"café ☕ node",
		"/home/jsc/projects/api",
	} {
		if got := Sanitize(in); got != in {
			t.Errorf("Sanitize(%q) = %q, want it unchanged", in, got)
		}
	}
}

// A hostile remote should not be able to push everything else off the line.
func TestSanitizeToBounds(t *testing.T) {
	long := strings.Repeat("x", 500)

	got := SanitizeTo(long, 64)

	if len([]rune(got)) != 64 {
		t.Errorf("want 64 runes, got %d", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated string should say so, got %q", got)
	}
	if short := SanitizeTo("node", 64); short != "node" {
		t.Errorf("a short string should be untouched, got %q", short)
	}
}

func TestSanitizeHandlesInvalidUTF8(t *testing.T) {
	if got := Sanitize(string([]byte{0xff, 0xfe, 'o', 'k'})); !strings.HasSuffix(got, "ok") {
		t.Errorf("invalid bytes should degrade, not vanish the content: %q", got)
	}
}
