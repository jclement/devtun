package authz

import "testing"

// TestALiteralValueIsAllowedOnlyByName: a value a field marks Literal is
// covered by an allow pattern only when the pattern names it in that field,
// while deny matching is unchanged.
func TestALiteralValueIsAllowedOnlyByName(t *testing.T) {
	schema := Schema{
		Fields: []Field{
			{Name: "key"},
			{Name: "destination", Literal: []string{"(arbitrary data)"}},
		},
		Separator: " → ",
	}
	const subject = "ssh-ed25519 SHA256:ab/cd → (arbitrary data)"
	for pattern, want := range map[string]bool{
		"**":                           false,
		"* → *":                        false,
		"* → **":                       false,
		"ssh-ed25519 SHA256:ab/cd → *": false,
		"* → (arbitrary*":              false,
		"* → (arbitrary data)":         true,
		"ssh-ed25519 SHA256:ab/cd → (arbitrary data)": true,
	} {
		if got := schema.Allows(pattern, subject); got != want {
			t.Errorf("Allows(%q) = %v, want %v", pattern, got, want)
		}
		if !schema.Match(pattern, subject) && want {
			t.Errorf("Match(%q) is false for a pattern Allows accepts", pattern)
		}
	}
	if !schema.Match("* → *", subject) {
		t.Error("Match must still see * → * as matching, so a deny written that way refuses it")
	}
	if !schema.Allows("* → *", "ssh-ed25519 SHA256:ab/cd → github.com") {
		t.Error("an ordinary destination lost its wildcard allow")
	}
}
