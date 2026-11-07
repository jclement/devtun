package authz

import "strings"

// What a subject is made of, per broker.
//
// A subject used to be one opaque string to everything but the broker that
// built it, and two things went wrong because of that. A person writing a rule
// had nothing to tell them what the string was made of, so they wrote what
// looked right. And matching treated every subject as a path, so the `*` that
// means "one path segment" in `op://Personal/*` also stopped at the `/` that
// about half of all SHA256 key fingerprints contain — `* → github.com`, the
// rule the agent's own documentation recommended, silently failed to match
// those keys.
//
// A schema names the parts. The interface shows them as fields rather than as
// a string to get exactly right, and matching compares a pattern with a
// subject part by part, each part with the glob dialect that suits it.

// Field is one named part of a subject.
type Field struct {
	// Name is stable and machine-readable: "reference", "key", "destination".
	Name string
	// Label is what a column or a form calls it.
	Label string
	// Help is one line on what to write there.
	Help string
}

// Schema describes one broker's subjects.
type Schema struct {
	// Noun is what one request is for — "secret", "signature", "site" — so a
	// screen can say "any signature from bedev" rather than "anything".
	Noun string
	// Fields are the parts, in the order they appear in the subject.
	Fields []Field
	// Separator joins the fields. Empty for a single-field schema.
	Separator string
	// PathLike makes `*` and `?` stop at `/`, the way they do in a shell. It
	// is right for op:// references, where `/` separates vault, item and
	// field, and wrong for anything that merely contains a slash.
	PathLike bool
}

// DefaultSchema is a single path-like field, which is what every subject was
// treated as before brokers described their own.
var DefaultSchema = Schema{
	Noun:     "request",
	Fields:   []Field{{Name: "subject", Label: "subject", Help: "what is being asked for"}},
	PathLike: true,
}

// Split breaks a subject or a pattern into one value per field.
//
// A pattern written without the separator — `**`, or a single field typed on
// its own — fills the fields it does not mention with `**`, which matches the
// same requests it did as a whole: "**" is every key to every destination, and
// says so when it is shown as two fields.
func (s Schema) Split(subject string) []string {
	n := len(s.Fields)
	if n <= 1 || s.Separator == "" {
		return []string{subject}
	}
	parts := strings.SplitN(subject, s.Separator, n)
	for len(parts) < n {
		parts = append(parts, HostWildcard)
	}
	return parts
}

// Join is Split's inverse.
func (s Schema) Join(values []string) string {
	if len(s.Fields) <= 1 || s.Separator == "" {
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	return strings.Join(values, s.Separator)
}

// Match reports whether a subject matches a pattern under this schema.
//
// A multi-field pattern is matched field by field. A pattern that does not
// contain the separator at all is matched against the whole subject instead,
// with wildcards free to cross everything — so the host-wide `**` keeps
// meaning everything, and `ssh-ed25519 *` means every ed25519 key, anywhere.
func (s Schema) Match(pattern, subject string) bool {
	if len(s.Fields) <= 1 || s.Separator == "" {
		return matchGlob(pattern, subject, s.PathLike)
	}
	if !strings.Contains(pattern, s.Separator) {
		return matchGlob(pattern, subject, false)
	}
	patterns := strings.SplitN(pattern, s.Separator, len(s.Fields))
	values := strings.SplitN(subject, s.Separator, len(s.Fields))
	if len(patterns) != len(values) {
		return false
	}
	for i := range patterns {
		if !matchGlob(patterns[i], values[i], s.PathLike) {
			return false
		}
	}
	return true
}

// fields reports whether the schema has more than one field.
func (s Schema) multi() bool { return len(s.Fields) > 1 && s.Separator != "" }

// withDefaults fills in a schema a caller left empty.
func (s Schema) withDefaults() Schema {
	if len(s.Fields) == 0 {
		return DefaultSchema
	}
	if s.Noun == "" {
		s.Noun = DefaultSchema.Noun
	}
	return s
}
