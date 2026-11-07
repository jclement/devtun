// Glob matching for policy subjects. Most subjects are slash-separated (they
// are usually op:// references), so the default semantics follow the shell
// rather than a plain regexp: `*` stops at a separator and `**` does not. That
// is what makes `op://Personal/*` mean "any item in Personal" rather than
// "everything". A Schema can turn the separator off for a field that is not a
// path — see schema.go.
package authz

import "strings"

// Match reports whether subject matches pattern, treating `/` as a separator.
//
//	?   one character, not a separator
//	*   any run of characters, not crossing a separator
//	**  any run of characters, separators included
//
// Matching is case-sensitive because 1Password vault and item names are.
func Match(pattern, subject string) bool {
	return matchGlob(pattern, subject, true)
}

// matchGlob is Match with the separator optional. With slashes false, `*` and
// `?` cross `/` like any other character.
func matchGlob(pattern, subject string, slashes bool) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			if strings.HasPrefix(pattern, "**") {
				rest := strings.TrimLeft(pattern, "*")
				// `**` is greedy but must still allow the remainder to match, so
				// try every split point from shortest consumed to longest.
				for i := 0; i <= len(subject); i++ {
					if matchGlob(rest, subject[i:], slashes) {
						return true
					}
				}
				return false
			}
			rest := pattern[1:]
			for i := 0; i <= len(subject); i++ {
				if slashes && i > 0 && subject[i-1] == '/' {
					break // a single star never crosses a separator
				}
				if matchGlob(rest, subject[i:], slashes) {
					return true
				}
			}
			return false
		case '?':
			if len(subject) == 0 || (slashes && subject[0] == '/') {
				return false
			}
			pattern, subject = pattern[1:], subject[1:]
		default:
			if len(subject) == 0 || subject[0] != pattern[0] {
				return false
			}
			pattern, subject = pattern[1:], subject[1:]
		}
	}
	return len(subject) == 0
}
