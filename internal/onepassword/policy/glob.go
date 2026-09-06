// Glob matching for policy subjects. Subjects are slash-separated (they are
// usually op:// references), so the wildcard semantics follow the shell rather
// than a plain regexp: `*` stops at a separator and `**` does not. That is what
// makes `op://Personal/*` mean "any item in Personal" rather than "everything".
package policy

import "strings"

// Match reports whether subject matches pattern.
//
//	?   one character, not a separator
//	*   any run of characters, not crossing a separator
//	**  any run of characters, separators included
//
// Matching is case-sensitive because 1Password vault and item names are.
func Match(pattern, subject string) bool {
	return matchFrom(pattern, subject)
}

func matchFrom(pattern, subject string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			if strings.HasPrefix(pattern, "**") {
				rest := strings.TrimLeft(pattern, "*")
				// `**` is greedy but must still allow the remainder to match, so
				// try every split point from shortest consumed to longest.
				for i := 0; i <= len(subject); i++ {
					if matchFrom(rest, subject[i:]) {
						return true
					}
				}
				return false
			}
			rest := pattern[1:]
			for i := 0; i <= len(subject); i++ {
				if i > 0 && subject[i-1] == '/' {
					break // a single star never crosses a separator
				}
				if matchFrom(rest, subject[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(subject) == 0 || subject[0] == '/' {
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
