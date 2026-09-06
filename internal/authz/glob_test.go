package authz

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		subject string
		want    bool
	}{
		{name: "exact", pattern: "op://V/I/F", subject: "op://V/I/F", want: true},
		{name: "exact mismatch", pattern: "op://V/I/F", subject: "op://V/I/G", want: false},

		{name: "star matches one segment", pattern: "op://Personal/*", subject: "op://Personal/Docker", want: true},
		{name: "star does not cross a separator", pattern: "op://Personal/*", subject: "op://Personal/Docker/PAT", want: false},
		{name: "star in the middle", pattern: "op://Personal/*/PAT", subject: "op://Personal/Docker/PAT", want: true},

		{name: "double star crosses separators", pattern: "op://Personal/**", subject: "op://Personal/Docker/PAT", want: true},
		{name: "double star alone matches everything", pattern: "**", subject: "op vault list", want: true},
		{name: "double star still has to match the prefix", pattern: "op://Work/**", subject: "op://Personal/Docker/PAT", want: false},

		{name: "question mark", pattern: "host?", subject: "host1", want: true},
		{name: "question mark does not match a separator", pattern: "a?b", subject: "a/b", want: false},

		{name: "case is significant", pattern: "op://personal/**", subject: "op://Personal/Docker", want: false},
		{name: "empty pattern matches only empty", pattern: "", subject: "x", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Match(test.pattern, test.subject); got != test.want {
				t.Errorf("Match(%q, %q) = %v, want %v", test.pattern, test.subject, got, test.want)
			}
		})
	}
}
