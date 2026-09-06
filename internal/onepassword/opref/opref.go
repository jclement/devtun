// Package opref understands 1Password secret references (op://…) and turns an
// `op` command line into the human-readable "subject" that approval prompts
// display and policy rules match against.
//
// Subjects are the vocabulary of the whole authorisation layer, so they must be
// stable: the same logical secret requested two different ways should produce
// the same subject, or a rule the user approved once will not apply the next
// time.
package opref

import (
	"fmt"
	"regexp"
	"strings"
)

// Scheme is the prefix of every 1Password secret reference.
const Scheme = "op://"

// Ref is a parsed op:// reference. Section is optional and rarely used; Field
// is optional for whole-item references.
type Ref struct {
	Vault   string
	Item    string
	Section string
	Field   string
	// Query is the part after `?`, kept without the leading mark.
	//
	// It was once discarded as decoration. It is not: `?attribute=otp` asks for
	// the one-time code rather than the field's own value, so dropping it meant
	// the *wrong secret* was fetched — and, because the canonical form was also
	// the cache key, a read with the query and one without shared an entry and
	// could be served each other's value.
	Query string
}

// String renders the reference back into canonical op:// form.
func (r Ref) String() string {
	parts := []string{r.Vault, r.Item}
	if r.Section != "" {
		parts = append(parts, r.Section)
	}
	if r.Field != "" {
		parts = append(parts, r.Field)
	}
	out := Scheme + strings.Join(parts, "/")
	if r.Query != "" {
		out += "?" + r.Query
	}
	return out
}

// Parse reads a secret reference of the form op://vault/item[/section]/field.
func Parse(s string) (Ref, error) {
	if !strings.HasPrefix(s, Scheme) {
		return Ref{}, fmt.Errorf("%q is not a 1Password secret reference (expected op://…)", s)
	}
	// The query selects which value of a field is wanted — `?attribute=otp`
	// asks for the one-time code — so it identifies the secret just as much as
	// the path does, and is kept.
	body := strings.TrimPrefix(s, Scheme)
	query := ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		query, body = body[i+1:], body[:i]
	}
	parts := strings.Split(strings.Trim(body, "/"), "/")
	for _, p := range parts {
		if p == "" {
			return Ref{}, fmt.Errorf("%q has an empty path segment", s)
		}
	}
	switch len(parts) {
	case 2:
		return Ref{Vault: parts[0], Item: parts[1], Query: query}, nil
	case 3:
		return Ref{Vault: parts[0], Item: parts[1], Field: parts[2], Query: query}, nil
	case 4:
		return Ref{Vault: parts[0], Item: parts[1], Section: parts[2], Field: parts[3], Query: query}, nil
	default:
		return Ref{}, fmt.Errorf("%q must have between 2 and 4 path segments", s)
	}
}

// refPattern finds secret references embedded in arbitrary text, which is how
// `op inject` templates and `op run` environments carry them. The character
// class stops at whitespace and at the shell/quoting characters that would
// realistically terminate a reference in a config file.
var refPattern = regexp.MustCompile(`op://[^\s"'` + "`" + `<>|;,)\]}]+`)

// Find returns every distinct secret reference appearing in text, in order of
// first appearance. Malformed candidates are skipped rather than reported: a
// template is allowed to contain the literal text "op://" for other reasons,
// and failing the whole injection over it would be surprising.
func Find(text string) []string {
	var found []string
	seen := make(map[string]bool)
	for _, candidate := range refPattern.FindAllString(text, -1) {
		// Trailing punctuation is far more likely to belong to the surrounding
		// document than to the reference itself.
		candidate = strings.TrimRight(candidate, ".:")
		if _, err := Parse(candidate); err != nil {
			continue
		}
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		found = append(found, candidate)
	}
	return found
}

// Subject describes what a request is asking for, in a form that is both shown
// to the user and matched by policy rules.
//
// For anything expressible as a secret reference the subject is that reference,
// so `op read op://Personal/Docker/PAT` and a template mentioning the same
// reference share one rule. Everything else falls back to the normalised
// command line, which is deliberately coarse: a rule for an unrecognised
// command should not silently cover a different one.
func Subject(argv []string) string {
	if len(argv) == 0 {
		return "op"
	}
	positional, flags := splitArgs(argv)

	if len(positional) > 0 && positional[0] == "read" && len(positional) > 1 {
		if ref, err := Parse(positional[1]); err == nil {
			return ref.String()
		}
	}

	// `op item get <item> --vault v --fields f` is the other common way to pull
	// a single value; map it onto the same reference shape so one approval
	// covers both spellings.
	if len(positional) >= 3 && positional[0] == "item" && positional[1] == "get" {
		vault := flags["vault"]
		if vault == "" {
			vault = "?"
		}
		ref := Ref{Vault: vault, Item: positional[2], Field: fieldFromFlag(flags["fields"])}
		return ref.String()
	}

	return "op " + strings.Join(argv, " ")
}

// fieldFromFlag reduces --fields to a single field name for subject purposes.
// The flag accepts a comma-separated list and "label=" / "type=" qualifiers;
// anything beyond one plain field name is reported as "*" so that the subject
// stays honest about covering more than one value.
func fieldFromFlag(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, ",") {
		return "*"
	}
	if eq := strings.IndexByte(value, '='); eq >= 0 {
		return value[eq+1:]
	}
	return value
}

// splitArgs separates positional arguments from flags, understanding both
// --flag=value and --flag value forms. Flag values are returned keyed by the
// flag name with dashes stripped.
func splitArgs(argv []string) (positional []string, flags map[string]string) {
	flags = make(map[string]string)
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			positional = append(positional, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			flags[name[:eq]] = name[eq+1:]
			continue
		}
		// A following non-flag token is treated as this flag's value. Boolean
		// flags therefore consume nothing, which is why the next token is only
		// claimed when it does not itself look like a flag.
		if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") && takesValue(name) {
			flags[name] = argv[i+1]
			i++
		} else {
			flags[name] = ""
		}
	}
	return positional, flags
}

// valueFlags lists the `op` flags that take a separate value argument. Guessing
// wrongly would misalign positional arguments, so the list is explicit rather
// than heuristic.
var valueFlags = map[string]bool{
	"vault": true, "fields": true, "format": true, "account": true,
	"out-file": true, "session": true, "config": true, "in-file": true,
	"otp": true, "categories": true, "tags": true, "favorite": true,
	"env-file": true, "cache": true, "encoding": true,
}

func takesValue(name string) bool { return valueFlags[name] }
