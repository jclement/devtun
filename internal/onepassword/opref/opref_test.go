package opref

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Ref
		wantErr bool
	}{
		{name: "vault and item", input: "op://Personal/Docker", want: Ref{Vault: "Personal", Item: "Docker"}},
		{name: "with field", input: "op://Personal/Docker/PAT", want: Ref{Vault: "Personal", Item: "Docker", Field: "PAT"}},
		{name: "with section", input: "op://Personal/Docker/tokens/PAT", want: Ref{Vault: "Personal", Item: "Docker", Section: "tokens", Field: "PAT"}},
		// The query is kept: it selects which value of the field is wanted, so
		// two references differing only by it are two different secrets.
		{name: "query string preserved", input: "op://Personal/Docker/PAT?attribute=otp", want: Ref{Vault: "Personal", Item: "Docker", Field: "PAT", Query: "attribute=otp"}},
		{name: "wrong scheme", input: "https://example.com/x", wantErr: true},
		{name: "too few segments", input: "op://Personal", wantErr: true},
		{name: "too many segments", input: "op://a/b/c/d/e", wantErr: true},
		{name: "empty segment", input: "op://Personal//PAT", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) succeeded, want an error", test.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Errorf("Parse(%q) = %+v, want %+v", test.input, got, test.want)
			}
		})
	}
}

func TestRefStringRoundTrips(t *testing.T) {
	for _, input := range []string{"op://Personal/Docker", "op://Personal/Docker/PAT", "op://Personal/Docker/tokens/PAT"} {
		ref, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		if got := ref.String(); got != input {
			t.Errorf("round trip of %q gave %q", input, got)
		}
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "env file",
			input: "TOKEN=op://Personal/Docker/PAT\nOTHER=op://Work/CI/key\n",
			want:  []string{"op://Personal/Docker/PAT", "op://Work/CI/key"},
		},
		{
			name:  "quoted and duplicated",
			input: `a: "op://V/I/F"\nb: 'op://V/I/F'`,
			want:  []string{"op://V/I/F"},
		},
		{
			name:  "trailing sentence punctuation is not part of the reference",
			input: "the value is op://V/I/F.",
			want:  []string{"op://V/I/F"},
		},
		{
			name:  "malformed candidates are skipped",
			input: "see op:// for details",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Find(test.input); !reflect.DeepEqual(got, test.want) {
				t.Errorf("Find() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSubject(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{name: "read", argv: []string{"read", "op://Personal/Docker/PAT"}, want: "op://Personal/Docker/PAT"},
		// The subject keeps the query too, so approving a password does not
		// silently approve that item's one-time code as well.
		{name: "read keeps the query string", argv: []string{"read", "op://Personal/Docker/PAT?attribute=otp"}, want: "op://Personal/Docker/PAT?attribute=otp"},
		{
			name: "item get maps onto the same reference",
			argv: []string{"item", "get", "Docker", "--vault", "Personal", "--fields", "PAT"},
			want: "op://Personal/Docker/PAT",
		},
		{
			name: "item get with a label qualifier",
			argv: []string{"item", "get", "Docker", "--vault=Personal", "--fields=label=PAT"},
			want: "op://Personal/Docker/PAT",
		},
		{
			name: "item get for several fields is not one secret",
			argv: []string{"item", "get", "Docker", "--vault", "Personal", "--fields", "PAT,username"},
			want: "op://Personal/Docker/*",
		},
		{
			name: "item get without a vault is still distinct",
			argv: []string{"item", "get", "Docker", "--fields", "PAT"},
			want: "op://?/Docker/PAT",
		},
		{name: "anything else falls back to the command line", argv: []string{"vault", "list"}, want: "op vault list"},
		{name: "empty", argv: nil, want: "op"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Subject(test.argv); got != test.want {
				t.Errorf("Subject(%v) = %q, want %q", test.argv, got, test.want)
			}
		})
	}
}

// A read of a reference and an item get of the same field must produce the same
// subject, or approving one would not cover the other and the user would be
// asked twice for one secret.
func TestSubjectAgreesAcrossSpellings(t *testing.T) {
	viaRead := Subject([]string{"read", "op://Personal/Docker/PAT"})
	viaItem := Subject([]string{"item", "get", "Docker", "--vault", "Personal", "--fields", "PAT"})
	if viaRead != viaItem {
		t.Errorf("subjects differ: %q vs %q", viaRead, viaItem)
	}
}

// `?attribute=otp` asks for the one-time code rather than the field's own
// value, so it identifies the secret just as much as the path does. Dropping it
// fetched the wrong secret, and — because the canonical form was also the cache
// key — let a read with the query and one without be served each other's value.
func TestQuerySurvivesAndDistinguishesReferences(t *testing.T) {
	withQuery, err := Parse("op://Personal/GitHub/one-time password?attribute=otp")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if withQuery.Query != "attribute=otp" {
		t.Errorf("the query was dropped, got %q", withQuery.Query)
	}
	if !strings.HasSuffix(withQuery.String(), "?attribute=otp") {
		t.Errorf("String must round-trip the query, got %q", withQuery.String())
	}

	plain, err := Parse("op://Personal/GitHub/one-time password")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if plain.String() == withQuery.String() {
		t.Error("two references asking for different values must not be identical")
	}
	if plain.Query != "" {
		t.Errorf("a reference with no query should have none, got %q", plain.Query)
	}

	// The path parts are still parsed identically; only the query differs.
	if plain.Vault != withQuery.Vault || plain.Field != withQuery.Field {
		t.Error("the query must not disturb the path")
	}
}
