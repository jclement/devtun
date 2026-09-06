package onepassword

import (
	"testing"
)

func TestAccountsFor(t *testing.T) {
	accounts := Accounts{
		Default: "personal.1password.com",
		ByVault: map[string]string{"Barreleye": "work.1password.com"},
	}
	tests := map[string]string{
		"op://Barreleye/CI/token": "work.1password.com",
		"op://Private/Docker/PAT": "personal.1password.com",
		"op://Barreleye/CI":       "work.1password.com",
		"op vault list":           "personal.1password.com",
		"op://?/Docker/PAT":       "personal.1password.com",
	}
	for subject, want := range tests {
		if got := accounts.For(subject); got != want {
			t.Errorf("For(%q) = %q, want %q", subject, got, want)
		}
	}
}

// With one account signed in there is nothing to route, and passing --account
// unnecessarily would just be another way to get it wrong.
func TestAccountsForWithNothingConfigured(t *testing.T) {
	if got := (Accounts{}).For("op://V/I/F"); got != "" {
		t.Errorf("For() = %q, want empty so op picks", got)
	}
}

// A live "allow anything from bedev for 5 minutes" is the most consequential
// state in the process. Until it could be listed, the only thing anyone could
// do about it was drop every grant at once.
