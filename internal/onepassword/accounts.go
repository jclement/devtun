package onepassword

import (
	"github.com/jclement/devtun/internal/onepassword/opref"
)

// Accounts routes a request to one of several 1Password accounts.
//
// A secret reference names a vault but not an account, and `op` resolves an
// ambiguous vault against whichever account is currently the default — so with
// two accounts signed in, half your references quietly fail. Vaults belong to
// exactly one account, so the vault is the right thing to route on.
type Accounts struct {
	// Default is used for any vault not named in ByVault. Empty means "let op
	// decide", which is correct when only one account is signed in.
	Default string `yaml:"default,omitempty"`
	// ByVault maps a vault name to the account that holds it.
	ByVault map[string]string `yaml:"by_vault,omitempty"`
}

// For returns the account to use for a subject, or "" to let op choose.
func (a Accounts) For(subject string) string {
	if ref, err := opref.Parse(subject); err == nil {
		if account, ok := a.ByVault[ref.Vault]; ok {
			return account
		}
	}
	return a.Default
}
