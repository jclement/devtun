package onepassword

import (
	"fmt"
	"slices"
	"strings"

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

// Known reports whether name is one of the configured accounts: the default,
// or an account some vault is routed to.
func (a Accounts) Known(name string) bool {
	if name == "" {
		return false
	}
	if name == a.Default {
		return true
	}
	for _, account := range a.ByVault {
		if account == name {
			return true
		}
	}
	return false
}

// names lists the configured accounts, for an error a person can act on.
func (a Accounts) names() []string {
	var out []string
	if a.Default != "" {
		out = append(out, a.Default)
	}
	for _, account := range a.ByVault {
		if !slices.Contains(out, account) {
			out = append(out, account)
		}
	}
	slices.Sort(out)
	return out
}

// Effective is the account a request will actually reach, resolved before any
// policy is consulted: the caller's --account if it names a configured
// account, else the vault's routing, else the default ("" lets op choose).
//
// Resolving first is what makes an account-scoped rule mean something. When
// routing was applied only after authorisation, a deny on `[work] op://…` was
// stepped around by simply leaving --account off — the bare subject matched a
// bare allow, and routing then sent the read to work anyway.
//
// A selector is accepted only if it is spelled exactly as configured. op also
// takes a sign-in address, an account ID or a user ID for the same account, and
// devtun cannot tell those apart from a different account without asking op;
// accepting them would let one account be named several ways and so escape a
// rule written for one of its names. With no accounts configured at all, any
// --account is refused for the same reason.
func (a Accounts) Effective(explicit, bare string) (string, error) {
	if explicit == "" {
		return a.For(bare), nil
	}
	if a.Known(explicit) {
		return explicit, nil
	}
	if names := a.names(); len(names) > 0 {
		return "", fmt.Errorf("--account %q is not one of the accounts devtun is configured with (%s); use one of those names exactly",
			explicit, strings.Join(names, ", "))
	}
	return "", fmt.Errorf("--account %q cannot be honoured: no 1Password accounts are configured in devtun (1password: accounts:)", explicit)
}

// Scope is the policy subject for a bare subject reaching account. The default
// account's subjects stay bare, so a bare rule means the default account and
// only that; every other account's are scoped, `[account] op://…`.
func (a Accounts) Scope(account, bare string) string {
	if account == "" || account == a.Default {
		return bare
	}
	return opref.Scoped(account, bare)
}
