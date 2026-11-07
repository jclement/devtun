package onepassword

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/prompt"
)

// twoAccounts is the configuration these tests share: a default account, and
// a second one the Shared vault is routed to.
func twoAccounts() Accounts {
	return Accounts{Default: "personal", ByVault: map[string]string{"Shared": "work"}}
}

// TestAGrantForOneAccountDoesNotCoverAnother: a read approved in the default
// account must not authorise `op --account work read` of the same reference.
func TestAGrantForOneAccountDoesNotCoverAnother(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}
	h := start(t, Options{Prompter: prompter, Accounts: twoAccounts()},
		map[string]string{"op://Private/App/password": "mine"})

	if response := h.exec(t, "read", "op://Private/App/password"); response.Exit != 0 {
		t.Fatalf("default-account read: exit = %d, error = %q", response.Exit, response.Error)
	}
	prompter.answer(prompt.ChoiceDeny)
	if response := h.exec(t, "--account", "work", "read", "op://Private/App/password"); response.Exit != ExitDenied {
		t.Fatalf("a grant for the default account covered --account work: exit = %d", response.Exit)
	}
	if n := prompter.count(); n != 2 {
		t.Errorf("asked %d times, want 2: the other account is its own question", n)
	}
}

// TestBareRulesMeanTheDefaultAccountOnly: a bare rule covers the default
// account, by omission or by naming it, and nothing else — not an account the
// remote names, and not one a vault is routed to.
func TestBareRulesMeanTheDefaultAccountOnly(t *testing.T) {
	opts := Options{
		Accounts: twoAccounts(),
		Rules:    []authz.Rule{{Host: "**", Subject: "op://**", Action: authz.ActionAllow}},
	}
	h := start(t, opts, map[string]string{"op://Private/App/password": "mine", "op://Shared/App/password": "work"})

	if response := h.exec(t, "read", "op://Private/App/password"); response.Exit != 0 {
		t.Fatalf("the bare rule no longer allows the default account: %q", response.Error)
	}
	if response := h.exec(t, "--account", "personal", "read", "op://Private/App/password"); response.Exit != 0 {
		t.Fatalf("naming the default account is the default account: %q", response.Error)
	}
	if response := h.exec(t, "--account=work", "read", "op://Private/App/password"); response.Exit != ExitDenied {
		t.Fatalf("a bare rule allowed --account work: exit = %d", response.Exit)
	}
	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Fatalf("a bare rule allowed a vault routed to work: exit = %d", response.Exit)
	}
}

// TestAnAccountRuleNamesTheAccount: `[work] op://…` allows that account,
// whether it was named or routed to, and only that account.
func TestAnAccountRuleNamesTheAccount(t *testing.T) {
	opts := Options{
		Accounts: twoAccounts(),
		Rules:    []authz.Rule{{Host: "**", Subject: "[work] op://**", Action: authz.ActionAllow}},
	}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "work", "op://Private/App/password": "mine"})

	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != 0 {
		t.Fatalf("[work] did not allow a vault routed to work: %q", response.Error)
	}
	if response := h.exec(t, "--account", "work", "read", "op://Private/App/password"); response.Exit != 0 {
		t.Fatalf("[work] did not allow --account work: %q", response.Error)
	}
	if response := h.exec(t, "read", "op://Private/App/password"); response.Exit != ExitDenied {
		t.Fatalf("[work] allowed the default account: exit = %d", response.Exit)
	}
}

// TestAScopedDenyHoldsAgainstImplicitRouting is the review's P1. A deny on
// `[work] op://Shared/App/password` used to be stepped around by leaving
// --account off: the bare subject matched a bare allow, and routing then sent
// the read to work anyway. Exec and batched resolve alike.
func TestAScopedDenyHoldsAgainstImplicitRouting(t *testing.T) {
	opts := Options{
		Accounts: twoAccounts(),
		Rules: []authz.Rule{
			{Host: "**", Subject: "**", Action: authz.ActionAllow},
			{Host: "**", Subject: "[work] op://Shared/App/password", Action: authz.ActionDeny},
		},
	}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "work-secret", "op://Shared/App/other": "fine"})

	for name, argv := range map[string][]string{
		"explicit": {"--account", "work", "read", "op://Shared/App/password"},
		"implicit": {"read", "op://Shared/App/password"},
		"item get": {"item", "get", "App", "--vault", "Shared", "--fields", "password"},
	} {
		if response := h.exec(t, argv...); response.Exit != ExitDenied {
			t.Errorf("%s: the scoped deny was stepped around: exit = %d", name, response.Exit)
		}
	}
	if response := h.resolve(t, "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Errorf("resolve: the scoped deny was stepped around: exit = %d", response.Exit)
	}
	if n := h.runner.reads(); n != 0 {
		t.Errorf("the vault was read %d times", n)
	}
	if response := h.resolve(t, "op://Shared/App/other"); response.Exit != 0 {
		t.Errorf("a neighbouring secret was refused: %q", response.Error)
	}
}

// TestAnotherSpellingOfAnAccountIsRefused: op accepts a sign-in address, an
// account ID or a user ID for the same account, and devtun cannot tell them
// from a different account. Only the configured names are accepted, so a rule
// on one name cannot be escaped by another — and with no accounts configured,
// no --account is accepted at all.
func TestAnotherSpellingOfAnAccountIsRefused(t *testing.T) {
	h := start(t, Options{Accounts: twoAccounts(), Rules: []authz.Rule{{Host: "**", Subject: "**", Action: authz.ActionAllow}}}, nil)
	for _, spelling := range []string{"work.1password.com", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Work"} {
		response := h.exec(t, "--account", spelling, "read", "op://Shared/App/password")
		if response.Exit != ExitDenied || !strings.Contains(response.Error, "not one of the accounts") {
			t.Errorf("--account %s: exit = %d, error = %q", spelling, response.Exit, response.Error)
		}
	}

	bare := start(t, allowAll(), nil)
	if response := bare.exec(t, "--account", "work", "read", "op://V/I/F"); response.Exit != ExitDenied {
		t.Errorf("with no accounts configured, --account was honoured: exit = %d", response.Exit)
	}
	if n := len(h.runner.accountsUsed()) + len(bare.runner.accountsUsed()); n != 0 {
		t.Errorf("op ran %d times", n)
	}
}

// TestNamingAnAccountDoesNotEscapeABareDeny: a deny written as a bare
// reference is about the item, wherever it lives.
func TestNamingAnAccountDoesNotEscapeABareDeny(t *testing.T) {
	opts := Options{
		Accounts: twoAccounts(),
		Rules: []authz.Rule{
			{Host: "**", Subject: "**", Action: authz.ActionAllow},
			{Host: "**", Subject: "op://Private/Root Keys/**", Action: authz.ActionDeny},
		},
	}
	h := start(t, opts, map[string]string{"op://Private/Root Keys/ssh": "root"})

	response := h.exec(t, "--account", "work", "read", "op://Private/Root Keys/ssh")
	if response.Exit != ExitDenied || !strings.Contains(response.Error, "denied by rule") {
		t.Fatalf("--account stepped around a deny: exit = %d, error = %q", response.Exit, response.Error)
	}
	if n := h.runner.reads(); n != 0 {
		t.Errorf("the vault was read %d times", n)
	}
}

// TestOpIsToldTheResolvedAccountOnly: the caller's --account is taken out of
// the argv and the runner passes the resolved one, so op is handed exactly one
// account, and it is the one that was authorised.
func TestOpIsToldTheResolvedAccountOnly(t *testing.T) {
	opts := allowAll()
	opts.Accounts = twoAccounts()
	h := start(t, opts, nil)

	h.exec(t, "--account", "work", "read", "op://Private/App/password")
	h.exec(t, "read", "op://Shared/App/password")
	h.exec(t, "read", "op://Private/App/password")
	if got, want := h.runner.accountsUsed(), []string{"work", "work", "personal"}; !reflect.DeepEqual(got, want) {
		t.Errorf("accounts = %v, want %v", got, want)
	}
	for _, argv := range h.runner.execs {
		for _, arg := range argv {
			if strings.HasPrefix(arg, "--account") {
				t.Errorf("op was run with the caller's own selector: %q", argv)
			}
		}
	}
}

// TestAmbiguousAccountsAreRefused: two --account flags, or one whose value
// could reshape the subject, are refused before policy.
func TestAmbiguousAccountsAreRefused(t *testing.T) {
	opts := allowAll()
	opts.Accounts = twoAccounts()
	h := start(t, opts, nil)
	for _, argv := range [][]string{
		{"--account", "work", "read", "--account", "personal", "op://V/I/F"},
		{"--account", "work] op://Personal", "read", "op://V/I/F"},
		{"read", "op://V/I/F", "--account"},
	} {
		if response := h.exec(t, argv...); response.Exit != ExitDenied {
			t.Errorf("%q: exit = %d, want refused", argv, response.Exit)
		}
	}
	if n := len(h.runner.accountsUsed()); n != 0 {
		t.Errorf("op ran %d times", n)
	}
}

// TestUnmatchedDenyDoesNotRefuseAnAccountAllow: the bare-reference deny check
// honours only denies a rule or refusal made. Under `unmatched: deny` the bare
// reference has no rule and so "denies" — which must not refuse an explicit
// `[work] op://…` allow.
func TestUnmatchedDenyDoesNotRefuseAnAccountAllow(t *testing.T) {
	opts := Options{
		Accounts: twoAccounts(),
		Rules:    []authz.Rule{{Host: "**", Subject: "[work] op://Shared/**", Action: authz.ActionAllow}},
	}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "work"})
	h.host.config.seed(t, "unmatched", "deny")

	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != 0 {
		t.Fatalf("unmatched: deny refused an explicitly allowed account: %q", response.Error)
	}
	if response := h.exec(t, "read", "op://Private/App/password"); response.Exit != ExitDenied {
		t.Fatalf("unmatched: deny should still refuse what nothing allows: exit = %d", response.Exit)
	}
}

// TestADefaultAccountsScopedDenyStillApplies is the re-review's R1. With work
// as the default, its subjects are bare, so a deny written as
// `[work] op://Shared/App/password` used to match nothing and a broad allow
// won — by --account, by omission, and by resolve. Denies are now checked
// against the scoped identity as well as the bare one, always.
func TestADefaultAccountsScopedDenyStillApplies(t *testing.T) {
	opts := Options{
		Accounts: Accounts{Default: "work"},
		Rules: []authz.Rule{
			{Host: "**", Subject: "**", Action: authz.ActionAllow},
			{Host: "**", Subject: "[work] op://Shared/App/password", Action: authz.ActionDeny},
		},
	}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "s", "op://Shared/App/other": "fine"})

	for name, argv := range map[string][]string{
		"explicit": {"--account", "work", "read", "op://Shared/App/password"},
		"implicit": {"read", "op://Shared/App/password"},
	} {
		if response := h.exec(t, argv...); response.Exit != ExitDenied {
			t.Errorf("%s: the default account's scoped deny did not apply: exit = %d", name, response.Exit)
		}
	}
	if response := h.resolve(t, "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Errorf("resolve: the default account's scoped deny did not apply: exit = %d", response.Exit)
	}
	if n := h.runner.reads(); n != 0 {
		t.Errorf("the vault was read %d times", n)
	}
	if response := h.exec(t, "read", "op://Shared/App/other"); response.Exit != 0 {
		t.Errorf("a neighbouring secret was refused: %q", response.Error)
	}
}

// TestADenyOutlivesItsAccountBecomingTheDefault: a deny written for work while
// work was a routed account keeps refusing after work is made the default.
func TestADenyOutlivesItsAccountBecomingTheDefault(t *testing.T) {
	rules := []authz.Rule{
		{Host: "**", Subject: "**", Action: authz.ActionAllow},
		{Host: "**", Subject: "[work] op://Shared/**", Action: authz.ActionDeny},
	}
	for name, accounts := range map[string]Accounts{
		"routed":  {Default: "personal", ByVault: map[string]string{"Shared": "work"}},
		"default": {Default: "work"},
	} {
		h := start(t, Options{Accounts: accounts, Rules: rules}, map[string]string{"op://Shared/App/password": "s"})
		if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != ExitDenied {
			t.Errorf("%s: the [work] deny did not apply: exit = %d", name, response.Exit)
		}
	}
}
