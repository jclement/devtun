package onepassword

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/prompt"
)

// TestAGrantForOneAccountDoesNotCoverAnother is the cross-account P1: a read
// approved in the default account must not authorise
// `op --account personal read` of the same reference, which the CLI would
// resolve against a different vault entirely.
func TestAGrantForOneAccountDoesNotCoverAnother(t *testing.T) {
	prompter := &scriptedPrompter{choice: prompt.ChoiceAllowSecretSession}
	h := start(t, Options{Prompter: prompter}, map[string]string{"op://Shared/App/password": "work"})

	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != 0 {
		t.Fatalf("default-account read: exit = %d, error = %q", response.Exit, response.Error)
	}
	prompter.answer(prompt.ChoiceDeny)
	response := h.exec(t, "--account", "personal", "read", "op://Shared/App/password")
	if response.Exit != ExitDenied {
		t.Fatalf("a grant for the default account covered --account personal: exit = %d", response.Exit)
	}
	if n := prompter.count(); n != 2 {
		t.Errorf("asked %d times, want 2: the other account is its own question", n)
	}
	if n := h.runner.reads(); n != 1 {
		t.Errorf("the vault was read %d times, want 1", n)
	}
}

// TestExistingRulesMeanTheDefaultAccount: a rule written as a bare reference
// keeps meaning the account devtun picks, and does not widen to an account the
// remote names.
func TestExistingRulesMeanTheDefaultAccount(t *testing.T) {
	opts := Options{Rules: []authz.Rule{{Host: "**", Subject: "op://Shared/**", Action: authz.ActionAllow}}}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "work"})

	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != 0 {
		t.Fatalf("the rule no longer allows the default account: %q", response.Error)
	}
	if response := h.exec(t, "read", "--account=personal", "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Fatalf("op://Shared/** allowed --account personal: exit = %d", response.Exit)
	}
}

// TestAnAccountRuleNamesTheAccount: the subject a rule must match carries the
// account in front, so allowing one account is something a person can write.
func TestAnAccountRuleNamesTheAccount(t *testing.T) {
	opts := Options{Rules: []authz.Rule{{Host: "**", Subject: "[personal] op://Shared/**", Action: authz.ActionAllow}}}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "mine"})

	if response := h.exec(t, "--account", "personal", "read", "op://Shared/App/password"); response.Exit != 0 {
		t.Fatalf("[personal] rule did not allow --account personal: %q", response.Error)
	}
	if response := h.exec(t, "--account", "work", "read", "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Fatalf("[personal] rule allowed --account work: exit = %d", response.Exit)
	}
	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Fatalf("[personal] rule allowed the default account: exit = %d", response.Exit)
	}
}

// TestNamingAnAccountDoesNotEscapeADeny: a deny written as a bare reference is
// about the item, and an account selector must not step around it.
func TestNamingAnAccountDoesNotEscapeADeny(t *testing.T) {
	opts := Options{Rules: []authz.Rule{
		{Host: "**", Subject: "**", Action: authz.ActionAllow},
		{Host: "**", Subject: "op://Private/Root Keys/**", Action: authz.ActionDeny},
	}}
	h := start(t, opts, map[string]string{"op://Private/Root Keys/ssh": "root"})

	response := h.exec(t, "--account", "work", "read", "op://Private/Root Keys/ssh")
	if response.Exit != ExitDenied || !strings.Contains(response.Error, "denied by rule") {
		t.Fatalf("--account stepped around a deny: exit = %d, error = %q", response.Exit, response.Error)
	}
	if n := h.runner.reads(); n != 0 {
		t.Errorf("the vault was read %d times", n)
	}
}

// TestAnExplicitAccountIsNotRoutedOver: routing adds --account only when the
// request did not choose one, so op is never handed two.
func TestAnExplicitAccountIsNotRoutedOver(t *testing.T) {
	opts := allowAll()
	opts.Accounts = Accounts{ByVault: map[string]string{"Shared": "work.1password.com"}}
	h := start(t, opts, nil)

	h.exec(t, "--account", "personal", "read", "op://Shared/App/password")
	if got := h.runner.accountsUsed(); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("routing added an account on top of the request's own: %v", got)
	}
}

// TestAmbiguousAccountsAreRefused: two --account flags, or one whose value
// could reshape the subject, are refused before policy.
func TestAmbiguousAccountsAreRefused(t *testing.T) {
	h := start(t, allowAll(), nil)
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
// must honour only denies a rule or refusal made. Under `unmatched: deny` the
// bare reference has no rule and so "denies" — which must not refuse an
// explicit `[personal] op://…` allow.
func TestUnmatchedDenyDoesNotRefuseAnAccountAllow(t *testing.T) {
	opts := Options{Rules: []authz.Rule{{Host: "**", Subject: "[personal] op://Shared/**", Action: authz.ActionAllow}}}
	h := start(t, opts, map[string]string{"op://Shared/App/password": "mine"})
	h.host.config.seed(t, "unmatched", "deny")

	if response := h.exec(t, "--account", "personal", "read", "op://Shared/App/password"); response.Exit != 0 {
		t.Fatalf("unmatched: deny refused an explicitly allowed account: %q", response.Error)
	}
	if response := h.exec(t, "read", "op://Shared/App/password"); response.Exit != ExitDenied {
		t.Fatalf("unmatched: deny should still refuse the bare reference: exit = %d", response.Exit)
	}
}
