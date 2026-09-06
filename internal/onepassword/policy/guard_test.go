package policy

import (
	"strings"
	"testing"
)

func TestGuardCheck(t *testing.T) {
	guard := NewGuard(GuardConfig{})

	tests := []struct {
		name        string
		argv        []string
		wantAllowed bool
		wantMessage string
	}{
		{name: "read is allowed", argv: []string{"read", "op://V/I/F"}, wantAllowed: true},
		{name: "item get is allowed", argv: []string{"item", "get", "Docker", "--fields", "PAT"}, wantAllowed: true},
		{name: "bare flags carry no command", argv: []string{"--version"}, wantAllowed: true},

		{name: "item delete is not on the allowlist", argv: []string{"item", "delete", "Docker"}, wantMessage: "allowlist"},
		{name: "vault create is not on the allowlist", argv: []string{"vault", "create", "New"}, wantMessage: "allowlist"},

		{name: "out-file would write locally", argv: []string{"read", "op://V/I/F", "--out-file", "/tmp/x"}, wantMessage: "not allowed through the proxy"},
		{name: "out-file with an equals sign", argv: []string{"read", "op://V/I/F", "--out-file=/tmp/x"}, wantMessage: "not allowed through the proxy"},
		{name: "short out-file", argv: []string{"read", "op://V/I/F", "-o", "/tmp/x"}, wantMessage: "not allowed through the proxy"},
		{name: "session override", argv: []string{"read", "op://V/I/F", "--session", "abc"}, wantMessage: "not allowed through the proxy"},

		{name: "run is handled by the shim", argv: []string{"run", "--", "echo"}, wantMessage: "not proxied"},
		{name: "inject is handled by the shim", argv: []string{"inject", "-i", "t"}, wantMessage: "not proxied"},
		{name: "signin belongs on the proxy machine", argv: []string{"signin"}, wantMessage: "not proxied"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := guard.Check(test.argv)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("Check(%v) = %v, want nil", test.argv, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Check(%v) = nil, want an error", test.argv)
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Errorf("Check(%v) = %q, want it to mention %q", test.argv, err, test.wantMessage)
			}
		})
	}
}

func TestGuardHonoursExtraAllowedCommands(t *testing.T) {
	guard := NewGuard(GuardConfig{AllowCommands: []string{"item create"}})
	if err := guard.Check([]string{"item", "create", "login"}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := guard.Check([]string{"item", "delete", "login"}); err == nil {
		t.Error("allowing `item create` must not allow `item delete`")
	}
}

// The escape hatch has to open every command, because that is what it is for —
// but it must not open the local-state flags, which are about *where* the
// command acts rather than what it does.
func TestAllowAllCommandsStillBlocksLocalStateFlags(t *testing.T) {
	guard := NewGuard(GuardConfig{AllowAllCommands: true})
	if err := guard.Check([]string{"item", "delete", "Docker"}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := guard.Check([]string{"read", "op://V/I/F", "--out-file", "/tmp/x"}); err == nil {
		t.Error("--out-file must stay blocked even with allow_all_commands")
	}
}

// A global flag before the subcommand must not hide the subcommand.
//
// This is a regression test for the worst defect this project has had: the
// guard stopped scanning at the first dash, produced an empty command path, and
// treated that as "nothing to authorise". Every read-only restriction could be
// stepped around by prefixing any option, and `op --account x run -- sh -c …`
// reached the workstation's shell.
func TestGlobalFlagsDoNotHideTheCommand(t *testing.T) {
	guard := NewGuard(GuardConfig{})

	mustRefuse := [][]string{
		{"--account", "work", "item", "delete", "X"},
		{"--account=work", "item", "delete", "X"},
		{"--account", "work", "run", "--", "sh", "-c", "touch /tmp/pwned"},
		{"--format", "json", "vault", "create", "X"},
		{"--no-color", "item", "delete", "X"},
		{"--debug", "--account", "work", "item", "delete", "X"},
	}
	for _, argv := range mustRefuse {
		if err := guard.Check(argv); err == nil {
			t.Errorf("op %v was allowed through the guard", argv)
		}
	}

	// The same prefixes must not break a command that is genuinely allowed.
	mustAllow := [][]string{
		{"--account", "work", "read", "op://V/I/F"},
		{"--account=work", "read", "op://V/I/F"},
		{"--no-color", "item", "get", "X"},
		{"--version"},
		{"--help"},
	}
	for _, argv := range mustAllow {
		if err := guard.Check(argv); err != nil {
			t.Errorf("op %v should be allowed, got %v", argv, err)
		}
	}
}

// An option we do not recognise could consume the next argument or not, and
// guessing either way fails open. Refusing costs a line in the table when `op`
// grows a flag; guessing costs the allowlist its meaning.
func TestUnknownGlobalFlagIsRefused(t *testing.T) {
	guard := NewGuard(GuardConfig{})

	err := guard.Check([]string{"--brand-new-flag", "value", "read", "op://V/I/F"})

	if err == nil {
		t.Fatal("an unrecognised global option must not be parsed past")
	}
	if !strings.Contains(err.Error(), "--brand-new-flag") {
		t.Errorf("the refusal should name the option, got %v", err)
	}
}
