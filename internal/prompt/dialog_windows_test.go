//go:build windows

package prompt

import (
	"strings"
	"testing"
)

// A host or vault name is attacker-influenced text that ends up inside a
// PowerShell literal. Single quotes are the only thing that can close one, and
// doubling them is how PowerShell escapes them.
func TestPowershellStringQuotesUntrustedText(t *testing.T) {
	tests := map[string]string{
		"plain":                 "'plain'",
		"it's":                  "'it''s'",
		"'; Start-Process cmd;": "'''; Start-Process cmd;'",
	}
	for input, want := range tests {
		if got := powershellString(input); got != want {
			t.Errorf("powershellString(%q) = %s, want %s", input, got, want)
		}
	}
}

// The script has to end with a value on stdout in both directions, or a
// cancelled dialog is indistinguishable from a crashed one.
func TestFormScriptAlwaysPrintsAnAnswer(t *testing.T) {
	script := buildFormScript("devtun", "bedev is asking for:", []string{"Yes, once", "Yes, always"})
	for _, want := range []string{denySentinel, "ShowDialog", "'Yes, once'", "'Yes, always'", "TopMost"} {
		if !strings.Contains(script, want) {
			t.Errorf("the script is missing %q:\n%s", want, script)
		}
	}
	if !strings.Contains(script, "$b.SelectedIndex=0") {
		t.Error("the cursor does not start on the narrowest answer")
	}
}

// An injected quote must not be able to break out of the label list and become
// another statement.
func TestFormScriptContainsInjectedLabels(t *testing.T) {
	script := buildFormScript("devtun", "x", []string{"'; Start-Process calc; '"})
	if strings.Contains(script, "@('; Start-Process calc; ')") {
		t.Fatalf("a label escaped its literal:\n%s", script)
	}
}
