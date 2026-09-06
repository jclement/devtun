package prompt

import (
	"strings"
	"testing"
	"time"
)

func TestApplescriptStringEscapes(t *testing.T) {
	tests := map[string]string{
		`plain`:      `"plain"`,
		`say "hi"`:   `"say \"hi\""`,
		`back\slash`: `"back\\slash"`,
	}
	for input, want := range tests {
		if got := applescriptString(input); got != want {
			t.Errorf("applescriptString(%q) = %s, want %s", input, got, want)
		}
	}
}

// A host or vault name is attacker-influenced text that ends up inside an
// AppleScript literal, so it must not be able to close the quote and add
// statements of its own.
func TestChooserScriptQuotesUntrustedText(t *testing.T) {
	script := buildChooserScript("devtun", `evil" & (do shell script "id") & "`, []string{"Allow once"})
	if strings.Contains(script, `& (do shell script`) && !strings.Contains(script, `\" &`) {
		t.Fatalf("prompt text escaped its literal:\n%s", script)
	}
	if !strings.Contains(script, denySentinel) {
		t.Error("the script must return the deny sentinel when cancelled")
	}
}

// The dialog offers the shared menu minus Deny, which it expresses as its
// cancel button. Asserting on the relationship rather than on fixed positions
// keeps this honest when the menu grows.
func TestDialogOptionsMatchTheTerminalMenu(t *testing.T) {
	request := Request{Host: "devbox", Subject: "op://V/I/F", TTL: 5 * time.Minute}
	labels, choices := dialogOptions(request)

	if len(labels) != len(choices) {
		t.Fatalf("%d labels for %d choices", len(labels), len(choices))
	}
	menu := MenuFor(request)
	if len(labels) != len(menu)-1 {
		t.Fatalf("dialog offers %d options, want the %d in the menu minus Deny", len(labels), len(menu))
	}
	for i, item := range menu[:len(menu)-1] {
		if labels[i] != item.Label || choices[i] != item.Choice {
			t.Errorf("option %d = %q/%v, want %q/%v", i, labels[i], choices[i], item.Label, item.Choice)
		}
	}
	for _, choice := range choices {
		if choice == ChoiceDeny {
			t.Error("Deny must not be an option; the cancel button is the refusal")
		}
	}

	joined := strings.Join(labels, "\n")
	for _, want := range []string{"5m0s", "devbox", "this session"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no option mentions %q:\n%s", want, joined)
		}
	}
}
