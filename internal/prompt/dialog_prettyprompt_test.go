//go:build darwin

package prompt

import "testing"

// Every way prettyprompt can end, and what devtun makes of it.
//
// The three that are not an answer must all become a refusal rather than an
// error: a cancel is a person saying no, a timeout is devtun's own deadline
// arriving, and an empty line is a cancel that did not manage to say so. None
// of them is a reason to go and ask somewhere else, and none of them is an
// approval.
func TestWhatPrettyPromptCanSay(t *testing.T) {
	for _, c := range []struct {
		name   string
		output string
		want   string
		fails  bool
	}{
		{"an answer", `{"status":"ok","value":"Yes, once"}`, "Yes, once", false},
		{"escape", `{"status":"cancelled"}`, denySentinel, false},
		{"our deadline", `{"status":"timeout"}`, denySentinel, false},
		{"nothing at all", "", denySentinel, false},
		{"trailing newline", "{\"status\":\"ok\",\"value\":\"No\"}\n", "No", false},
		// Not JSON at all, and a status nothing knows, are the two cases where
		// devtun genuinely does not know what happened. Refusing on the
		// strength of a message it cannot read would be inventing an answer.
		{"not json", "Segmentation fault", "", true},
		{"a status from the future", `{"status":"deferred"}`, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := parsePrettyPrompt(c.output)
			if c.fails {
				if err == nil {
					t.Fatalf("%q was read as the answer %q", c.output, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: %v", c.output, err)
			}
			if got != c.want {
				t.Errorf("%q gave %q, want %q", c.output, got, c.want)
			}
		})
	}
}

// The panel is named after what is being asked for, and the icon follows it.
func TestThePrettyPromptIconMatchesTheQuestion(t *testing.T) {
	for title, want := range map[string]string{
		"bedev wants to sign":  "key.fill",
		"a key on bedev":       "key.fill",
		"bedev wants to open":  "globe",
		"bedev wants a secret": "lock.fill",
	} {
		if got := prettyPromptIcon(title); got != want {
			t.Errorf("%q got %q, want %q", title, got, want)
		}
	}
}

// It leads on a Mac that has it, because the difference between the two is
// whether the person actually reads the question — and osascript is still
// there for every Mac that does not.
func TestPrettyPromptLeadsAndOsascriptRemains(t *testing.T) {
	all := choosers()
	if len(all) < 2 {
		t.Fatalf("only %d choosers on darwin", len(all))
	}
	if all[0].name() != prettyPromptName {
		t.Errorf("the first chooser is %q, want prettyprompt", all[0].name())
	}
	var haveOsascript bool
	for _, c := range all {
		if c.name() == "osascript" {
			haveOsascript = true
		}
	}
	if !haveOsascript {
		t.Error("osascript is gone, so a Mac without prettyprompt has no dialog at all")
	}
}
