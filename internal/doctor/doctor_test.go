package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sample() *Report {
	r := &Report{}
	here := r.Section("this machine")
	here.OK("devtun", "devtun v1.0.0")
	here.Warn("1password", "no `op` on this machine", "brew install 1password-cli")
	there := r.Section("bedev")
	there.Fail("ssh", "cannot connect", "check `ssh bedev` works first")
	there.Off("browser", "switched off for bedev")
	return r
}

// Only a failure is a failure. A box without the 1Password CLI is an ordinary
// box, and exiting non-zero over it would make doctor useless in the script
// that only wants to know whether devtun can connect at all.
func TestFailedIsOnlyAboutFailures(t *testing.T) {
	if sample().Failed() != true {
		t.Error("a report with a failing check did not report a failure")
	}

	r := &Report{}
	s := r.Section("this machine")
	s.OK("devtun", "fine")
	s.Warn("1password", "missing", "install it")
	s.Off("browser", "off")
	if r.Failed() {
		t.Error("warnings and switched-off services must not fail the run")
	}
}

func TestCounts(t *testing.T) {
	ok, warn, fail := sample().Counts()
	if ok != 1 || warn != 1 || fail != 1 {
		t.Errorf("counts = %d/%d/%d, want 1/1/1", ok, warn, fail)
	}
}

// Every part of a check has to reach the page: the name people would go and
// fix, what was found, and — for anything that is not OK — what to do.
func TestRenderShowsNameDetailAndFix(t *testing.T) {
	var buf bytes.Buffer
	sample().Render(&buf)
	out := buf.String()

	for _, want := range []string{
		"this machine", "bedev",
		"devtun", "devtun v1.0.0",
		"1password", "no `op` on this machine", "brew install 1password-cli",
		"ssh", "cannot connect", "check `ssh bedev` works first",
		"1 ok", "1 to look at", "1 broken",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
}

// Shape as well as colour: a report read in a pipe, in a CI log, or by somebody
// colourblind has to say the same thing.
func TestRenderMarksStatusWithoutRelyingOnColour(t *testing.T) {
	var buf bytes.Buffer
	sample().Render(&buf)
	out := buf.String()

	for _, want := range []string{"✓", "!", "✗"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in the report:\n%s", want, out)
		}
	}
}

// A fix that a person has to act on is worth several lines; each of them has to
// stay under the check it belongs to rather than becoming another finding.
func TestRenderIndentsAMultiLineFix(t *testing.T) {
	r := &Report{}
	r.Section("bedev").Warn("shell setup", "2 lines missing", "add to ~/.bashrc:\nexport PATH=x\nexport SSH_AUTH_SOCK=y")

	var buf bytes.Buffer
	r.Render(&buf)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "export PATH=x") && !strings.HasPrefix(line, "    ") {
			t.Errorf("a fix line is not indented under its check: %q", line)
		}
	}
}

func TestJSONCarriesEverything(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, buf.String())
	}
	if len(back.Sections) != 2 || back.Sections[1].Title != "bedev" {
		t.Fatalf("sections did not survive: %+v", back.Sections)
	}
	if got := back.Sections[1].Checks[0]; got.Status != StatusFail || got.Fix == "" {
		t.Errorf("the failing check lost something: %+v", got)
	}
	// An OK check carries no fix, because a suggestion attached to something
	// that already works is noise in the middle of the ones that matter.
	if back.Sections[0].Checks[0].Fix != "" {
		t.Error("an OK check carries a fix")
	}
}
