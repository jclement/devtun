// Package doctor is what `devtun doctor` reports: a list of things that were
// looked at, what was found, and — when something is wrong — what to do about
// it.
//
// It is a package rather than a printf in the command because both halves of
// the answer come from different places. The local half is about this
// workstation and lives in the command; the remote half is produced by the
// session, over the same connection a real run would use, so that what doctor
// verifies is what devtun will actually do rather than a second implementation
// that can drift from it.
//
// The governing rule is that a check earns its line. A doctor that prints forty
// green ticks is one nobody reads to the end of, and the one red line in the
// middle is the one they miss — so checks are few, named after the thing a
// person would go and fix, and every failure carries the fix with it.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jclement/devtun/internal/ui"
)

// Status is how a check came out.
type Status string

const (
	// StatusOK is working.
	StatusOK Status = "ok"
	// StatusWarn is working, but not the way you probably wanted — a service
	// that will be skipped, a shell line that is not installed yet. devtun
	// will still run.
	StatusWarn Status = "warn"
	// StatusFail is broken: this will not work until you do something.
	StatusFail Status = "fail"
	// StatusOff is a service switched off for this host. It is not a problem,
	// and saying nothing about it would leave somebody hunting for why a
	// service they configured is not running.
	StatusOff Status = "off"
)

// Check is one thing devtun looked at.
type Check struct {
	// Name is the thing, not the sentence: "1password", "helper", "PATH". It
	// is what you would go and fix, and it is what the eye scans down.
	Name string `json:"name"`
	// Status is how it came out.
	Status Status `json:"status"`
	// Detail is what was found, in one line.
	Detail string `json:"detail,omitempty"`
	// Fix is what to do about it. Present on anything that is not OK, absent
	// on everything that is — a suggestion attached to something that already
	// works is noise that makes the real ones harder to see.
	Fix string `json:"fix,omitempty"`
}

// Section is a group of checks under a heading — this machine, or one host.
type Section struct {
	Title  string  `json:"title"`
	Checks []Check `json:"checks"`
}

// OK reports a check that passed.
func (s *Section) OK(name, detail string) { s.add(Check{Name: name, Status: StatusOK, Detail: detail}) }

// Warn reports something that will not stop devtun but is probably not what
// you wanted.
func (s *Section) Warn(name, detail, fix string) {
	s.add(Check{Name: name, Status: StatusWarn, Detail: detail, Fix: fix})
}

// Fail reports something that has to be dealt with.
func (s *Section) Fail(name, detail, fix string) {
	s.add(Check{Name: name, Status: StatusFail, Detail: detail, Fix: fix})
}

// Off reports a service switched off for this host.
func (s *Section) Off(name, detail string) {
	s.add(Check{Name: name, Status: StatusOff, Detail: detail})
}

func (s *Section) add(c Check) { s.Checks = append(s.Checks, c) }

// Report is everything doctor looked at, in the order it looked.
type Report struct {
	Sections []*Section `json:"sections"`
}

// Section starts a new group and returns it for filling in.
func (r *Report) Section(title string) *Section {
	s := &Section{Title: title}
	r.Sections = append(r.Sections, s)
	return s
}

// Failed reports whether anything is actually broken, which is what the exit
// code is for. A warning is not a failure: a box without the 1Password CLI is
// an ordinary box, and exiting non-zero over it would make doctor useless in a
// script that only cares whether devtun can connect at all.
func (r *Report) Failed() bool {
	for _, section := range r.Sections {
		for _, check := range section.Checks {
			if check.Status == StatusFail {
				return true
			}
		}
	}
	return false
}

// Counts totals the checks by status, for the closing line.
func (r *Report) Counts() (ok, warn, fail int) {
	for _, section := range r.Sections {
		for _, check := range section.Checks {
			switch check.Status {
			case StatusOK:
				ok++
			case StatusWarn:
				warn++
			case StatusFail:
				fail++
			}
		}
	}
	return ok, warn, fail
}

// glyph is the mark down the left margin. Shape as well as colour, because a
// report read in a pipe, a CI log or by somebody colourblind has to say the
// same thing.
func glyph(status Status) string {
	switch status {
	case StatusOK:
		return ui.OK.Render("✓")
	case StatusWarn:
		return ui.Warn.Render("!")
	case StatusFail:
		return ui.Error.Render("✗")
	default:
		return ui.Muted.Render("·")
	}
}

const nameWidth = 12

// Render writes the report for a person to read.
func (r *Report) Render(w io.Writer) {
	for i, section := range r.Sections {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, ui.Banner.Render(section.Title))
		for _, check := range section.Checks {
			name := check.Name
			if len(name) < nameWidth {
				name += strings.Repeat(" ", nameWidth-len(name))
			}
			fmt.Fprintf(w, "  %s %s %s\n", glyph(check.Status), ui.Header.Render(name), check.Detail)
			if check.Fix != "" {
				// The fix is indented under what it is about, so a report with
				// three problems reads as three problems rather than six lines.
				for _, line := range strings.Split(check.Fix, "\n") {
					fmt.Fprintf(w, "    %s %s\n", ui.Muted.Render("→"), ui.Muted.Render(line))
				}
			}
		}
	}

	ok, warn, fail := r.Counts()
	summary := fmt.Sprintf("%d ok", ok)
	if warn > 0 {
		summary += fmt.Sprintf(" · %d to look at", warn)
	}
	if fail > 0 {
		summary += fmt.Sprintf(" · %d broken", fail)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.Muted.Render(summary))
}

// WriteJSON writes the report as one JSON object, for a script that would
// rather not read glyphs.
func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}
