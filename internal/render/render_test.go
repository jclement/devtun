package render

import (
	"bytes"

	"charm.land/lipgloss/v2"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/ui"
)

func init() { ui.NoColor() }

func sample() event.Event {
	return event.Event{
		Time:    time.Date(2026, 9, 6, 14, 22, 1, 0, time.UTC),
		Service: "1password", Kind: "allowed", Class: event.Security, Level: event.Info,
		Text:   "op://Personal/Docker/PAT allowed for 5m",
		Fields: []any{"caller", "deploy.sh"},
	}
}

func TestLogLineCarriesTimeServiceAndText(t *testing.T) {
	var buf bytes.Buffer
	NewLog(&buf, false).Event(sample())

	line := buf.String()
	for _, want := range []string{"14:22:01", "op", "op://Personal/Docker/PAT"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line missing %q:\n%s", want, line)
		}
	}
	// The structured fields belong to NDJSON. Repeating them after a sentence
	// that already says the same thing is what makes a log read as machine
	// output, so the human log leaves them out unless asked.
	if strings.Contains(line, "caller=deploy.sh") {
		t.Errorf("the quiet log should not carry the logfmt tail:\n%s", line)
	}

	var loud bytes.Buffer
	NewLog(&loud, true).Event(sample())
	if !strings.Contains(loud.String(), "caller=deploy.sh") {
		t.Errorf("verbose should carry the fields:\n%s", loud.String())
	}
}

// Every secret line must start its text in the same column as every tunnel
// line. This only holds if the glyph column
// is padded by the width we declare rather than the one a width table guesses.
func TestGlyphColumnIsFixedAcrossClasses(t *testing.T) {
	var buf bytes.Buffer
	log := NewLog(&buf, false)
	for _, c := range []event.Class{event.Security, event.Network, event.Lifecycle} {
		log.Event(event.Event{Time: time.Now(), Service: "x", Class: c, Text: "MARK"})
	}

	var cells []int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		before, _, _ := strings.Cut(line, "MARK")
		cells = append(cells, lipgloss.Width(before))
	}
	for i, got := range cells {
		if got != cells[0] {
			t.Errorf("line %d starts its text %d cells in, want %d — the glyph column wanders",
				i, got, cells[0])
		}
	}
}

// A log that shows everything is a log nobody reads.
func TestDiagnosticsAreHiddenUnlessVerbose(t *testing.T) {
	e := event.Event{Time: time.Now(), Class: event.Diagnostic, Text: "shim is current"}

	var quiet bytes.Buffer
	NewLog(&quiet, false).Event(e)
	if quiet.Len() != 0 {
		t.Errorf("diagnostics should be dropped by default, got %q", quiet.String())
	}

	var loud bytes.Buffer
	NewLog(&loud, true).Event(e)
	if !strings.Contains(loud.String(), "shim is current") {
		t.Error("verbose should include diagnostics")
	}
}

// Fixed columns are what make a log skimmable, so the service column must not
// wander with the length of the name.
func TestServiceColumnIsFixedWidth(t *testing.T) {
	var buf bytes.Buffer
	log := NewLog(&buf, false)
	for _, svc := range []string{"1password", "tunnels", "browser", "session"} {
		log.Event(event.Event{Time: time.Now(), Service: svc, Text: "x"})
	}

	var starts []int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		starts = append(starts, strings.LastIndex(line, "x"))
	}
	for i, at := range starts {
		if at != starts[0] {
			t.Errorf("line %d starts its text at column %d, want %d — the column wanders", i, at, starts[0])
		}
	}
}

// Security and Network must not render identically, or the entire argument for
// putting them in one window collapses.
func TestSecurityAndNetworkAreVisuallyDistinct(t *testing.T) {
	glyphs := map[event.Class]string{}
	for _, c := range []event.Class{event.Security, event.Network, event.Lifecycle} {
		glyphs[c] = ui.ClassGlyph(c)
	}
	if glyphs[event.Security] == glyphs[event.Network] {
		t.Error("security and network events share a glyph")
	}
	if glyphs[event.Security] == glyphs[event.Lifecycle] {
		t.Error("security and lifecycle events share a glyph")
	}
}

func TestJSONIsOneObjectPerLineWithNamedFields(t *testing.T) {
	var buf bytes.Buffer
	NewJSON(&buf).Event(sample())

	var got jsonEvent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Service != "1password" || got.Kind != "allowed" {
		t.Errorf("wrong identity: %+v", got)
	}
	if got.Class != "security" || got.Level != "info" {
		t.Errorf("class and level should be spelled out, got %q/%q", got.Class, got.Level)
	}
	if got.Fields["caller"] != "deploy.sh" {
		t.Errorf("fields should be reachable by name, got %v", got.Fields)
	}
	if strings.Count(strings.TrimSpace(buf.String()), "\n") != 0 {
		t.Error("one object per line")
	}
}

// A pipe can filter; a script that wanted the detail cannot ask for it later.
func TestJSONEmitsDiagnostics(t *testing.T) {
	var buf bytes.Buffer
	NewJSON(&buf).Event(event.Event{Time: time.Now(), Class: event.Diagnostic, Text: "detail"})
	if buf.Len() == 0 {
		t.Error("NDJSON should carry diagnostics")
	}
}

func TestOddTrailingFieldIsDropped(t *testing.T) {
	var buf bytes.Buffer
	NewJSON(&buf).Event(event.Event{Time: time.Now(), Fields: []any{"a", 1, "dangling"}})

	var got jsonEvent
	_ = json.Unmarshal(buf.Bytes(), &got)
	if _, ok := got.Fields["dangling"]; ok {
		t.Error("a key with no value should be dropped, not paired with nothing")
	}
	if got.Fields["a"] != float64(1) {
		t.Errorf("the complete pair should survive, got %v", got.Fields)
	}
}

// Events arrive from every service's goroutine at once.
func TestRenderersAreConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	log, js := NewLog(&buf, true), NewJSON(&bytes.Buffer{})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Event(sample())
			js.Event(sample())
		}()
	}
	wg.Wait()

	if got := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1; got != 50 {
		t.Errorf("want 50 interleaved lines, got %d", got)
	}
}
