// Package render turns the event stream into something to read.
//
// Two renderers, and the difference between them is who is reading. The log is
// for a human watching a window in the corner of a screen: colour, alignment,
// and — the point of the whole exercise — a treatment that separates a secret
// leaving your vault from a port being forwarded, at a glance, without reading
// the words. NDJSON is for a pipe, and says everything the log does plus the
// fields the log leaves out.
//
// Neither knows anything about services. They key off event.Class, which is why
// a fourth service gets the right presentation for free.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/ui"
)

// Renderer consumes events.
type Renderer interface {
	Event(event.Event)
}

// Log writes a coloured line per event.
type Log struct {
	mu  sync.Mutex
	out io.Writer
	// verbose includes Diagnostic events, which are otherwise dropped: they
	// exist for when something is being investigated, and a log that shows
	// everything is a log nobody reads.
	verbose bool
}

// NewLog builds a log renderer.
func NewLog(out io.Writer, verbose bool) *Log {
	return &Log{out: out, verbose: verbose}
}

// Event renders one line.
//
// The shape is fixed: time, class glyph, service, then the sentence. Fixed
// columns are what make a log skimmable — a wandering left margin means reading
// every line to find the one that matters.
func (l *Log) Event(e event.Event) {
	if e.Class == event.Diagnostic && !l.verbose {
		return
	}

	style := ui.ClassStyle(e.Class)
	line := fmt.Sprintf("%s %s %s  %s",
		ui.Muted.Render(e.Time.Format("15:04:05")),
		// Padded to a fixed two cells using the width we declare rather than one
		// measured: 🔒 is two cells and ⇄ is one, and a log whose left margin
		// wanders is a log you have to read rather than skim.
		ui.ClassGlyph(e.Class)+strings.Repeat(" ", 2-ui.GlyphCells(e.Class)),
		style.Render(pad(short(e.Service), 9)),
		ui.LevelStyle(e.Level).Render(e.Text),
	)
	// The structured fields are for NDJSON. Repeating them after a sentence
	// that already says the same thing — `remote 8080 → 127.0.0.1:8080` then
	// `remote=8080 local=8080 endpoint=127.0.0.1:8080` — is the tell of a log
	// written for a machine and read by a person. Verbose still shows them.
	if l.verbose {
		if fields := renderFields(e.Fields); fields != "" {
			line += "  " + ui.Muted.Render(fields)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	// A log line that cannot be written is not worth failing a session over —
	// and there is nowhere to report it to but the writer that just failed.
	_, _ = fmt.Fprintln(l.out, line)
}

// short abbreviates service ids to keep the column narrow. The names are ours,
// so this is a lookup rather than a truncation, and an unknown service keeps
// its full name rather than being silently mangled.
func short(service string) string {
	switch service {
	case "1password":
		return "op"
	case "tunnels":
		return "tun"
	case "browser":
		return "web"
	case "session":
		return "ssh"
	default:
		return service
	}
}

func pad(s string, width int) string {
	for lipgloss.Width(s) < width {
		s += " "
	}
	return s
}

// renderFields formats key/value pairs in logfmt style. An odd trailing key is
// dropped rather than paired with nothing.
func renderFields(fields []any) string {
	out := ""
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf("%s=%v", key, fields[i+1])
	}
	return out
}

// JSON writes one object per line, for scripts.
type JSON struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewJSON builds an NDJSON renderer.
func NewJSON(out io.Writer) *JSON {
	return &JSON{encoder: json.NewEncoder(out)}
}

// jsonEvent is the wire shape. Fields are flattened into a map so a consumer
// can reach them by name rather than by position, and Class and Level are
// spelled out rather than numbered.
type jsonEvent struct {
	Time    time.Time      `json:"time"`
	Service string         `json:"service"`
	Kind    string         `json:"kind"`
	Class   string         `json:"class"`
	Level   string         `json:"level"`
	Text    string         `json:"text"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// Event writes one JSON object.
//
// Everything is emitted, Diagnostic included: a pipe can filter, and a script
// that wanted the detail has no way to ask for it after the fact.
func (j *JSON) Event(e event.Event) {
	out := jsonEvent{
		Time: e.Time, Service: e.Service, Kind: e.Kind,
		Class: string(e.Class), Level: e.Level.String(), Text: e.Text,
	}
	if len(e.Fields) > 1 {
		out.Fields = make(map[string]any, len(e.Fields)/2)
		for i := 0; i+1 < len(e.Fields); i += 2 {
			if key, ok := e.Fields[i].(string); ok {
				out.Fields[key] = e.Fields[i+1]
			}
		}
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.encoder.Encode(out)
}

// Discard renders nothing, for when the TUI owns the screen.
type Discard struct{}

// Event does nothing.
func (Discard) Event(event.Event) {}
