// Package event is devtun's activity bus.
//
// Everything a session does — a tunnel opening, a secret being approved, an
// SSH connection dropping — becomes an Event here, and every renderer (the
// coloured log, NDJSON, the TUI's activity tab) is a subscriber. Services never
// write to a terminal; they emit.
//
// The field that earns the package its existence is Class. A secret leaving the
// vault and a port being forwarded are not the same kind of news, and the whole
// point of putting them in one window is that you can still tell them apart at
// a glance. Class is what every renderer keys its treatment off, so that
// distinction is made once, here, rather than in each of them.
package event

import (
	"sync"
	"time"
)

// Class is the kind of news an event carries. It drives colour, glyph and
// filtering everywhere an event is displayed.
type Class string

const (
	// Security is vault access and authorisation: a secret requested, granted,
	// denied, cached, or a rule applied. These are the events that are worth
	// reading every one of, and they are styled to be impossible to skim past.
	Security Class = "security"
	// Network is traffic plumbing: tunnels opening and closing, ports being
	// remapped, URLs routed to a browser.
	Network Class = "network"
	// Lifecycle is the session itself: connecting, reconnecting, shim uploads,
	// services starting and stopping.
	Lifecycle Class = "lifecycle"
	// Diagnostic is detail wanted only when something is being investigated.
	Diagnostic Class = "diagnostic"
)

// Level is severity, orthogonal to Class: a denied secret is Security/Info
// because denying is the system working, not failing.
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

// String renders the level for structured output.
func (l Level) String() string {
	switch l {
	case Debug:
		return "debug"
	case Warn:
		return "warn"
	case Error:
		return "error"
	default:
		return "info"
	}
}

// Event is one thing that happened.
type Event struct {
	Time time.Time `json:"time"`
	// Service is the emitter's id — "tunnels", "1password", "browser" — or
	// "session" for the supervisor itself.
	Service string `json:"service"`
	// Kind is a stable machine-readable verb: "opened", "closed", "allowed",
	// "denied". Scripts match on this; humans read Text.
	Kind  string `json:"kind"`
	Class Class  `json:"class"`
	Level Level  `json:"level"`
	// Text is the human sentence, already complete on its own.
	Text string `json:"text"`
	// Fields are logfmt-style key/value pairs, flattened into JSON output.
	// Alternating key, value; keys must be strings.
	Fields []any `json:"-"`
}

// Sink is what a service is handed to report activity. It is deliberately the
// narrowest possible interface so a service can be tested with a slice.
type Sink interface {
	Emit(Event)
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(Event)

// Emit calls f.
func (f SinkFunc) Emit(e Event) { f(e) }

// Discard drops everything. Useful in tests and in the shim, which has no
// business logging anywhere.
var Discard Sink = SinkFunc(func(Event) {})

// Bus fans events out to subscribers and keeps a bounded history so a renderer
// attaching late — the TUI's activity tab, opened for the first time ten
// minutes in — still has something to show.
type Bus struct {
	mu   sync.Mutex
	subs map[int]func(Event)
	// order keeps subscribers in registration order, so delivery is
	// deterministic rather than following map iteration.
	order   []int
	nextID  int
	history []Event
	limit   int
	now     func() time.Time

	// deliver serialises the callbacks themselves, without the state lock.
	deliver sync.Mutex
}

// NewBus returns a bus retaining the last limit events. A limit of zero keeps
// no history.
func NewBus(limit int) *Bus {
	return &Bus{subs: make(map[int]func(Event)), limit: limit, now: time.Now}
}

// Emit timestamps the event if it has no time of its own, records it, and
// delivers it to every subscriber.
//
// Subscribers are called synchronously so events can never be delivered out of
// order, which matters when the order is a security record. They are NOT called
// with the lock held, and that distinction is the whole of this comment.
//
// It used to hold the lock across delivery, on the reasoning that every
// subscriber is non-blocking. That reasoning was wrong: the log and NDJSON
// renderers write straight to the writer they were given, and
// `devtun --json | consumer` with a stopped consumer fills the pipe and blocks
// in Write. With the lock held, that froze every producer in the process —
// every service, every approval, the reconnect loop — on a stalled pipe at the
// far end of a shell pipeline. A renderer that blocks should stall the log, not
// the session.
//
// Ordering is preserved by a delivery mutex held only during the callbacks, so
// two emitters cannot interleave, while the state lock is released first.
func (b *Bus) Emit(e Event) {
	subs, e := b.record(e)

	// Serialises delivery without holding the state lock, so a slow subscriber
	// delays other emitters but never blocks History, Subscribe or Emit's own
	// bookkeeping.
	b.deliver.Lock()
	defer b.deliver.Unlock()
	for _, fn := range subs {
		fn(e)
	}
}

// record stamps and stores the event, returning the subscribers to deliver to.
func (b *Bus) record(e Event) ([]func(Event), Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = b.now()
	}
	if b.limit > 0 {
		b.history = append(b.history, e)
		if len(b.history) > b.limit {
			// Copy down rather than reslicing, so the backing array does not
			// grow without bound over a long session.
			copy(b.history, b.history[len(b.history)-b.limit:])
			b.history = b.history[:b.limit]
		}
	}
	subs := make([]func(Event), 0, len(b.subs))
	for _, id := range b.order {
		if fn, ok := b.subs[id]; ok {
			subs = append(subs, fn)
		}
	}
	return subs, e
}

// Subscribe registers fn and returns a function that unregisters it.
//
// fn must not call back into the bus — that would deadlock on the delivery
// mutex. It may block: a slow subscriber holds up other emitters but no longer
// freezes the process, which is what a renderer writing into a stalled pipe
// actually does.
func (b *Bus) Subscribe(fn func(Event)) (cancel func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := b.nextID
	b.nextID++
	b.subs[id] = fn
	b.order = append(b.order, id)

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.subs, id)
		for i, other := range b.order {
			if other == id {
				b.order = append(b.order[:i], b.order[i+1:]...)
				break
			}
		}
	}
}

// History returns a copy of the retained events, oldest first.
func (b *Bus) History() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.history))
	copy(out, b.history)
	return out
}

// For returns a Sink that stamps every event with the given service id, so a
// service cannot accidentally attribute its events to another.
func (b *Bus) For(service string) Sink {
	return SinkFunc(func(e Event) {
		e.Service = service
		b.Emit(e)
	})
}
