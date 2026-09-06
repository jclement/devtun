package tui

import (
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/event"
)

// seedMsg carries the events that happened before the interface opened.
type seedMsg []event.Event

// forwarder queues events for the program.
//
// It exists because of one line in the bus's contract: subscribers are called
// synchronously, with the bus's own lock held, and must not block. Program.Send
// blocks — until the program has started, and whenever the message channel is
// busy — so calling it from a subscriber would stall the service that emitted
// the event and, with the lock still held, every other emitter behind it.
//
// The queue is unbounded rather than a fixed buffer, deliberately. The
// alternative to growing is dropping, and a burst of events is exactly the
// shape a security log has when something interesting is happening. It drains
// as fast as the program can take messages, which is far faster than a session
// can produce them.
type forwarder struct {
	mu     sync.Mutex
	queue  []event.Event
	closed bool
	wake   chan struct{}
}

func newForwarder() *forwarder {
	return &forwarder{wake: make(chan struct{}, 1)}
}

// push appends an event and nudges the pump. It never blocks.
func (f *forwarder) push(e event.Event) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.queue = append(f.queue, e)
	f.mu.Unlock()

	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// take empties the queue.
func (f *forwarder) take() []event.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.queue
	f.queue = nil
	return out
}

func (f *forwarder) close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *forwarder) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// forwardEvents seeds the interface with the bus's history and then keeps it
// fed, returning a function that unsubscribes and stops the pump.
func forwardEvents(bus *event.Bus, program *tea.Program) (stop func()) {
	if bus == nil {
		return func() {}
	}

	f := newForwarder()
	cancel := bus.Subscribe(f.push)

	// Subscribe first, then read the history: the other order loses anything
	// emitted in between, and this one only duplicates it — which is
	// recoverable, since a duplicate is exactly a suffix of the history and a
	// prefix of what the subscription has caught. Doing both under one lock is
	// not an option: the bus calls its subscribers while holding it, so asking
	// it for the history from inside one would deadlock.
	history := bus.History()
	queued := f.take()
	seed := append(history, queued[overlap(history, queued):]...)

	go func() {
		defer restoreOnPanic(program)
		if len(seed) > 0 {
			program.Send(seedMsg(seed))
		}
		for range f.wake {
			for _, e := range f.take() {
				program.Send(eventMsg(e))
			}
			if f.isClosed() {
				return
			}
		}
	}()

	return func() {
		cancel()
		f.close()
	}
}

// overlap returns how many of the queued events the history already carries.
//
// Both are in emission order, and the events the subscription caught while the
// history was being copied are the newest ones in it — so the longest suffix of
// history that equals a prefix of queue is the duplicate set.
func overlap(history, queued []event.Event) int {
	for k := min(len(history), len(queued)); k > 0; k-- {
		if sameEvents(history[len(history)-k:], queued[:k]) {
			return k
		}
	}
	return 0
}

func sameEvents(a, b []event.Event) bool {
	for i := range a {
		if !sameEvent(a[i], b[i]) {
			return false
		}
	}
	return true
}

// sameEvent compares the identifying fields. Fields is left out: it is a []any
// and so not comparable, and two events agreeing on time, source, kind and
// sentence are the same event.
func sameEvent(a, b event.Event) bool {
	return a.Time.Equal(b.Time) && a.Service == b.Service &&
		a.Kind == b.Kind && a.Text == b.Text
}
