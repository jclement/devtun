package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/event"
)

func ev(second int, text string) event.Event {
	return event.Event{
		Time:    testNow.Add(time.Duration(second) * time.Second),
		Service: "tunnels", Class: event.Network, Kind: "opened", Text: text,
	}
}

// The bus calls its subscribers synchronously, holding its own lock. If the
// subscriber blocked — and Program.Send does, until the program has started —
// the session that emitted the event would stall, and every other emitter
// behind the lock with it. This is that deadlock, and it must not happen.
func TestEmittingNeverBlocksOnAProgramThatIsNotRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bus := event.NewBus(10)
	// Deliberately never run: Send on it blocks forever.
	program := tea.NewProgram(nil, tea.WithContext(ctx))
	stop := forwardEvents(bus, program)
	t.Cleanup(stop)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			bus.Emit(ev(i, "opened 5173"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("emitting blocked on the interface — the whole session would be stalled")
	}
}

// The history and the subscription overlap, because the bus cannot hand out
// both under one lock. The seed must contain each event exactly once.
func TestSeedingKeepsEveryEventExactlyOnce(t *testing.T) {
	cases := []struct {
		name            string
		history, queued []event.Event
		want            []string
	}{
		{
			name:    "no overlap",
			history: []event.Event{ev(1, "a"), ev(2, "b")},
			queued:  []event.Event{ev(3, "c")},
			want:    []string{"a", "b", "c"},
		},
		{
			name:    "the queue repeats the tail of the history",
			history: []event.Event{ev(1, "a"), ev(2, "b"), ev(3, "c")},
			queued:  []event.Event{ev(2, "b"), ev(3, "c"), ev(4, "d")},
			want:    []string{"a", "b", "c", "d"},
		},
		{
			name:    "the queue is entirely in the history",
			history: []event.Event{ev(1, "a"), ev(2, "b")},
			queued:  []event.Event{ev(2, "b")},
			want:    []string{"a", "b"},
		},
		{
			// Several events can share a timestamp — one Sync opens three
			// tunnels — so the overlap cannot be found by comparing times.
			name:    "events sharing a timestamp",
			history: []event.Event{ev(1, "a"), ev(1, "b")},
			queued:  []event.Event{ev(1, "b"), ev(1, "c")},
			want:    []string{"a", "b", "c"},
		},
		{
			name:    "nothing yet",
			history: nil,
			queued:  nil,
			want:    nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seed := append(c.history, c.queued[overlap(c.history, c.queued):]...)
			var got []string
			for _, e := range seed {
				got = append(got, e.Text)
			}
			if len(got) != len(c.want) {
				t.Fatalf("seed = %v, want %v", got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("seed = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// The model has to survive the seed arriving as one message, since that is how
// a session reattached to ten minutes in starts.
func TestSeedFillsTheActivityTab(t *testing.T) {
	m := newTestModel(t, deps{tunnels: newStub()})
	m.Update(seedMsg{ev(1, "opened 3000"), ev(2, "opened 5173")})
	m.tab = tabActivity

	view := bodyLines(m)
	for _, want := range []string{"opened 3000", "opened 5173"} {
		if !strings.Contains(view, want) {
			t.Errorf("the seeded activity tab is missing %q:\n%s", want, view)
		}
	}
}
