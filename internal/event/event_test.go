package event

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBusDeliversInOrderAndStampsTime(t *testing.T) {
	bus := NewBus(10)
	var got []Event
	bus.Subscribe(func(e Event) { got = append(got, e) })

	bus.Emit(Event{Kind: "first", Class: Security})
	bus.Emit(Event{Kind: "second", Class: Network})

	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].Kind != "first" || got[1].Kind != "second" {
		t.Fatalf("events out of order: %q then %q", got[0].Kind, got[1].Kind)
	}
	if got[0].Time.IsZero() {
		t.Error("emit should stamp a time when the event has none")
	}
}

func TestBusKeepsSuppliedTime(t *testing.T) {
	bus := NewBus(1)
	when := time.Date(2026, 9, 6, 14, 22, 0, 0, time.UTC)
	var got Event
	bus.Subscribe(func(e Event) { got = e })

	bus.Emit(Event{Kind: "k", Time: when})

	if !got.Time.Equal(when) {
		t.Errorf("want the supplied time %v, got %v", when, got.Time)
	}
}

// The history is what a renderer attaching late sees, so it must be bounded
// and must keep the newest events rather than the oldest.
func TestHistoryIsBoundedAndKeepsNewest(t *testing.T) {
	bus := NewBus(3)
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		bus.Emit(Event{Kind: k})
	}

	history := bus.History()
	if len(history) != 3 {
		t.Fatalf("want 3 retained events, got %d", len(history))
	}
	for i, want := range []string{"c", "d", "e"} {
		if history[i].Kind != want {
			t.Errorf("history[%d]: want %q, got %q", i, want, history[i].Kind)
		}
	}
}

func TestZeroLimitKeepsNoHistory(t *testing.T) {
	bus := NewBus(0)
	bus.Emit(Event{Kind: "a"})
	if len(bus.History()) != 0 {
		t.Error("a zero limit should retain nothing")
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	bus := NewBus(0)
	count := 0
	cancel := bus.Subscribe(func(Event) { count++ })

	bus.Emit(Event{Kind: "a"})
	cancel()
	bus.Emit(Event{Kind: "b"})

	if count != 1 {
		t.Errorf("want 1 delivery after unsubscribing, got %d", count)
	}
}

// A service must not be able to attribute its events to another one, because
// the log is a record of who did what.
func TestForStampsTheServiceID(t *testing.T) {
	bus := NewBus(1)
	var got Event
	bus.Subscribe(func(e Event) { got = e })

	bus.For("1password").Emit(Event{Kind: "allowed", Service: "tunnels"})

	if got.Service != "1password" {
		t.Errorf("want the sink's service id to win, got %q", got.Service)
	}
}

// A renderer that blocks should stall the log, not the session.
//
// The bus used to deliver with its state lock held, on the reasoning that every
// subscriber is non-blocking. The renderers write straight to the writer they
// were given, so `devtun --json | consumer` with a stopped consumer fills the
// pipe and blocks in Write — and with the lock held that froze every service,
// every approval and the reconnect loop on a stalled pipe at the far end of a
// shell pipeline.
func TestASlowSubscriberDoesNotFreezeTheBus(t *testing.T) {
	bus := NewBus(8)

	release := make(chan struct{})
	blocked := make(chan struct{})
	bus.Subscribe(func(Event) {
		close(blocked)
		<-release
	})

	go bus.Emit(Event{Kind: "first"})
	<-blocked // the subscriber is now stuck inside delivery

	// Everything that touches bus state must still work while it is stuck.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = bus.History()
		cancel := bus.Subscribe(func(Event) {})
		cancel()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("a blocked subscriber froze the rest of the bus")
	}
	close(release)
}

// Delivery order is what makes the log a record rather than a pile, so it must
// not follow map iteration.
func TestSubscribersAreCalledInRegistrationOrder(t *testing.T) {
	bus := NewBus(0)

	var mu sync.Mutex
	var order []string
	for _, name := range []string{"a", "b", "c", "d"} {
		bus.Subscribe(func(Event) {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
		})
	}

	bus.Emit(Event{Kind: "x"})

	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, "") != "abcd" {
		t.Errorf("want registration order, got %v", order)
	}
}

// Two goroutines emitting at once must not interleave a single event's
// delivery across subscribers.
func TestConcurrentEmitsDoNotInterleave(t *testing.T) {
	bus := NewBus(0)

	var mu sync.Mutex
	var seen []string
	for i := 0; i < 3; i++ {
		bus.Subscribe(func(e Event) {
			mu.Lock()
			seen = append(seen, e.Kind)
			mu.Unlock()
		})
	}

	var wg sync.WaitGroup
	for _, kind := range []string{"a", "b", "c", "d"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Emit(Event{Kind: kind})
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	// Each event reached all three subscribers as an unbroken run.
	for i := 0; i < len(seen); i += 3 {
		if seen[i] != seen[i+1] || seen[i+1] != seen[i+2] {
			t.Fatalf("one event's delivery was interleaved with another: %v", seen)
		}
	}
}
