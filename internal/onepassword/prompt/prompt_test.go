package prompt

import (
	"context"
	"sync"
	"testing"
	"time"
)

// blockingPrompter records overlap, which is the property Serialize exists to
// prevent: two prompts drawing on one terminal at once.
type blockingPrompter struct {
	mu          sync.Mutex
	concurrent  int
	maxOverlap  int
	releaseOnce sync.Once
	release     chan struct{}
}

func newBlockingPrompter() *blockingPrompter {
	return &blockingPrompter{release: make(chan struct{})}
}

func (b *blockingPrompter) Ask(ctx context.Context, request Request) (Choice, error) {
	b.mu.Lock()
	b.concurrent++
	if b.concurrent > b.maxOverlap {
		b.maxOverlap = b.concurrent
	}
	b.mu.Unlock()

	select {
	case <-b.release:
	case <-ctx.Done():
	}

	b.mu.Lock()
	b.concurrent--
	b.mu.Unlock()
	return ChoiceAllowOnce, nil
}

func (b *blockingPrompter) unblock() {
	b.releaseOnce.Do(func() { close(b.release) })
}

func TestSerializeAsksOneAtATime(t *testing.T) {
	inner := newBlockingPrompter()
	prompter := Serialize(inner)

	var wait sync.WaitGroup
	for i := 0; i < 5; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = prompter.Ask(context.Background(), Request{Host: "devbox", Subject: "op://V/I/F"})
		}()
	}

	time.Sleep(50 * time.Millisecond)
	inner.unblock()
	wait.Wait()

	inner.mu.Lock()
	defer inner.mu.Unlock()
	if inner.maxOverlap != 1 {
		t.Errorf("maximum overlapping prompts = %d, want 1", inner.maxOverlap)
	}
}

// A request whose deadline has already passed must not sit in the queue and
// then pop a prompt for a caller that has given up.
func TestSerializeRespectsCancellationWhileQueued(t *testing.T) {
	inner := newBlockingPrompter()
	defer inner.unblock()
	prompter := Serialize(inner)

	held := make(chan struct{})
	go func() {
		close(held)
		_, _ = prompter.Ask(context.Background(), Request{Subject: "first"})
	}()
	<-held
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	choice, err := prompter.Ask(ctx, Request{Subject: "second"})
	if err == nil {
		t.Fatal("a queued request past its deadline should fail")
	}
	if choice.Allows() {
		t.Error("a cancelled prompt must not allow anything")
	}
}

func TestDenyAllRefuses(t *testing.T) {
	choice, err := DenyAll{}.Ask(context.Background(), Request{})
	if choice.Allows() {
		t.Error("DenyAll allowed a request")
	}
	if err != ErrNoPrompter {
		t.Errorf("err = %v, want ErrNoPrompter", err)
	}
}

// The zero value has to be Deny: a prompt that is interrupted, times out, or
// fails to render falls back to it.
func TestZeroChoiceIsDeny(t *testing.T) {
	var choice Choice
	if choice.Allows() {
		t.Fatal("the zero Choice must not allow anything")
	}
	if choice != ChoiceDeny {
		t.Errorf("zero Choice = %v, want ChoiceDeny", choice)
	}
}

func TestNewRejectsUnknownBackend(t *testing.T) {
	if _, err := New("carrier-pigeon"); err == nil {
		t.Fatal("an unknown backend should be an error")
	}
	if _, err := New(BackendDeny); err != nil {
		t.Fatalf("New(deny): %v", err)
	}
}
