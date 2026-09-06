package prompt

import (
	"context"
	"strings"
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

// The menu is the sentence somebody is deciding on, so it has to describe what
// will actually happen. "Allow this secret" in front of a signature request
// describes something that is not happening.
func TestMenuNamesTheSubjectAndItsScope(t *testing.T) {
	key := Request{Host: "bedev", Noun: "key", Scope: "github.com", TTL: 5 * time.Minute}

	var labels []string
	for _, item := range MenuFor(key) {
		labels = append(labels, item.Label)
	}
	joined := strings.Join(labels, "\n")

	if !strings.Contains(joined, "this key for github.com — 5m0s") {
		t.Errorf("the menu should name the key and its destination:\n%s", joined)
	}
	if strings.Contains(joined, "this secret") {
		t.Errorf("a signature request should not be described as a secret:\n%s", joined)
	}

	// The default noun keeps the 1Password wording exactly as it was.
	secret := Request{Host: "bedev", TTL: 5 * time.Minute}
	for _, item := range MenuFor(secret) {
		if strings.Contains(item.Label, "this secret") {
			return
		}
	}
	t.Error("with no noun the menu should still say 'this secret'")
}

// The order never changes — only where the cursor starts. A hurried reader must
// still see the broad options below the narrow ones and travel to reach them.
func TestPreferredIndexMovesTheCursorNotTheOptions(t *testing.T) {
	menu := MenuFor(Request{Host: "bedev", Noun: "key", TTL: time.Minute})

	if got := PreferredIndex(menu, ChoiceAllowSecretSession); menu[got].Choice != ChoiceAllowSecretSession {
		t.Errorf("the preferred option was not found, landed on %v", menu[got].Choice)
	}
	if menu[0].Choice != ChoiceAllowOnce {
		t.Error("the options must stay in narrowest-first order")
	}
	// Every approval comes before every refusal, so nothing that grants access
	// can be reached by overshooting downward. Deny is no longer literally last
	// — "no, this session" and "never" follow it — but no allow may be.
	seenRefusal := false
	for _, item := range menu {
		if !item.Choice.Allows() {
			seenRefusal = true
			continue
		}
		if seenRefusal {
			t.Errorf("%q grants access but sits below a refusal", item.Label)
		}
	}
	if menu[len(menu)-1].Choice.Allows() {
		t.Error("the last option must never be one that grants access")
	}

	// An unset preference is the zero Choice, which is Deny — and resolving
	// that literally would start the cursor on "Deny".
	if got := PreferredIndex(menu, ChoiceDeny); got != 0 {
		t.Errorf("an unset preference should land on the first option, got %d", got)
	}
	if got := PreferredIndex(menu, Choice(99)); got != 0 {
		t.Errorf("an unknown preference should land on the first option, got %d", got)
	}
}
