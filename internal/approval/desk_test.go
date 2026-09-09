package approval

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/prompt"
)

func testRequest() prompt.Request {
	return prompt.Request{Host: "bedev", Subject: "op://Personal/Docker/PAT", TTL: 5 * time.Minute}
}

// blockingPrompter never answers, standing in for a modal nobody is looking at.
type blockingPrompter struct{ asked chan struct{} }

func (p *blockingPrompter) Ask(ctx context.Context, _ prompt.Request) (prompt.Choice, error) {
	select {
	case p.asked <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return prompt.ChoiceDeny, nil
}

// waitFor polls until the desk has the expected number of questions, so a test
// never depends on how fast a goroutine got scheduled.
func waitFor(t *testing.T, d *Desk, want int) []Item {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if items := d.Waiting(); len(items) == want {
			return items
		}
		if time.Now().After(deadline) {
			t.Fatalf("wanted %d waiting, got %d", want, len(d.Waiting()))
		}
		time.Sleep(time.Millisecond)
	}
}

// A question is visible to anything watching the desk, and answering it there
// is what the asker gets back.
func TestAnsweringFromTheDeskIsWhatTheAskerGets(t *testing.T) {
	inner := &blockingPrompter{asked: make(chan struct{}, 1)}
	desk := New(Options{Prompter: inner})

	got := make(chan prompt.Choice, 1)
	go func() {
		choice, _ := desk.Ask(context.Background(), testRequest())
		got <- choice
	}()

	items := waitFor(t, desk, 1)
	if items[0].Request.Subject != "op://Personal/Docker/PAT" {
		t.Fatalf("the desk published %+v", items[0].Request)
	}
	if len(items[0].Options) == 0 {
		t.Fatal("the desk published no menu, so nothing could answer it")
	}

	if err := desk.Answer(items[0].ID, prompt.ChoiceAllowOnce); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	select {
	case choice := <-got:
		if choice != prompt.ChoiceAllowOnce {
			t.Errorf("the asker got %v", choice)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the asker never returned")
	}

	if len(desk.Waiting()) != 0 {
		t.Error("an answered question is still on the desk")
	}
}

// An id is spent on first use. Without that, a replayed approval could land on
// whatever question happened to be waiting next.
func TestAnIDIsGoodForOneAnswer(t *testing.T) {
	inner := &blockingPrompter{asked: make(chan struct{}, 1)}
	desk := New(Options{Prompter: inner})

	go func() { _, _ = desk.Ask(context.Background(), testRequest()) }()
	id := waitFor(t, desk, 1)[0].ID

	if err := desk.Answer(id, prompt.ChoiceAllowOnce); err != nil {
		t.Fatalf("the first answer was refused: %v", err)
	}
	if err := desk.Answer(id, prompt.ChoiceAllowOnce); !errors.Is(err, ErrUnknown) {
		t.Errorf("the same id answered twice: %v", err)
	}
}

// Addressing by id and not by position is the point: between reading the board
// and clicking, the waiting question may be a different one entirely.
func TestAnUnknownIDIsRefused(t *testing.T) {
	desk := New(Options{})
	for _, id := range []string{"", "not-an-id", strings.Repeat("A", 22)} {
		if err := desk.Answer(id, prompt.ChoiceAllowOnce); !errors.Is(err, ErrUnknown) {
			t.Errorf("id %q was accepted: %v", id, err)
		}
	}
}

// A request for a signature must not be answerable with an option that was only
// ever offered for a vault read.
func TestAChoiceMustHaveBeenOnThatRequestsMenu(t *testing.T) {
	inner := &blockingPrompter{asked: make(chan struct{}, 1)}
	desk := New(Options{Prompter: inner})

	go func() { _, _ = desk.Ask(context.Background(), testRequest()) }()
	item := waitFor(t, desk, 1)[0]

	// A Choice outside the range the menu offers at all.
	if err := desk.Answer(item.ID, prompt.Choice(99)); !errors.Is(err, ErrNotOffered) {
		t.Errorf("an answer that was never offered was accepted: %v", err)
	}
	// Deny is always available even when the menu does not list it, because a
	// surface must always be able to say no.
	if err := desk.Answer(item.ID, prompt.ChoiceDeny); err != nil {
		t.Errorf("a refusal was refused: %v", err)
	}
}

// The modal and the board are the same question. Whichever answers first wins,
// and the other is withdrawn rather than left waiting for an answer nobody is
// listening for.
func TestTheFirstAnswerWinsAndTheOtherIsWithdrawn(t *testing.T) {
	withdrawn := make(chan struct{})
	inner := prompt.PrompterFunc(func(ctx context.Context, _ prompt.Request) (prompt.Choice, error) {
		<-ctx.Done()
		close(withdrawn)
		return prompt.ChoiceDeny, nil
	})
	desk := New(Options{Prompter: inner})

	go func() { _, _ = desk.Ask(context.Background(), testRequest()) }()
	id := waitFor(t, desk, 1)[0].ID

	if err := desk.Answer(id, prompt.ChoiceAllowOnce); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	select {
	case <-withdrawn:
	case <-time.After(2 * time.Second):
		t.Error("the inner prompter was left waiting after the desk answered")
	}
}

// The other direction: the modal answers, and the question leaves the desk so
// the board stops offering something that has already been decided.
func TestAnAnswerAtTheModalClearsTheDesk(t *testing.T) {
	desk := New(Options{Prompter: prompt.PrompterFunc(
		func(context.Context, prompt.Request) (prompt.Choice, error) {
			return prompt.ChoiceAllowSecretTTL, nil
		})})

	choice, err := desk.Ask(context.Background(), testRequest())
	if err != nil || choice != prompt.ChoiceAllowSecretTTL {
		t.Fatalf("Ask = %v, %v", choice, err)
	}
	if len(desk.Waiting()) != 0 {
		t.Error("the question is still on the desk after the modal answered it")
	}
}

// A question that times out leaves nothing behind to answer, and refuses.
func TestATimedOutQuestionRefusesAndLeavesNothing(t *testing.T) {
	inner := &blockingPrompter{asked: make(chan struct{}, 1)}
	desk := New(Options{Prompter: inner})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	choice, err := desk.Ask(ctx, testRequest())
	if err != nil {
		t.Fatalf("a timeout is a refusal, not an error: %v", err)
	}
	if choice != prompt.ChoiceDeny {
		t.Errorf("a timed-out question answered %v", choice)
	}
	if len(desk.Waiting()) != 0 {
		t.Error("a timed-out question is still answerable")
	}
}

// Two surfaces clicking at once must not both succeed, or a question has been
// answered twice and one of the callers is wrong about what happened.
func TestConcurrentAnswersProduceExactlyOneWinner(t *testing.T) {
	inner := &blockingPrompter{asked: make(chan struct{}, 1)}
	desk := New(Options{Prompter: inner})

	go func() { _, _ = desk.Ask(context.Background(), testRequest()) }()
	id := waitFor(t, desk, 1)[0].ID

	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = desk.Answer(id, prompt.ChoiceAllowOnce)
		}(i)
	}
	wg.Wait()

	var won int
	for _, err := range results {
		if err == nil {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d callers were told they answered the question, want 1", won)
	}
}

// Ids must not be guessable: they are what an HTTP caller presents to approve
// access to a vault.
func TestIDsAreUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		id, err := newID()
		if err != nil {
			t.Fatalf("newID: %v", err)
		}
		if len(id) < 20 {
			t.Fatalf("id %q is too short to be unguessable", id)
		}
		if seen[id] {
			t.Fatalf("id %q was minted twice", id)
		}
		seen[id] = true
	}
}

// recorder is a surface that says when it was asked and can be told what to
// answer, so a test can watch several of them at once.
type recorder struct {
	asked   chan struct{}
	answer  chan prompt.Choice
	dropped chan struct{}
}

func newRecorder() *recorder {
	return &recorder{
		asked:   make(chan struct{}, 8),
		answer:  make(chan prompt.Choice, 1),
		dropped: make(chan struct{}, 8),
	}
}

func (r *recorder) Ask(ctx context.Context, _ prompt.Request) (prompt.Choice, error) {
	r.asked <- struct{}{}
	select {
	case choice := <-r.answer:
		return choice, nil
	case <-ctx.Done():
		r.dropped <- struct{}{}
		return prompt.ChoiceDeny, ctx.Err()
	}
}

func (r *recorder) wasAsked(t *testing.T) {
	t.Helper()
	select {
	case <-r.asked:
	case <-time.After(2 * time.Second):
		t.Fatal("this surface was never asked")
	}
}

// The default is every surface at once. devtun runs in a window you are not
// looking at, so whichever single surface you pick is the one you will miss —
// and a question nobody sees becomes a timeout, which reads as a refusal
// nobody made.
func TestAQuestionGoesToEverySurfaceAtOnce(t *testing.T) {
	terminal, dialog := newRecorder(), newRecorder()
	desk := New(Options{Prompter: terminal})
	desk.AddPrompter(dialog)

	if got := desk.Asking(); got != 2 {
		t.Fatalf("the desk is asking %d surfaces, want 2", got)
	}

	go func() { _, _ = desk.Ask(context.Background(), testRequest()) }()
	terminal.wasAsked(t)
	dialog.wasAsked(t)

	// And the board, which watches the desk rather than being a prompter.
	if items := waitFor(t, desk, 1); items[0].Request.Subject == "" {
		t.Error("the question was not published for the board")
	}
}

// The first answer wins and the rest are taken down. A dialog still on screen
// after the question was answered on the board is worse than no dialog: the
// next thing you do is answer a question that has already been decided.
func TestTheFirstSurfaceToAnswerTakesTheOthersDown(t *testing.T) {
	terminal, dialog := newRecorder(), newRecorder()
	desk := New(Options{Prompter: terminal})
	desk.AddPrompter(dialog)

	got := make(chan prompt.Choice, 1)
	go func() {
		choice, _ := desk.Ask(context.Background(), testRequest())
		got <- choice
	}()
	terminal.wasAsked(t)
	dialog.wasAsked(t)

	terminal.answer <- prompt.ChoiceAllowSecretSession

	select {
	case choice := <-got:
		if choice != prompt.ChoiceAllowSecretSession {
			t.Errorf("the asker got %v", choice)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the answer never came back")
	}
	select {
	case <-dialog.dropped:
	case <-time.After(2 * time.Second):
		t.Error("the other surface was left asking a question that had been answered")
	}
}

// A surface with nobody at it must not decide anything. A dialog on a machine
// with no window server fails immediately; if that counted as an answer, every
// request would be refused the instant it was made and the surfaces that *do*
// have somebody at them would never get a chance.
func TestASurfaceThatFailsDoesNotAnswerForTheOthers(t *testing.T) {
	broken := prompt.PrompterFunc(func(context.Context, prompt.Request) (prompt.Choice, error) {
		return prompt.ChoiceDeny, errors.New("no window server")
	})
	good := newRecorder()
	desk := New(Options{Prompter: broken})
	desk.AddPrompter(good)

	got := make(chan prompt.Choice, 1)
	go func() {
		choice, _ := desk.Ask(context.Background(), testRequest())
		got <- choice
	}()

	good.wasAsked(t)
	select {
	case choice := <-got:
		t.Fatalf("a broken surface answered %v for the whole desk", choice)
	case <-time.After(150 * time.Millisecond):
	}

	good.answer <- prompt.ChoiceAllowOnce
	select {
	case choice := <-got:
		if choice != prompt.ChoiceAllowOnce {
			t.Errorf("the working surface's answer came back as %v", choice)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the working surface's answer never arrived")
	}
}

// SetPrompter replaces and AddPrompter adds. The interface installs its modal
// when its program starts, and again when the setting changes; neither should
// quietly drop the desktop dialog beside it.
func TestReplacingASurfaceDoesNotDropTheRest(t *testing.T) {
	desk := New(Options{Prompter: newRecorder()})
	desk.AddPrompter(newRecorder())
	if got := desk.Asking(); got != 2 {
		t.Fatalf("Asking = %d, want 2", got)
	}
	desk.SetPrompter(newRecorder())
	if got := desk.Asking(); got != 1 {
		t.Errorf("after SetPrompter the desk asks %d surfaces, want 1", got)
	}
	desk.AddPrompter(newRecorder())
	if got := desk.Asking(); got != 2 {
		t.Errorf("after AddPrompter the desk asks %d surfaces, want 2", got)
	}
	// Nil is not a surface, and adding one must not create a hole that looks
	// like somewhere to ask.
	desk.AddPrompter(nil)
	if got := desk.Asking(); got != 2 {
		t.Errorf("a nil surface was counted: %d", got)
	}
}
