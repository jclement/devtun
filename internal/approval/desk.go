// Package approval holds the questions waiting on a human, so that more than
// one surface can show them and any one of them can answer.
//
// Until now a question went to exactly one place: the interface's modal, or a
// desktop dialog, or the terminal. That is fine when you are sitting in front
// of it and useless when you are not — which is the ordinary case, because
// devtun runs in a window you are not looking at. The web board could see that
// something was waiting and could not do anything about it.
//
// So the prompter becomes a desk. A request is registered here, offered to
// whichever prompter the session was built with, and simultaneously visible to
// anything else that asks. The first answer wins and the rest are withdrawn.
//
// # What makes this safe to expose over HTTP
//
// The web board is on loopback behind a one-shot token, a loopback-only Host
// check and an Origin check on every mutation. Those stop somebody reaching the
// port. This package stops the other thing: an answer being *replayed* or aimed
// at the wrong question.
//
//   - A request is addressed by an unguessable id, not by position. "Approve
//     the pending one" is not an operation, because between reading the board
//     and clicking, the pending one may be a different question entirely.
//   - An id is spent on first use. A second answer to the same request is
//     refused rather than silently ignored, so a replayed or double-submitted
//     approval cannot approve the next thing to come along.
//   - A choice is checked against the menu built for that specific request. A
//     request for a signature cannot be answered with an option that was only
//     ever offered for a vault read.
//   - Every id dies with its request. A timed-out question leaves nothing
//     behind to answer.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/prompt"
)

// ErrUnknown is returned for an id that is not waiting: never issued, already
// answered, or expired. The three are deliberately one error — telling them
// apart tells a caller which ids once existed.
var ErrUnknown = errors.New("no such request is waiting")

// ErrNotOffered is returned for a choice that was not on the menu for that
// request.
var ErrNotOffered = errors.New("that answer was not offered for this request")

// Item is one question waiting on a human.
type Item struct {
	// ID addresses this request and nothing else. It is unguessable because it
	// is the thing an HTTP caller presents to answer.
	ID string
	// Request is what is being asked.
	Request prompt.Request
	// Options is the menu built for this request, once, so that every surface
	// offers the same answers.
	Options []prompt.MenuItem
	// Asked is when it arrived, for showing how long it has been waiting.
	Asked time.Time
	// Deadline is when it becomes a refusal on its own. Zero means no deadline,
	// which in practice does not happen: the broker always wraps the ask.
	Deadline time.Time
}

// pending is an Item plus the machinery to answer it exactly once.
type pending struct {
	item   Item
	answer chan prompt.Choice
	once   sync.Once
}

// resolve delivers a choice, the first time only, and reports whether this
// call was the one that landed.
func (p *pending) resolve(choice prompt.Choice) bool {
	var won bool
	p.once.Do(func() {
		won = true
		p.answer <- choice
	})
	return won
}

// Desk is the registry of waiting questions. The zero value is not usable; use
// New.
type Desk struct {
	// asking are the surfaces a question is put to, all at once. Several
	// rather than one because a question you did not see is a timeout, and a
	// timeout reads as a refusal nobody made — so the default is every surface
	// this session has, and the first answer wins.
	asking []prompt.Prompter
	// publish says whether a question is offered to whatever watches this desk
	// — which in practice is the web board.
	//
	// The board is not a Prompter: it reads the waiting list rather than being
	// asked. So without this, choosing `native` or `tui` narrowed where the
	// question was *drawn* and left the board able to see and answer it anyway
	// — which makes naming a surface a suggestion rather than an instruction,
	// and quietly defeats somebody who set `prompt: tui` precisely so that a
	// browser could not approve their key.
	publish bool
	// notify is called whenever the waiting set changes, so a surface can
	// redraw without polling. Optional.
	notify func()
	now    func() time.Time

	mu      sync.Mutex
	waiting map[string]*pending
}

var _ prompt.Prompter = (*Desk)(nil)

// Options configure a Desk.
type Options struct {
	// Prompter is asked alongside the desk being published. Nil means the desk
	// is the only surface, which is what a session with no interface at all
	// would have — and with nothing watching the desk, every request then
	// refuses on its deadline, which is the right answer.
	Prompter prompt.Prompter
	// Changed is called when a question arrives or leaves.
	Changed func()
	// Now is injectable for tests.
	Now func() time.Time
	// Publish offers questions to whatever is watching this desk before Fill
	// has said which surfaces were chosen. Fill overrides it either way.
	Publish bool
}

// New returns a desk.
func New(opts Options) *Desk {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	desk := &Desk{
		notify:  opts.Changed,
		now:     opts.Now,
		waiting: map[string]*pending{},
		// Publishing is off until Fill says which surfaces were chosen. A desk
		// nobody has configured must not be answerable from a board: the
		// direction to fail in is "the question was not offered", never "the
		// question was offered somewhere it should not have been".
		publish: opts.Publish,
	}
	desk.AddPrompter(opts.Prompter)
	return desk
}

// Ask publishes the request, puts it to every surface at once, and returns the
// first answer from any of them.
//
// Every way out that is not a deliberate choice returns ChoiceDeny, which is
// the zero Choice: a timeout, a cancelled context, an interface that has gone.
func (d *Desk) Ask(ctx context.Context, request prompt.Request) (prompt.Choice, error) {
	id, err := newID()
	if err != nil {
		// Without an unguessable id there is nothing safe to publish, and a
		// desk that fell back to a guessable one would be worse than one that
		// refuses. The inner prompter can still answer.
		return d.askInner(ctx, request)
	}

	deadline, _ := ctx.Deadline()
	p := &pending{
		item: Item{
			ID:      id,
			Request: request,
			// Built once, here, from the shared definition: every surface must
			// offer the same answers or they are not answering the same
			// question.
			Options:  prompt.MenuFor(request),
			Asked:    d.now(),
			Deadline: deadline,
		},
		answer: make(chan prompt.Choice, 1),
	}

	d.mu.Lock()
	published := d.publish
	if published {
		d.waiting[id] = p
	}
	d.mu.Unlock()
	if published {
		d.changed()
		defer func() {
			d.mu.Lock()
			delete(d.waiting, id)
			d.mu.Unlock()
			d.changed()
		}()
	}

	// The inner prompter runs under a context this cancels, so an answer from
	// the board withdraws the modal rather than leaving it on screen waiting
	// for an answer nobody is listening for.
	innerCtx, withdraw := context.WithCancel(ctx)
	defer withdraw()

	// Every surface at once, and the first answer wins. resolve takes exactly
	// one, so the losers are simply cancelled — a dialog left on screen after
	// the question was answered on the board is worse than no dialog.
	for _, surface := range d.prompters() {
		go func() {
			choice, err := surface.Ask(innerCtx, request)
			if err != nil {
				// A surface with nobody at it is not an answer. The others are
				// still asking, the desk is still published, and the deadline
				// is still the backstop.
				return
			}
			p.resolve(choice)
		}()
	}

	select {
	case choice := <-p.answer:
		// A select whose cases are both ready picks at random, so an answer
		// arriving in the same instant as the deadline could be returned as an
		// allow the deadline had already refused. The deadline wins: the zero
		// value of a decision is no, and no has to survive a coin toss.
		if ctx.Err() != nil {
			return prompt.ChoiceDeny, nil
		}
		return choice, nil
	case <-ctx.Done():
		return prompt.ChoiceDeny, nil
	}
}

// askInner is the degraded path: no id, so nothing is published and the board
// cannot answer. The first surface is asked directly.
func (d *Desk) askInner(ctx context.Context, request prompt.Request) (prompt.Choice, error) {
	asking := d.prompters()
	if len(asking) == 0 {
		return prompt.ChoiceDeny, prompt.ErrNoPrompter
	}
	return asking[0].Ask(ctx, request)
}

// SetPrompter replaces the surface asked alongside the desk.
//
// It exists for the same reason every other SetPrompter here does: the
// interface's modal cannot be built until its program is, and the Config tab
// can change where approvals appear while the session runs. Call it before a
// question is in flight; a request already waiting keeps the prompter it was
// offered to.
func (d *Desk) SetPrompter(p prompt.Prompter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p == nil {
		d.asking = nil
		return
	}
	d.asking = []prompt.Prompter{p}
}

// Fill puts a prompter on the desk for each surface a question should go to.
//
// One implementation, called from both the interface and the plain session,
// because "where does an approval appear" answered twice is answered
// differently the first time either changes.
//
// tuiPrompter is the interface's modal, which only the interface can build —
// its Bubble Tea program has to exist first. Nil means there is no interface,
// and the terminal surface is a form in the terminal instead.
//
// SurfaceWeb adds nothing: the board watches this desk rather than being asked,
// which is exactly what lets it show a question a dialog is showing at the same
// moment, and answer it out from under that dialog.
func (d *Desk) Fill(surfaces prompt.Surfaces, tuiPrompter prompt.Prompter) {
	var asking []prompt.Prompter
	for _, surface := range prompt.AllSurfaces {
		if !surfaces.Has(surface) {
			continue
		}
		if surface == prompt.SurfaceWeb {
			// Nothing to ask: the board watches instead. Publishing IS its
			// installation.
			continue
		}
		if surface == prompt.SurfaceTUI && tuiPrompter != nil {
			asking = append(asking, tuiPrompter)
			continue
		}
		// A surface that cannot be built here is skipped rather than refused.
		// Whether it is acceptable for one to be missing is a decision about
		// what the user asked for — `all` is a wish and naming one is an
		// instruction — and that decision belongs where the setting is read,
		// not here. Making this total means there is one place that can get it
		// wrong instead of two.
		if prompter, err := prompt.PrompterFor(surface); err == nil && prompter != nil {
			asking = append(asking, prompter)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asking = asking
	d.publish = surfaces.Has(prompt.SurfaceWeb)
}

// AddPrompter adds a surface to ask alongside the others.
//
// Separate from SetPrompter, which replaces: the interface installs its modal
// when its program starts and may install it again when the setting changes,
// and neither of those should quietly drop the desktop dialog.
func (d *Desk) AddPrompter(p prompt.Prompter) {
	if p == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asking = append(d.asking, p)
}

// Publishing reports whether questions are offered to whatever watches this
// desk — the web board. False means the board will show nothing and can answer
// nothing, which is what choosing surfaces without `web` has to mean.
func (d *Desk) Publishing() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.publish
}

// Asking reports how many surfaces a question is put TO, which does not count
// the ones watching the desk. A session whose only surface is the board asks
// nobody and is still perfectly answerable.
func (d *Desk) Asking() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.asking)
}

// prompter reads the inner prompter under the lock.
// prompters copies the list, so a question in flight is not asking a surface
// the settings screen removed underneath it.
func (d *Desk) prompters() []prompt.Prompter {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]prompt.Prompter(nil), d.asking...)
}

// Waiting lists the questions, oldest first, so a surface showing one shows the
// one that has been waiting longest.
func (d *Desk) Waiting() []Item {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]Item, 0, len(d.waiting))
	for _, p := range d.waiting {
		out = append(out, p.item)
	}
	// Insertion sort: there is almost never more than one, and often none.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Asked.Before(out[j-1].Asked); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Answer resolves one waiting request.
//
// It is the whole of what an HTTP caller may do, so it is deliberately narrow:
// an id that is waiting, and a choice that was on that request's own menu.
// Both are checked, and the id is spent whether or not this call was the one
// that landed — a second answer to the same question is refused rather than
// quietly dropped, because a caller that thinks it approved something and did
// not is worse off than one that is told no.
func (d *Desk) Answer(id string, choice prompt.Choice) error {
	d.mu.Lock()
	p, ok := d.waiting[id]
	d.mu.Unlock()
	if !ok {
		return ErrUnknown
	}

	if !offered(p.item.Options, choice) {
		return ErrNotOffered
	}
	if !p.resolve(choice) {
		// Somebody else got there first — the modal, the dialog, or a second
		// click. The question is answered; this call did not answer it.
		return ErrUnknown
	}
	return nil
}

// offered reports whether a choice was on this request's menu.
//
// Deny is always allowed even when the menu does not list it: the desktop
// dialog expresses refusal as its cancel button rather than as an option, and
// a surface must always be able to say no.
func offered(options []prompt.MenuItem, choice prompt.Choice) bool {
	if choice == prompt.ChoiceDeny {
		return true
	}
	for _, item := range options {
		if item.Choice == choice {
			return true
		}
	}
	return false
}

func (d *Desk) changed() {
	if d.notify != nil {
		d.notify()
	}
}

// newID mints an unguessable request id.
func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
