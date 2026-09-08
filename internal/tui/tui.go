// Package tui is devtun's interactive interface: one screen for one session,
// with everything that session is doing on it at once.
//
// devtun is a single SSH connection with several services layered on it, and
// the argument for putting them in one window is that the interesting moments
// are the ones where they meet — a deploy script on the remote box asking for a
// secret while the port it will publish to comes up. So there is one frame,
// four tabs over it, and a three-line ticker of recent activity under every tab
// so an approval can never be off-screen when it arrives.
//
// Everything here is a view. The model asks the services what is true and tells
// them what the user pressed; it computes nothing a subcommand would also want,
// because anything of that shape belongs in the service where `devtun status`
// can reach it too. That is why the whole layer is testable by sending it
// messages and reading the frame back: there is no SSH connection behind it to
// stub out, only three narrow interfaces.
package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// Options is everything the interface is given. Every field is optional except
// Bus and Session: a session running only tunnels has no 1Password service, and
// the interface must be honest about that rather than fall over.
type Options struct {
	Session *session.Session
	Bus     *event.Bus
	Tunnels *tunnels.Service
	// Services is the registry, in the order the session attaches them. The
	// interface finds what it needs in here by interface — brokers for the
	// Access tab, prompters, settings — rather than by naming services it
	// happens to import, so a fifth one is wired up by existing.
	Services []service.Service
	Host     string
	Version  string
	Store    *hostcfg.Store
	// Prompt is how approvals are asked for. The modal is the default and the
	// right answer for someone looking at this window; BackendDialog says to
	// raise a desktop dialog instead, which is what you want when devtun is
	// running behind the browser and a secret request would otherwise sit
	// unanswered on a screen nobody is on.
	Prompt prompt.Backend
	// WebURL is where the browser interface is, when one was asked for. It is
	// announced through the log once the program is running, because it is
	// carrying a token and a line printed before then would scroll the frame.
	WebURL string
	// NoDissolve turns off the exit animation, for a terminal or a person that
	// would rather not have one.
	NoDissolve bool
}

// Run owns the terminal until the user quits or ctx is cancelled. It starts
// the session itself, in the background.
func Run(ctx context.Context, o Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	model := newModel(deps{
		tunnels:  tunnelAdapter{svc: o.Tunnels},
		secrets:  secretSources(o.Services),
		store:    storeOf(o.Store),
		services: o.Services,
		status:   statusOf(o.Session),
		retry:    retryOf(o.Session),
		host:     o.Host,
		webURL:   o.WebURL,
		version:  o.Version,
		dissolve: !o.NoDissolve,
		openURL:  ui.OpenURL,
	})

	program := tea.NewProgram(model, tea.WithContext(ctx))

	// The approval modal and the shell-rc question are both this interface's
	// to answer, and neither can exist before the program does — which is why
	// they are installed here rather than wired up at construction. Under the
	// TUI the 1Password service is deliberately built with no prompter at all,
	// so without this every request would be silently refused.
	prompter := NewPrompter()
	prompter.Attach(program)
	defer prompter.Detach()

	// Every service that asks a human gets the modal, found by interface
	// rather than by name.
	//
	// This was a list of one, and the SSH agent broker was not on it — so
	// under the interface, which is the default, every signature was refused
	// in the same instant it was requested and no prompt ever appeared. A
	// service built with no prompter refuses by construction, which is the
	// right default and exactly why forgetting to install one is silent.
	// Asking "can you be prompted?" means a fifth broker cannot be forgotten.
	approver := approverFor(o.Prompt, prompter, o.Bus)
	for _, svc := range o.Services {
		if p, ok := svc.(interface{ SetPrompter(prompt.Prompter) }); ok {
			p.SetPrompter(approver)
		}
	}
	if o.Session != nil {
		o.Session.SetAskSetup(prompter.AskSetup)
	}

	stop := forwardEvents(o.Bus, program)
	defer stop()

	// After the forwarder is subscribed, or the one line telling somebody where
	// the browser interface is would be the one line they never see.
	if o.WebURL != "" && o.Bus != nil {
		o.Bus.Emit(event.Event{
			Time: time.Now(), Service: "web", Class: event.Lifecycle, Level: event.Info,
			Kind: "listening", Text: "the board is also at " + o.WebURL,
		})
	}

	if o.Session != nil {
		go func() {
			defer restoreOnPanic(program)
			if err := o.Session.Run(ctx); err != nil {
				program.Send(fatalMsg{err: err})
			}
		}()
	}

	defer restoreOnPanic(program)

	if _, err := program.Run(); err != nil {
		return err
	}
	return model.Err()
}

// restoreOnPanic puts the terminal back before a panic takes the process down.
//
// Bubble Tea recovers panics on its own goroutines; these are ours, and a crash
// that leaves the alternate screen up and the terminal in raw mode leaves a
// shell the user has to close rather than fix.
func restoreOnPanic(program *tea.Program) {
	if r := recover(); r != nil {
		program.Kill()
		panic(r)
	}
}

// tunnelAdapter joins the tunnels service to its manager.
//
// The Manager does not exist until the first connection — it is bound to a
// host's config — so it is resolved on every call rather than captured: the
// interface is on screen long before there is anything to show in it, and a
// nil captured at construction would stay nil forever. A call made before then
// answers emptily, which is the truth.
type tunnelAdapter struct{ svc *tunnels.Service }

func (a tunnelAdapter) mgr() *tunnels.Manager {
	if a.svc == nil {
		return nil
	}
	return a.svc.Manager()
}

// Hidden counts what the table is deliberately not showing.
func (a tunnelAdapter) Hidden() int {
	if m := a.mgr(); m != nil {
		return m.Hidden()
	}
	return 0
}

func (a tunnelAdapter) States() []tunnels.State {
	if a.svc == nil {
		return nil
	}
	return a.svc.States()
}

func (a tunnelAdapter) SetMode(remotePort int, mode tunnels.Mode) tunnels.Mode {
	if m := a.mgr(); m != nil {
		return m.SetMode(remotePort, mode)
	}
	return tunnels.ModeAuto
}

func (a tunnelAdapter) CycleMode(remotePort int) tunnels.Mode {
	if m := a.mgr(); m != nil {
		return m.CycleMode(remotePort)
	}
	return tunnels.ModeAuto
}

func (a tunnelAdapter) CycleScheme(remotePort int) tunnels.Scheme {
	if m := a.mgr(); m != nil {
		return m.CycleScheme(remotePort)
	}
	return tunnels.SchemeUnknown
}

func (a tunnelAdapter) SetScheme(remotePort int, scheme tunnels.Scheme) tunnels.Scheme {
	if m := a.mgr(); m != nil {
		return m.SetScheme(remotePort, scheme)
	}
	return tunnels.SchemeUnknown
}

func (a tunnelAdapter) SetLocalPort(remotePort, local int) error {
	if m := a.mgr(); m != nil {
		return m.SetLocalPort(remotePort, local)
	}
	return nil
}

func (a tunnelAdapter) SetLabel(remotePort int, label string) error {
	if m := a.mgr(); m != nil {
		return m.SetLabel(remotePort, label)
	}
	return nil
}

func (a tunnelAdapter) Policy() tunnels.Policy {
	if m := a.mgr(); m != nil {
		return m.Policy()
	}
	return tunnels.Policy{}
}

func (a tunnelAdapter) SetPolicy(p tunnels.Policy) {
	if m := a.mgr(); m != nil {
		m.SetPolicy(p)
	}
}

func (a tunnelAdapter) ViewPrefs() tunnels.ViewPrefs {
	if a.svc == nil {
		return tunnels.DefaultViewPrefs()
	}
	return a.svc.ViewPrefs()
}

func (a tunnelAdapter) SetViewPrefs(p tunnels.ViewPrefs) {
	if a.svc != nil {
		a.svc.SetViewPrefs(p)
	}
}

// The remaining adapters exist only to turn a typed nil pointer into an
// interface that is nil, which is the difference between "no 1Password on this
// session" and a crash.

// secretSources lists the brokers whose grants and rules the Access tab shows.
//
// Found by interface, in registry order, rather than by naming the two services
// this package happens to import. That is the same lesson as the prompter: a
// list of services written down by hand is a list somebody adds a fifth service
// to and forgets — and a broker missing from this tab is access nobody can see
// or take back.
//
// A service that does not gate anything is left out rather than listed as
// empty, since a tab offering to revoke nothing from something that never asks
// would be a lie about what is happening.
func secretSources(services []service.Service) []accessSource {
	var out []accessSource
	for _, svc := range services {
		meta := svc.Meta()
		switch broker := svc.(type) {
		case secretsCtrl:
			out = append(out, accessSource{id: meta.ID, title: meta.Title, ctrl: broker})
		case cachelessCtrl:
			// A broker with no cache to purge reports the zero it computed
			// rather than the interface pretending every broker keeps one.
			out = append(out, accessSource{id: meta.ID, title: meta.Title, ctrl: cachelessBroker{broker}})
		}
	}
	return out
}

// cachelessCtrl is the same surface minus the two-number Forget: a broker that
// never sees a secret has nothing to cache and nothing to purge.
type cachelessCtrl interface {
	Rules() []authz.Rule
	GlobalRules() []authz.Rule
	Revoke(index int) error
	Deny(index int) error
	Grants() []authz.Grant
	RevokeGrant(host, subject string) bool
	Forget() int
}

// cachelessBroker adapts a broker that has nothing to purge.
//
// The agent never holds a secret to cache: it does not see key material at any
// point, it only asks the real agent to produce a signature. The browser is the
// same. So they can forget grants but have no second number to report.
type cachelessBroker struct{ cachelessCtrl }

func (b cachelessBroker) Forget() (grants, cached int) { return b.cachelessCtrl.Forget(), 0 }

func storeOf(s *hostcfg.Store) configStore {
	if s == nil {
		return nil
	}
	return s
}

func statusOf(s *session.Session) func() session.Status {
	if s == nil {
		return nil
	}
	return s.Status
}

func retryOf(s *session.Session) func() {
	if s == nil {
		return nil
	}
	return s.RetryNow
}

// approverFor picks the prompter the brokers are given.
//
// The modal is the default and the right answer for somebody looking at this
// window. The other two are deliberate settings: a desktop dialog for when
// devtun's window is not the one you are looking at, and deny for a session
// that must answer nothing at all — which has to hold here too, or a modal
// anyone walking past could approve would quietly undo it.
func approverFor(backend prompt.Backend, modal prompt.Prompter, bus *event.Bus) prompt.Prompter {
	switch backend {
	case prompt.BackendDeny:
		return prompt.Serialize(prompt.DenyAll{})
	case prompt.BackendDialog:
		dialog, err := prompt.NewWithFallback(prompt.BackendDialog, modal)
		if err != nil {
			// Not fatal: the interface can ask perfectly well itself, and
			// ending a session over a missing zenity would be absurd. Say so
			// once, in the log everybody can see.
			if bus != nil {
				bus.Emit(event.Event{
					Time: time.Now(), Service: "session", Class: event.Security, Level: event.Warn,
					Kind: "prompt", Text: "asking in the interface instead: " + err.Error(),
				})
			}
			return modal
		}
		// The modal stays the dialog's fallback, so a dialog that cannot be
		// drawn on the day asks here rather than refusing on the user's behalf.
		return dialog
	default:
		return modal
	}
}
