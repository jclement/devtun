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

	tea "charm.land/bubbletea/v2"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/onepassword"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/sshagent"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
)

// Options is everything the interface is given. Every field is optional except
// Bus and Session: a session running only tunnels has no Secrets service, and
// the interface must be honest about that rather than fall over.
type Options struct {
	Session  *session.Session
	Bus      *event.Bus
	Tunnels  *tunnels.Service
	Secrets  *onepassword.Service
	Agent    *sshagent.Service
	Services []service.Service
	Host     string
	Version  string
	Store    *hostcfg.Store
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
		secrets:  secretSources(o.Secrets, o.Agent),
		store:    storeOf(o.Store),
		services: o.Services,
		status:   statusOf(o.Session),
		retry:    retryOf(o.Session),
		host:     o.Host,
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
	if o.Secrets != nil {
		o.Secrets.SetPrompter(prompter)
	}
	if o.Session != nil {
		o.Session.SetAskSetup(prompter.AskSetup)
	}

	stop := forwardEvents(o.Bus, program)
	defer stop()

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

// secretSources lists the brokers whose grants and rules the Secrets tab shows.
//
// A nil service is left out rather than listed as empty: a session running only
// tunnels has no broker at all, and a tab offering to revoke nothing from a
// thing that is not running would be a lie about what is happening.
func secretSources(op *onepassword.Service, agent *sshagent.Service) []secretSource {
	var out []secretSource
	if op != nil {
		out = append(out, secretSource{id: "1password", title: "1Password", ctrl: op})
	}
	if agent != nil {
		out = append(out, secretSource{id: "ssh-agent", title: "SSH Agent", ctrl: cachelessBroker{agent}})
	}
	return out
}

// cachelessBroker adapts a broker that has nothing to purge.
//
// The agent never holds a secret to cache: it does not see key material at any
// point, it only asks the real agent to produce a signature. So it can forget
// grants but has no second number to report, and reporting a zero it computed
// is more honest than an interface pretending every broker keeps a cache.
type cachelessBroker struct{ *sshagent.Service }

func (b cachelessBroker) Forget() (grants, cached int) { return b.Service.Forget(), 0 }

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
