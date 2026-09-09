package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jclement/devtun/internal/approval"
	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/browser"
	"github.com/jclement/devtun/internal/buildinfo"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/gpgagent"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/onepassword"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/release"
	"github.com/jclement/devtun/internal/render"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/settings"
	"github.com/jclement/devtun/internal/sshagent"
	"github.com/jclement/devtun/internal/sshx"
	"github.com/jclement/devtun/internal/tui"
	"github.com/jclement/devtun/internal/tunnels"
	"github.com/jclement/devtun/internal/ui"
	"github.com/jclement/devtun/internal/web"
)

// historyLimit is how many events the bus retains for a renderer that attaches
// late — the activity tab, opened for the first time ten minutes in.
const historyLimit = 2000

// upFlags is every flag on the default command.
type upFlags struct {
	destination string

	// transport
	user           string
	port           int
	identityFiles  []string
	proxyJump      string
	authSock       string
	knownHosts     []string
	hostKeyMode    string
	connectTimeout time.Duration
	wait           bool
	noReconnect    bool

	// tunnels
	bind       string
	include    string
	exclude    string
	minPort    int
	maxPort    int
	remoteBind string
	samePort   bool
	interval   time.Duration

	// SSH agent
	noAgent bool

	// 1Password
	promptBackend string
	account       string
	opPath        string
	cache         bool
	cacheTTL      time.Duration
	ttl           time.Duration
	promptTimeout time.Duration

	// gate overrides whether gated services ask before acting, for this run.
	gate string
	// takeOver displaces another devtun already attached to the host.
	takeOver bool
	// web, when set, serves the board over HTTP as well. "on" picks a port.
	web string
	// webOpen opens that page in a browser once it is listening.
	webOpen bool

	// presentation and behaviour
	tui        bool
	logMode    bool
	jsonOut    bool
	plain      bool
	noColor    bool
	verbose    bool
	setup      string
	noInstall  bool
	noDissolve bool
	shimBinary string
	only       []string
	// installOnly stops once the remote helper is in place, for `devtun
	// install`. It is not a flag; the subcommand sets it.
	installOnly bool
}

func (f *upFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	f.registerConnection(fl)

	fl.BoolVar(&f.wait, "wait", false, "keep retrying until the first connection succeeds")
	fl.BoolVar(&f.noReconnect, "no-reconnect", false, "make a dropped connection fatal")

	fl.StringVarP(&f.bind, "bind", "b", "127.0.0.1", "local bind address (0.0.0.0 shares on your LAN)")
	fl.StringVar(&f.include, "include", "", "only these remote ports, e.g. 3000,8000-9000")
	fl.StringVar(&f.exclude, "exclude", "", "never these remote ports")
	fl.IntVar(&f.minPort, "min-port", 1024, "lowest remote port to forward")
	fl.IntVar(&f.maxPort, "max-port", 65535, "highest remote port to forward")
	fl.StringVar(&f.remoteBind, "remote-bind", "any", "forward services bound to: any, loopback")
	fl.BoolVar(&f.samePort, "same-port", false, "never remap; a busy local port is an error")
	fl.DurationVar(&f.interval, "interval", 2*time.Second, "how often to scan the remote for new ports")

	fl.BoolVar(&f.noAgent, "no-agent", false, "do not forward your SSH agent")
	// No default: an empty value means "whatever the config says, else auto",
	// and a flag defaulting to auto could not be told apart from someone
	// typing it — which would make the config setting unreachable.
	fl.StringVar(&f.promptBackend, "prompt", "", "approvals: auto, tui, dialog, deny (default: your config, else auto)")
	fl.StringVar(&f.account, "account", "", "pin 1Password requests to one account")
	fl.BoolVar(&f.cache, "cache", false, "hold fetched secret values in memory")
	fl.DurationVar(&f.cacheTTL, "cache-ttl", 0, "how long a cached secret is kept (default: the grant)")
	fl.DurationVar(&f.ttl, "ttl", 0, "lifetime of temporary approvals (default 5m)")
	fl.DurationVar(&f.promptTimeout, "prompt-timeout", 0, "how long a request waits for you (default 2m)")

	fl.BoolVar(&f.tui, "tui", false, "the interactive interface (the default on a terminal)")
	fl.BoolVar(&f.logMode, "log", false, "a coloured line per event instead of the interface")
	fl.BoolVar(&f.noDissolve, "no-dissolve", false, "skip the quit animation. you monster.")
	fl.BoolVar(&f.jsonOut, "json", false, "NDJSON, one object per event")
	fl.BoolVar(&f.plain, "plain", false, "plain log lines, no colour")
	fl.BoolVar(&f.noColor, "no-color", false, "disable colour")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "include diagnostic events")
	// No default, for the same reason --prompt has none: an empty value means
	// "whatever the config says, else ask", and a flag defaulting to ask could
	// not be told apart from somebody typing it — which would leave `setup:` in
	// the config file unreachable.
	fl.StringVar(&f.setup, "setup", "", "the remote shell rc: ask, auto, never (default: your config, else ask)")
	fl.StringVar(&f.gate, "gate", "", "browser: ask before each site, or auto (default: your config)")
	fl.StringVar(&f.web, "web", "", "serve the board in a browser; bare, or an address like 127.0.0.1:8765")
	// Bare `--web` is the way people will write it, so it has to mean
	// something. pflag needs telling that the value is optional.
	fl.Lookup("web").NoOptDefVal = "on"
	// Opening it is the default. The URL carries a token, so it is long and
	// unmemorable by construction — and under the interface it lands in a log
	// you cannot select with the mouse, since the mouse belongs to the table.
	// Printing something nobody can copy and then not opening it is the worst
	// of both.
	fl.BoolVar(&f.webOpen, "web-open", true, "open the web board in your browser when it starts")
	fl.BoolVar(&f.noInstall, "no-install", false, "never upload the remote helper")
	fl.BoolVar(&f.takeOver, "take-over", false, "displace another devtun already attached to this host")
	fl.StringSliceVar(&f.only, "only", nil, "run only these services, e.g. tunnels,browser")
}

// registerConnection registers the flags for reaching a box, on whichever
// command needs them.
//
// They are a group of their own because the subcommands that connect —
// `install`, `doctor` — have to accept them *after* the subcommand name.
// `devtun doctor -i key -p 2222 bedev` is what a person types, and a diagnostic
// that rejects its own flags when somebody is already stuck is worse than no
// diagnostic.
func (f *upFlags) registerConnection(fl *pflag.FlagSet) {
	fl.StringVarP(&f.user, "user", "l", "", "remote username")
	fl.IntVarP(&f.port, "port", "p", 0, "SSH port")
	fl.StringArrayVarP(&f.identityFiles, "identity", "i", nil, "private key (repeatable; implies IdentitiesOnly, like ssh(1))")
	fl.StringVarP(&f.proxyJump, "jump", "J", "", "jump host")
	fl.StringVar(&f.authSock, "auth-sock", "", "SSH agent socket")
	fl.StringArrayVar(&f.knownHosts, "known-hosts", nil, "known_hosts file (repeatable)")
	fl.StringVar(&f.hostKeyMode, "host-key", "", "unknown host keys: ask, accept-new, yes, no")
	fl.DurationVar(&f.connectTimeout, "connect-timeout", 20*time.Second, "SSH connection timeout")
	fl.StringVar(&f.shimBinary, "shim-binary", "", "helper binary to upload to the remote")
	fl.StringVar(&f.opPath, "op", "", "path to the 1Password CLI")
}

// runUp is the whole of `devtun <host>`.
func runUp(ctx context.Context, f upFlags) error {
	if f.noColor || f.plain {
		ui.NoColor()
	}

	dest, connectOpts, err := resolveDestination(f)
	if err != nil {
		return err
	}

	store := hostcfg.OpenDefault()
	// A configuration file that would not parse read as empty. For a sort
	// order that is fine; for a file that may have carried deny rules it is
	// failing open, so stop rather than run on a policy we cannot vouch for.
	// Read the host's own file before the gate below. Host files load lazily,
	// so a check that ran first would be looking only at the global one — and
	// a malformed hosts/<host>.yaml would read as empty, taking its deny rules
	// with it, which is the exact failure the gate exists to prevent.
	store.LoadHost(dest.Label())
	if err := store.Err(); err != nil {
		return fmt.Errorf("refusing to start on a configuration devtun cannot read: %w", err)
	}
	defer func() {
		if err := store.Save(); err != nil {
			fmt.Fprintln(os.Stderr, ui.Warn.Render("devtun: could not save settings: "+err.Error()))
		}
	}()

	setupMode, err := setupMode(f, store)
	if err != nil {
		return err
	}

	// The interface is the default, because it is the thing devtun is: a board
	// of what is forwarded, what is open in your name, and what just happened.
	// The log is what you ask for when you want to pipe it, watch it in a
	// corner, or read it later — so it is a flag rather than the fallback.
	//
	// Anything that is not a terminal still gets machine-readable output
	// without being asked: a TUI written into a pipe is line noise.
	useTUI := wantsTUI(f, ui.IsTTY())

	backend := promptBackend(f, store, dest.Label())

	// The desk is what lets one question be answered from more than one place.
	// It is built whenever a board is, and only then: without a board there is
	// no second surface, and every approval goes exactly where it always did.
	var desk *approval.Desk
	if f.web != "" {
		desk = approval.New(approval.Options{})
	}

	bus := event.NewBus(historyLimit)
	services, tunnelSvc, err := buildServices(f, store, backend, useTUI, desk)
	if err != nil {
		return err
	}

	sess := session.New(session.Options{
		Connector:   session.NewSSHConnector(dest, connectOpts),
		Bus:         bus,
		Services:    services,
		Config:      store,
		Reconnect:   !f.noReconnect,
		AutoInstall: !f.noInstall,
		TakeOver:    f.takeOver,
		ShimBinary:  f.shimBinary,
		// A helper for the remote's platform is downloaded from this build's
		// own release when there is no other way to get one — which is the
		// ordinary case for anyone who installed from Homebrew and is pointing
		// devtun at a Linux box.
		FetchShim: (&release.Fetcher{
			Slug:    repoSlug,
			Version: buildinfo.Version(),
		}).Binary,
		Version:  buildinfo.Version(),
		Setup:    setupMode,
		AskSetup: askSetupOnTerminal,
	})

	if f.installOnly {
		return sess.Prepare(ctx)
	}

	// Where a changed prompt setting is put into effect. Under the interface
	// that is the interface's job, because it owns the modal; without one it is
	// this function, built here where the services and the desk both are.
	applier := &promptApplier{}
	if !useTUI {
		applier.set(func(b prompt.Backend) {
			installPrompter(b, services, desk)
		})
	}

	// The web interface runs *alongside* whichever interface owns the terminal,
	// rather than instead of it — and either can answer an approval, because
	// both are handed the same question off the same desk.
	var webURL string
	if f.web != "" {
		url, stop, err := serveWeb(ctx, f, bus, sess, tunnelSvc, services, dest.Label(), desk,
			store, backend, applier)
		if err != nil {
			return err
		}
		defer stop()
		webURL = url
	}

	if useTUI {
		return tui.Run(ctx, tui.Options{
			// The board is already running and needs to be able to move where
			// approvals appear, which only the interface can actually do.
			ShareApplyPrompt: applier.set,
			Session:          sess,
			Bus:              bus,
			Tunnels:          tunnelSvc,
			Services:         services,
			Host:             dest.Label(),
			Version:          buildinfo.Version(),
			Store:            store,
			Prompt:           backend,
			Approvals:        desk,
			WebURL:           webURL,
			NoDissolve:       f.noDissolve,
		})
	}
	return runHeadless(ctx, f, sess, bus, dest, webURL)
}

// serveWeb starts the browser interface and returns where it is.
//
// It returns the URL rather than announcing it, because *where* to say so
// differs: under the interface stdout belongs to Bubble Tea and a stray line
// there scrolls the frame — the bug that ate the header once already — while in
// log mode stderr is exactly right. The URL carries the token, so it goes where
// a person is looking and not into a log they may be piping to a file.
// promptApplier holds the function that puts a changed prompt setting into
// effect now rather than at the next connection.
//
// It exists because of an ordering problem rather than a design one: the board
// is started before the interface, and under `--tui --web` it is the interface
// that owns the modal a live change installs — which does not exist until its
// program does. So the board is handed this, and whoever can build the real
// function fills it in.
type promptApplier struct {
	mu    sync.Mutex
	apply func(prompt.Backend)
}

func (p *promptApplier) set(fn func(prompt.Backend)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.apply = fn
}

// Apply is a no-op before anything has been installed. A setting changed that
// early is still written and still takes effect on the next connection; what is
// missed is only the "now" part.
func (p *promptApplier) Apply(backend prompt.Backend) {
	p.mu.Lock()
	fn := p.apply
	p.mu.Unlock()
	if fn != nil {
		fn(backend)
	}
}

func serveWeb(
	ctx context.Context, f upFlags, bus *event.Bus, sess *session.Session,
	tunnelSvc *tunnels.Service, services []service.Service, label string, desk *approval.Desk,
	store *hostcfg.Store, backend prompt.Backend, applier *promptApplier,
) (string, func(), error) {
	addr := strings.TrimSpace(f.web)
	if addr == "on" || addr == "true" {
		addr = defaultWebAddr
	}
	server, err := web.New(web.Options{
		// An address named on the command line is honoured or reported; only
		// the default one gives way to a free port. This was written, promised
		// in the README, and never actually passed — so a named port moved
		// silently, which is the one thing it was supposed not to do.
		FixedAddr: addr != defaultWebAddr,
		Addr:      addr,
		Host:      label,
		Version:   buildinfo.Version(),
		Tunnels:   webTunnels(tunnelSvc),
		Services:  services,
		Bus:       bus,
		Status:    sess.Status,
		Retry:     sess.RetryNow,
		Approvals: desk,
		// The settings screen. Without these the board can list a session and
		// not configure it, which is the half of the interface that was
		// missing from it.
		Store:         storeOrNil(store),
		PromptNow:     func() prompt.Backend { return backend },
		ApplyPrompt:   applier.Apply,
		DialogChooser: prompt.DialogBackend,
	})
	if err != nil {
		return "", nil, err
	}

	// Bind before returning, so a port already in use is an error at startup
	// rather than a line in a log nobody is reading yet.
	ready := make(chan error, 1)
	webCtx, cancel := context.WithCancel(ctx)
	go func() { ready <- server.Run(webCtx) }()

	// Run fills in the URL as soon as it has bound; give it that moment.
	deadline := time.Now().Add(2 * time.Second)
	for server.URL() == "" {
		select {
		case err := <-ready:
			cancel()
			return "", nil, err
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			return "", nil, errors.New("the web interface did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f.webOpen {
		// Best effort, and quietly: a machine with no browser is a machine
		// where the URL in the log is the answer, not an error to report.
		go func() {
			openCtx, done := context.WithTimeout(ctx, 10*time.Second)
			defer done()
			_ = ui.OpenURL(openCtx, server.URL())
		}()
	}
	return server.URL(), cancel, nil
}

// defaultWebAddr is where a bare `--web` listens.
//
// A fixed port rather than one the kernel picks, so the board can be
// bookmarked and so a reload after a restart lands somewhere. It gives way
// rather than failing when something else already has it — a second devtun on
// the same machine is an ordinary thing to want, and refusing to start over a
// port number would be a poor trade for the convenience of a stable one.
const defaultWebAddr = "127.0.0.1:8422"

// webTunnels adapts the tunnels service for the web interface, and returns a
// nil interface rather than a typed nil pointer when there is none.
func webTunnels(svc *tunnels.Service) web.Tunnels {
	if svc == nil {
		return nil
	}
	return webTunnelAdapter{svc: svc}
}

// webTunnelAdapter joins the two halves of the tunnels service, exactly as the
// interface's own adapter does: the Manager owns the live table and does not
// exist until the first connection, while the Service owns the preferences.
type webTunnelAdapter struct{ svc *tunnels.Service }

func (a webTunnelAdapter) States() []tunnels.State {
	if mgr := a.svc.Manager(); mgr != nil {
		return mgr.States()
	}
	return nil
}

func (a webTunnelAdapter) SetMode(port int, mode tunnels.Mode) tunnels.Mode {
	if mgr := a.svc.Manager(); mgr != nil {
		return mgr.SetMode(port, mode)
	}
	return mode
}

func (a webTunnelAdapter) SetScheme(port int, scheme tunnels.Scheme) tunnels.Scheme {
	if mgr := a.svc.Manager(); mgr != nil {
		return mgr.SetScheme(port, scheme)
	}
	return scheme
}

func (a webTunnelAdapter) SetLabel(port int, label string) error {
	mgr := a.svc.Manager()
	if mgr == nil {
		return errors.New("no connection yet")
	}
	return mgr.SetLabel(port, label)
}

func (a webTunnelAdapter) SetLocalPort(port, local int) error {
	mgr := a.svc.Manager()
	if mgr == nil {
		return errors.New("no connection yet")
	}
	return mgr.SetLocalPort(port, local)
}

func (a webTunnelAdapter) Policy() tunnels.Policy {
	if mgr := a.svc.Manager(); mgr != nil {
		return mgr.Policy()
	}
	return tunnels.Policy{}
}

func (a webTunnelAdapter) SetPolicy(p tunnels.Policy) {
	if mgr := a.svc.Manager(); mgr != nil {
		mgr.SetPolicy(p)
	}
}

func (a webTunnelAdapter) Hidden() int {
	if mgr := a.svc.Manager(); mgr != nil {
		return mgr.Hidden()
	}
	return 0
}

func (a webTunnelAdapter) ViewPrefs() tunnels.ViewPrefs     { return a.svc.ViewPrefs() }
func (a webTunnelAdapter) SetViewPrefs(p tunnels.ViewPrefs) { a.svc.SetViewPrefs(p) }

// wantsTUI decides between the interface and a stream of events.
//
// It takes isTTY rather than asking, so the decision is testable without a
// terminal — which is the only way to check the rule that matters here: a TUI
// written into a pipe is line noise, and no flag may override that.
func wantsTUI(f upFlags, isTTY bool) bool {
	if !isTTY {
		return false
	}
	// A board and an interface are two implementations of one surface, and
	// running both is redundant rather than complementary. The interface costs
	// the alt screen, the mouse and your scrollback — worth paying to interact
	// there, worth nothing if you are interacting in a browser. A log is a
	// different thing entirely: a record you can scroll, select, grep and pipe,
	// which is exactly what you want beside a board and cannot get from a
	// second copy of it.
	//
	// `--tui` still forces it, for the two-monitor case, because the command
	// line is about this run and must always be able to win.
	if f.web != "" && !f.tui {
		return false
	}
	return !f.logMode && !f.jsonOut && !f.plain
}

// runHeadless is log mode: the events go to a writer and the session owns the
// process until it is interrupted.
func runHeadless(ctx context.Context, f upFlags, sess *session.Session, bus *event.Bus, dest *sshx.Destination, webURL string) error {
	var renderer render.Renderer
	switch {
	case f.jsonOut || (!ui.IsTTY() && !f.plain):
		renderer = render.NewJSON(os.Stdout)
	default:
		renderer = render.NewLog(os.Stdout, f.verbose)
	}
	bus.Subscribe(renderer.Event)

	if !f.jsonOut {
		fmt.Fprintln(os.Stderr, ui.Banner.Render("devtun")+" "+ui.Muted.Render("connecting to "+dest.String()+"…"))
	}
	// To stderr and after the renderer is attached: the URL carries the token,
	// so it belongs where a person is looking rather than in a log they may be
	// piping to a file, and announcing it before anything is subscribed is how
	// it went missing the first time.
	if webURL != "" {
		// "the board is at", not "also at". In log mode the board is the place
		// you do things and this terminal is the record, so the URL is the way
		// in rather than a footnote.
		fmt.Fprintln(os.Stderr, ui.Banner.Render("devtun")+" "+ui.Muted.Render("the board is at ")+ui.Host.Render(webURL))
	}
	return sess.Run(ctx)
}

// resolveDestination turns the typed destination and the transport flags into
// something Dial can use.
func resolveDestination(f upFlags) (*sshx.Destination, sshx.Options, error) {
	sshCfg, err := sshx.LoadConfig()
	if err != nil {
		return nil, sshx.Options{}, err
	}
	dest, err := sshx.Resolve(f.destination, sshCfg, sshx.Overrides{
		User:          f.user,
		Port:          f.port,
		IdentityFiles: f.identityFiles,
		ProxyJump:     f.proxyJump,
	})
	if err != nil {
		return nil, sshx.Options{}, err
	}

	opts := sshx.Options{
		Config:          sshCfg,
		AuthSock:        f.authSock,
		KnownHostsFiles: f.knownHosts,
		ConnectTimeout:  f.connectTimeout,
		ClientVersion:   buildinfo.UserAgent(),
		Wait:            f.wait,
	}
	if f.hostKeyMode != "" {
		opts.HostKeyMode = sshx.ParseHostKeyMode(f.hostKeyMode)
	}
	// Questions can only be asked while a terminal is still ours, which is
	// before any interface takes the screen. The session drops this prompter
	// once the first connection is made.
	if ui.IsInteractive() {
		opts.Prompter = sshx.NewTerminalPrompter(os.Stdin, os.Stderr)
	}
	return dest, opts, nil
}

// buildServices assembles the service registry in the order they are attached.
//
// Tunnels comes first because the browser bridge resolves ports through it, and
// because it is the one that needs nothing on the remote box: if everything
// else fails, forwarding still works, which is very often why devtun was run.
func buildServices(
	f upFlags, store *hostcfg.Store, backend prompt.Backend, useTUI bool, desk *approval.Desk,
) ([]service.Service, *tunnels.Service, error) {
	policy, err := tunnelPolicy(f)
	if err != nil {
		return nil, nil, err
	}

	hide, err := tunnels.ParsePortSet(store.Global().Hide.Spec())
	if err != nil {
		return nil, nil, fmt.Errorf("the `hide` list in your config: %w", err)
	}

	tunnelSvc := tunnels.New(tunnels.Options{
		Policy:     policy,
		Bind:       f.bind,
		SamePort:   f.samePort,
		Interval:   f.interval,
		GlobalHide: hide,
	})

	prompter, err := buildPrompter(backend, useTUI)
	if err != nil {
		return nil, nil, err
	}
	// Outside whatever the setting chose, not instead of it: the terminal form
	// or the desktop dialog is still where somebody at this machine answers,
	// and the desk is what lets the board answer the same question. Wrapping
	// outside is also what keeps `prompt: deny` meaning deny — a session told
	// to answer nothing must not become answerable by opening a browser tab.
	//
	// Under the interface this is nil and the wrapping happens in tui.Run
	// instead, because the modal cannot exist until its program does.
	if desk != nil && prompter != nil && backend != prompt.BackendDeny {
		desk.SetPrompter(prompter)
		prompter = desk
	}
	opRules, err := globalRules(store, "1password")
	if err != nil {
		return nil, nil, err
	}
	agentRules, err := globalRules(store, "ssh-agent")
	if err != nil {
		return nil, nil, err
	}
	browserRules, err := globalRules(store, "browser")
	if err != nil {
		return nil, nil, err
	}
	accounts, err := globalAccounts(store, f.account)
	if err != nil {
		return nil, nil, err
	}
	opSvc := onepassword.New(onepassword.Options{
		Rules:         opRules,
		Accounts:      accounts,
		DefaultTTL:    f.ttl,
		PromptTimeout: f.promptTimeout,
		CacheTTL:      cacheTTL(f),
		Prompter:      prompter,
		OpPath:        f.opPath,
	})

	// The agent broker is enabled like every other service, and gated the same
	// way: nothing is signed without an approval, and nothing happens at all
	// until SSH_AUTH_SOCK points at it — a line the user has to accept. Being
	// the odd service out and defaulting to off would not add safety, it would
	// only add a flag to discover after `git push` has already failed.
	agentSvc := sshagent.New(sshagent.Options{
		Rules:         agentRules,
		DefaultTTL:    f.ttl,
		PromptTimeout: f.promptTimeout,
		AuthSock:      f.authSock,
		// Defaulted, not just passed through: without a known_hosts file the
		// agent can only name a destination by its host-key fingerprint, and
		// "sign for SHA256:BIFkz…" is not a question anybody can answer.
		KnownHosts: knownHostsFiles(f),
	})

	// The browser can be gated, and is not by default. Its dial is the service
	// itself — on or off, per host — because a window opening is usually the
	// direct consequence of a command somebody just typed, and a prompt for
	// each one is a prompt that gets answered without being read. `gate: ask`
	// is there for anyone who wants a say in each one; the subject is the site,
	// so one "always" answer covers the dozen redirects of a login flow.
	browserSvc := browser.New(browser.Options{
		// The service, not its Manager: the Manager does not exist until the
		// first connection, so capturing it here would capture nil.
		Tunnels:       tunnelSvc,
		Open:          ui.OpenURL,
		Bind:          f.bind,
		Rules:         browserRules,
		DefaultTTL:    f.ttl,
		PromptTimeout: f.promptTimeout,
		Prompter:      prompter,
		Ask:           gateDefault(f),
	})

	// The GPG bridge is registered like the rest and starts off: it is the one
	// service that changes how other tools on the remote behave, so a host has
	// to ask for it. Registered rather than omitted, because a service you
	// cannot see on the Services tab is one nobody ever turns on.
	gpgSvc := gpgagent.New(gpgagent.Options{})

	all := []service.Service{tunnelSvc, opSvc, agentSvc, gpgSvc, browserSvc}
	if f.noAgent {
		all = []service.Service{tunnelSvc, opSvc, gpgSvc, browserSvc}
	}
	return filterServices(all, f.only), tunnelSvc, nil
}

// gateDefault turns --gate into the tri-state the services take: nil means
// "whatever the config says, else the service's own default".
func gateDefault(f upFlags) *bool {
	switch strings.TrimSpace(f.gate) {
	case "ask":
		yes := true
		return &yes
	case "auto":
		no := false
		return &no
	default:
		return nil
	}
}

// filterServices applies --only, which is how you run devtun as just one of
// the tools it replaces.
func filterServices(all []service.Service, only []string) []service.Service {
	if len(only) == 0 {
		return all
	}
	wanted := make(map[string]bool, len(only))
	for _, name := range only {
		wanted[strings.TrimSpace(name)] = true
	}
	var out []service.Service
	for _, svc := range all {
		if wanted[svc.Meta().ID] {
			out = append(out, svc)
		}
	}
	return out
}

func tunnelPolicy(f upFlags) (tunnels.Policy, error) {
	policy := tunnels.DefaultPolicy()
	policy.MinPort, policy.MaxPort = f.minPort, f.maxPort

	if f.minPort < 1 || f.maxPort > 65535 || f.minPort > f.maxPort {
		return policy, fmt.Errorf("--min-port %d and --max-port %d do not describe a range within 1–65535", f.minPort, f.maxPort)
	}
	var err error
	if f.include != "" {
		if policy.Include, err = tunnels.ParsePortSet(f.include); err != nil {
			return policy, fmt.Errorf("--include: %w", err)
		}
	}
	if f.exclude != "" {
		if policy.Exclude, err = tunnels.ParsePortSet(f.exclude); err != nil {
			return policy, fmt.Errorf("--exclude: %w", err)
		}
	}
	if policy.RemoteBind, err = tunnels.ParseRemoteBind(f.remoteBind); err != nil {
		return policy, err
	}
	if f.interval < 200*time.Millisecond {
		return policy, errors.New("--interval below 200ms would spend more time scanning than working")
	}
	return policy, nil
}

// setupMode resolves whether devtun offers to edit the remote shell rc: the
// flag, then the global config, then ask.
//
// It reads the config for the same reason --prompt does. "Never touch a shell
// rc" is a standing preference about how you work, not a decision to retype on
// every connection — and a setting nothing reads is a setting the Config tab
// would be lying about.
func setupMode(f upFlags, store *hostcfg.Store) (session.SetupMode, error) {
	if v := strings.TrimSpace(f.setup); v != "" {
		return session.ParseSetupMode(v)
	}
	return session.ParseSetupMode(strings.TrimSpace(store.Global().Setup))
}

// promptBackend resolves how approvals are asked for.
//
// The flag wins, then the host file, then the global file, then auto. It is a
// config setting and not only a flag because it describes the machine you sit
// at — a desktop with zenity installed, or a laptop where devtun always runs in
// a window behind the browser — and a setting you must remember to type is one
// you will be missing on the day it mattered.
func promptBackend(f upFlags, store *hostcfg.Store, label string) prompt.Backend {
	if v := strings.TrimSpace(f.promptBackend); v != "" {
		return prompt.Backend(v)
	}
	return prompt.Backend(store.Prompt(label, string(prompt.BackendAuto)))
}

// buildPrompter chooses how approvals are asked for outside the interface.
//
// Under the TUI the question is a modal inside it — a huh form in the terminal
// would draw over the thing it is asking about — so this returns nil there and
// lets the interface install its own. The exception is a desktop dialog, which
// the interface handles itself: it is a separate window and does not touch the
// terminal at all, and wanting one is precisely the case where devtun's window
// is not the one you are looking at.
func buildPrompter(backend prompt.Backend, useTUI bool) (prompt.Prompter, error) {
	if useTUI {
		// The value still has to be checked here. Under the interface nothing
		// else parses it, and a typo in a config file that surfaced only when
		// a secret was asked for would surface as a refusal nobody understood.
		if !backend.Valid() {
			return nil, fmt.Errorf("unknown prompt backend %q (want auto, tui, dialog or deny)", backend)
		}
		return nil, nil
	}
	if !ui.IsInteractive() && (backend == prompt.BackendAuto || backend == "") {
		// Nobody can answer, and the zero value of a decision is no.
		backend = prompt.BackendDeny
	}
	return prompt.New(backend)
}

// knownHostsFiles are the files consulted to put a name on a signing
// destination. The flag wins when given; otherwise the usual places, which is
// where a person's hosts actually are.
func knownHostsFiles(f upFlags) []string {
	if len(f.knownHosts) > 0 {
		return f.knownHosts
	}
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out,
			filepath.Join(home, ".ssh", "known_hosts"),
			filepath.Join(home, ".ssh", "known_hosts2"),
		)
	}
	return append(out, "/etc/ssh/ssh_known_hosts")
}

func cacheTTL(f upFlags) time.Duration {
	if !f.cache {
		return 0
	}
	if f.cacheTTL > 0 {
		return f.cacheTTL
	}
	// Zero here would mean "no cache", so fall back to the grant lifetime,
	// which is the bound the cache is meant to respect anyway.
	return 5 * time.Minute
}

// globalRules reads the deny-everywhere rules from the top-level config.
//
// A failure here is reported rather than swallowed: rules include denies, so
// carrying on without them would silently widen access, which is the one
// direction a config error must never fail in.
// globalRules reads one service's global rules.
//
// One service's. This used to read the 1Password section once and hand the same
// slice to all three brokers, which was wrong in both directions and quietly
// so: a global `1password: rules: [{subject: "**", action: deny}]` — the very
// shape the README recommends — also refused every SSH signature and every
// browser open, while `ssh-agent:` and `browser:` rules written in the global
// file were read by nobody. The Access tab then labelled all of it as though
// each broker had its own.
func globalRules(store *hostcfg.Store, serviceID string) ([]authz.Rule, error) {
	var rules []authz.Rule
	if _, err := store.GlobalFor(serviceID).Get("rules", &rules); err != nil {
		return nil, fmt.Errorf("reading the global %s rules: %w", serviceID, err)
	}
	return rules, nil
}

// globalAccounts reads vault-to-account routing. A secret reference names a
// vault but not an account, so with two accounts signed in `op` resolves an
// ambiguous vault against whichever is currently the default and half your
// references quietly fail. A vault belongs to exactly one account, which makes
// the vault the right thing to route on.
func globalAccounts(store *hostcfg.Store, account string) (onepassword.Accounts, error) {
	var accounts onepassword.Accounts
	if _, err := store.GlobalFor("1password").Get("accounts", &accounts); err != nil {
		return accounts, fmt.Errorf("reading 1Password account routing: %w", err)
	}
	// --account sets the default; per-vault routing still wins.
	if account != "" {
		accounts.Default = account
	}
	return accounts, nil
}

// installPrompter puts a prompter on every service that asks a human, found by
// interface rather than by name.
//
// That list was once written down by hand and the SSH agent broker was not on
// it, so every signature was refused in the same instant it was requested. A
// service built with no prompter refuses by construction, which is the right
// default and exactly why forgetting to install one is silent.
func installPrompter(backend prompt.Backend, services []service.Service, desk *approval.Desk) {
	prompter, err := buildPrompter(backend, false)
	if err != nil || prompter == nil {
		return
	}
	// The desk wraps whatever the setting chose rather than replacing it, so
	// `prompt: deny` still denies: a session told to answer nothing must not
	// become answerable by opening a browser tab.
	if desk != nil && backend != prompt.BackendDeny {
		desk.SetPrompter(prompter)
		prompter = desk
	}
	for _, svc := range services {
		if p, ok := svc.(interface{ SetPrompter(prompt.Prompter) }); ok {
			p.SetPrompter(prompter)
		}
	}
}

// storeOrNil hands the board a real store or nothing at all.
//
// A typed nil in an interface is not nil, and the settings screen tests the
// store to decide whether anything can be saved — so a --no-config run has to
// arrive as an untyped nil or every write would be attempted and panic.
func storeOrNil(store *hostcfg.Store) settings.Store {
	if store == nil {
		return nil
	}
	return store
}
