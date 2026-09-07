package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	// web, when set, serves the board over HTTP as well. "on" picks a port.
	web string

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
	fl.StringVar(&f.setup, "setup", "ask", "the remote shell rc: ask, auto, never")
	fl.StringVar(&f.gate, "gate", "", "browser: ask before each site, or auto (default: your config)")
	fl.StringVar(&f.web, "web", "", "also serve the board in a browser (\"on\", or an address like 127.0.0.1:8765)")
	fl.BoolVar(&f.noInstall, "no-install", false, "never upload the remote helper")
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

	setupMode, err := session.ParseSetupMode(f.setup)
	if err != nil {
		return err
	}

	dest, connectOpts, err := resolveDestination(f)
	if err != nil {
		return err
	}

	store := hostcfg.OpenDefault()
	// A configuration file that would not parse read as empty. For a sort
	// order that is fine; for a file that may have carried deny rules it is
	// failing open, so stop rather than run on a policy we cannot vouch for.
	if err := store.Err(); err != nil {
		return fmt.Errorf("refusing to start on a configuration devtun cannot read: %w", err)
	}
	defer func() {
		if err := store.Save(); err != nil {
			fmt.Fprintln(os.Stderr, ui.Warn.Render("devtun: could not save settings: "+err.Error()))
		}
	}()

	// The interface is the default, because it is the thing devtun is: a board
	// of what is forwarded, what is open in your name, and what just happened.
	// The log is what you ask for when you want to pipe it, watch it in a
	// corner, or read it later — so it is a flag rather than the fallback.
	//
	// Anything that is not a terminal still gets machine-readable output
	// without being asked: a TUI written into a pipe is line noise.
	useTUI := wantsTUI(f, ui.IsTTY())

	backend := promptBackend(f, store, dest.Label())

	bus := event.NewBus(historyLimit)
	services, tunnelSvc, err := buildServices(f, store, backend, useTUI)
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

	// The web interface runs *alongside* whichever interface owns the terminal,
	// rather than instead of it. Approvals stay where they already are — a page
	// that could approve would have to be right about tokens, origins and
	// rebinding all at once, and the cost of being subtly wrong there is
	// somebody's secret.
	var webURL string
	if f.web != "" {
		url, stop, err := serveWeb(ctx, f, bus, sess, tunnelSvc, services, dest.Label())
		if err != nil {
			return err
		}
		defer stop()
		webURL = url
	}

	if useTUI {
		return tui.Run(ctx, tui.Options{
			Session:    sess,
			Bus:        bus,
			Tunnels:    tunnelSvc,
			Services:   services,
			Host:       dest.Label(),
			Version:    buildinfo.Version(),
			Store:      store,
			Prompt:     backend,
			WebURL:     webURL,
			NoDissolve: f.noDissolve,
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
func serveWeb(
	ctx context.Context, f upFlags, bus *event.Bus, sess *session.Session,
	tunnelSvc *tunnels.Service, services []service.Service, label string,
) (string, func(), error) {
	addr := strings.TrimSpace(f.web)
	if addr == "on" || addr == "true" {
		addr = ""
	}
	server, err := web.New(web.Options{
		Addr:     addr,
		Host:     label,
		Version:  buildinfo.Version(),
		Tunnels:  webTunnels(tunnelSvc),
		Services: services,
		Bus:      bus,
		Status:   sess.Status,
		Retry:    sess.RetryNow,
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
	return server.URL(), cancel, nil
}

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
		fmt.Fprintln(os.Stderr, ui.Banner.Render("devtun")+" "+ui.Muted.Render("the board is also at ")+ui.Host.Render(webURL))
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
func buildServices(f upFlags, store *hostcfg.Store, backend prompt.Backend, useTUI bool) ([]service.Service, *tunnels.Service, error) {
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
	rules, err := globalRules(store)
	if err != nil {
		return nil, nil, err
	}
	accounts, err := globalAccounts(store, f.account)
	if err != nil {
		return nil, nil, err
	}
	opSvc := onepassword.New(onepassword.Options{
		Rules:         rules,
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
		Rules:         rules,
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
		Rules:         rules,
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
func globalRules(store *hostcfg.Store) ([]authz.Rule, error) {
	var rules []authz.Rule
	if _, err := store.GlobalFor("1password").Get("rules", &rules); err != nil {
		return nil, fmt.Errorf("reading global 1Password rules: %w", err)
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
