// Package browser sends URLs the remote box wants opened to the browser you
// are actually sitting in front of.
//
// `vite --open`, `gh auth login`, `wrangler login`, `jupyter notebook` — all of
// them try to open a browser, and on a dev box that means either nothing at all
// or a hopeful "Couldn't find a suitable web browser". This service shadows the
// opener commands with the devtun shim, so those tools keep doing exactly what
// they always did and the window opens on the right machine.
//
// The interesting part is not the transport, it is the rewriting: a URL naming
// a port on the remote's loopback has to be turned into the port that tunnel
// actually landed on locally, and the cases where that is not possible have to
// fail loudly rather than pointing you at whatever *your* machine runs there.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
	"github.com/jclement/devtun/internal/tunnels"
)

var (
	_ service.Service       = (*Service)(nil)
	_ service.SocketHandler = (*Service)(nil)
	_ service.Instance      = (*instance)(nil)
)

// loopback is the set of hosts that mean "this machine" — which, in a URL
// printed by a process on the dev box, means the dev box.
var loopback = map[string]bool{
	"localhost": true, "127.0.0.1": true, "::1": true,
	"0.0.0.0": true, "::": true, "[::1]": true,
}

// gateKey is where this service's "ask or open" preference lives in the host's
// config document.
const gateKey = "gate"

const (
	// openTimeout bounds handing a URL to the platform opener.
	openTimeout = 6 * time.Second
	// awaitTunnel is how long a request waits for its tunnel to appear. A
	// dev server prints its URL the instant it binds, which is usually before
	// the next remote scan has noticed the port at all.
	awaitTunnel = 5 * time.Second
	awaitPoll   = 250 * time.Millisecond
)

// Tunnels is the slice of the tunnels service this needs. Declaring it here
// rather than taking the concrete type keeps the rewriting testable without a
// manager, an allocator or a network.
type Tunnels interface {
	States() []tunnels.State
	TryLocalPort(remotePort, local int) error
	ForwardNow(remotePort int) error
}

// Options configure the service.
type Options struct {
	// Tunnels resolves a remote port to the local one it landed on. Without it
	// only absolute public URLs can be opened.
	Tunnels Tunnels
	// Open hands a URL to the local platform opener.
	Open func(ctx context.Context, rawURL string) error
	// Bind is the local address tunnels listen on, used to build the rewritten
	// URL.
	Bind string
	// Poll is the retry interval while waiting for a tunnel.
	Poll time.Duration
	// Wait is how long a request waits for its tunnel to appear before giving
	// up. It is generous by default because a dev server prints its URL the
	// instant it binds, which is usually before the next remote scan has
	// noticed the port at all — so the common case is not "this port is not
	// forwarded" but "ask again in a moment".
	Wait time.Duration

	// Rules are the global policy rules, applying to every host. The rules
	// devtun writes when a prompt is answered "always" are per-host and live in
	// the host's own config document.
	Rules []authz.Rule
	// DefaultTTL is how long a "for a while" grant lasts. Zero means five
	// minutes.
	DefaultTTL time.Duration
	// PromptTimeout bounds how long an open request waits for a human. Zero
	// means two minutes; the tool on the other end is blocked meanwhile, so it
	// wants to be short rather than generous.
	PromptTimeout time.Duration
	// Prompter asks the human. Nil means nobody can be asked, which refuses
	// everything a rule does not already allow.
	Prompter prompt.Prompter
	// Ask is the default answer to "must a person approve each site", used
	// when neither the host nor the global config says.
	//
	// It is false. The dial for the browser bridge is the service itself —
	// on or off, per host — and asking about every window on top of that is a
	// prompt for something that is usually a direct consequence of a command
	// you just typed. `gate: ask` in the config turns it on for anyone who
	// wants a say in each one; the credential brokers, where a decision buys
	// something a rule cannot express, ask by construction.
	Ask *bool
}

// Service is the browser-bridge capability.
type Service struct {
	opts Options
	gate *authz.Gate

	mu     sync.Mutex
	events event.Sink
	label  string
	// ask is this host's answer to "gate each site", resolved on attach.
	ask bool
}

// New returns a browser service.
func New(opts Options) *Service {
	if opts.Poll <= 0 {
		opts.Poll = awaitPoll
	}
	if opts.Wait <= 0 {
		opts.Wait = awaitTunnel
	}
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}
	return &Service{
		opts: opts,
		gate: authz.NewGate(authz.Config{
			DefaultTTL:    opts.DefaultTTL,
			PromptTimeout: opts.PromptTimeout,
			Rules:         opts.Rules,
		}, opts.Prompter),
		events: event.Discard,
		ask:    askDefault(opts.Ask),
	}
}

// askDefault resolves the built-in default for gating, which is off.
func askDefault(configured *bool) bool {
	if configured != nil {
		return *configured
	}
	return false
}

// SetPrompter replaces how approvals are asked for. See authz.Gate.
func (s *Service) SetPrompter(p prompt.Prompter) { s.gate.SetPrompter(p) }

// The rules surface the interface's Access tab drives. The browser never sees
// a secret, so it has nothing cached to purge and reports one number.
func (s *Service) Rules() []authz.Rule       { return s.gate.Rules() }
func (s *Service) GlobalRules() []authz.Rule { return s.gate.GlobalRules() }
func (s *Service) Revoke(index int) error    { return s.gate.Revoke(index) }
func (s *Service) Deny(index int) error      { return s.gate.Deny(index) }
func (s *Service) Grants() []authz.Grant     { return s.gate.Grants() }
func (s *Service) Forget() int               { return s.gate.ForgetGrants() }

func (s *Service) RevokeGrant(host, subject string) bool {
	return s.gate.RevokeGrant(host, subject)
}

// sink returns where to report, which is whichever host is attached now.
func (s *Service) sink() (event.Sink, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events, s.label
}

// Meta identifies the service.
func (s *Service) Meta() service.Meta {
	return service.Meta{
		ID: "browser", Title: "Browser", Glyph: "◱", Class: event.Network,
		Short: "open URLs from the remote box in your local browser",
	}
}

// Probe reports whether the bridge can work here.
//
// It needs nothing on the remote but the shim, which the session installs, so
// the only real question is whether anything can open a URL on this end.
func (s *Service) Probe(context.Context, service.Host) service.Support {
	if s.opts.Open == nil {
		return service.Unsupported("no way to open a browser on this machine")
	}
	return service.Supported()
}

// Attach binds the service to a connection. There is nothing to set up: the
// shim and the socket are the session's business, and requests arrive through
// HandleConn.
func (s *Service) Attach(_ context.Context, h service.Host) (service.Instance, error) {
	if err := s.gate.Adopt(h.Label(), h.Config(), "browser"); err != nil {
		return nil, err
	}
	// Get, not GetLocal: `gate` is a preference, and a preference you set once
	// globally should apply to every host that has not said otherwise. Rules
	// are the opposite and are read with GetLocal, inside the gate.
	ask := askDefault(s.opts.Ask)
	var mode string
	if ok, err := h.Config().Get(gateKey, &mode); ok && err == nil {
		ask = mode == "ask"
	}

	s.mu.Lock()
	s.events, s.label, s.ask = h.Events(), h.Label(), ask
	s.mu.Unlock()
	return &instance{}, nil
}

// SetupLines reports what the remote shell still needs. The PATH entry is the
// session's own line and is reported there; the openers are symlinks inside it,
// so once PATH is right there is nothing more to say.
func (s *Service) SetupLines(service.Host) []string { return nil }

type instance struct{}

func (i *instance) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (i *instance) Close() error                  { return nil }

// openRequest is what the shim sends. One request, one reply, one connection.
//
// This and openResponse are one of TWO spellings of a single wire format; the
// remote half is in internal/shim/wire.go and the two must change together. The
// JSON tags are the contract.
type openRequest struct {
	URL string `json:"url"`
}

type openResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// HandleConn serves one open request.
func (s *Service) HandleConn(ctx context.Context, conn net.Conn, caller service.Caller) error {
	defer func() { _ = conn.Close() }()

	var request openRequest
	if err := shim.ReadFrame(conn, &request); err != nil {
		return fmt.Errorf("reading the open request: %w", err)
	}

	events, label := s.sink()
	// The URL is echoed back in the event text either way, so it is sanitised
	// before it can reach a terminal. localize parses the original.
	shown := event.SanitizeTo(request.URL, 200)

	// Ask before doing any of the work. A refused request should not spend five
	// seconds waiting for a tunnel it is never going to open, and the question
	// is about the site as it was asked for rather than the rewritten address —
	// "bedev wants to open github.com" is a sentence somebody can answer.
	err := s.approve(ctx, label, request.URL, caller, events)

	var target string
	if err == nil {
		target, err = s.localize(ctx, request.URL)
	}
	if err == nil {
		openCtx, cancel := context.WithTimeout(ctx, openTimeout)
		err = s.opts.Open(openCtx, target)
		cancel()
	}

	// A browser window appearing on your laptop because a process on another
	// machine asked for it is exactly the kind of thing that should never be a
	// surprise. Until now this service was the only one that did its work in
	// silence, which made it the only one you could not account for afterwards.
	switch {
	case err != nil:
		events.Emit(event.Event{
			Kind: "refused", Class: event.Network, Level: event.Warn,
			Text:   fmt.Sprintf("did not open %s for %s: %v", shown, callerName(caller), err),
			Fields: []any{"url", shown, "caller", caller.Program},
		})
	default:
		events.Emit(event.Event{
			Kind: "opened", Class: event.Network, Level: event.Info,
			Text:   fmt.Sprintf("opened %s for %s on %s", target, callerName(caller), label),
			Fields: []any{"url", target, "requested", shown, "caller", caller.Program},
		})
	}

	response := openResponse{OK: err == nil}
	if err != nil {
		response.Error = err.Error()
	}
	return shim.WriteFrame(conn, response)
}

// approve puts the site in front of a human, unless policy has already decided
// or this host is configured not to ask.
//
// The subject is the site, not the URL: a grant on "github.com" covers the
// dozen redirects an OAuth flow makes, where a grant on one URL would ask again
// at each of them and teach the only lesson a security prompt must never teach
// — that the way to make it stop is to keep saying yes.
func (s *Service) approve(
	ctx context.Context, label, raw string, caller service.Caller, events event.Sink,
) error {
	s.mu.Lock()
	ask := s.ask
	s.mu.Unlock()
	if !ask {
		return nil
	}

	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("not a URL: %q", raw)
	}
	subject := siteOf(parsed)

	asked := s.gate.Authorize(ctx, prompt.Request{
		Host:    label,
		Subject: subject,
		// "site", so the menu offers "Yes, this site — 5m" rather than
		// describing a secret that is not involved.
		Noun: "site",
		Rows: []prompt.Row{
			{Label: "url", Value: event.SanitizeTo(raw, 200)},
			{Label: "caller", Value: callerName(caller)},
		},
	})
	if asked.Note != "" {
		events.Emit(event.Event{
			Kind: "rule", Class: event.Security, Level: event.Info, Text: asked.Note,
		})
	}
	if asked.Err != nil {
		events.Emit(event.Event{
			Kind: "rule-failed", Class: event.Security, Level: event.Warn,
			Text: "the decision stands but could not be saved: " + asked.Err.Error(),
		})
	}
	if !asked.Allowed {
		return fmt.Errorf("refused: %s", asked.Reason)
	}
	return nil
}

// siteOf names what is being decided.
//
// A loopback URL is one of the dev box's own servers, so the port is the
// identifying part and belongs in the subject: approving "localhost:3000" for
// the afternoon should not also approve whatever else that box starts. A public
// URL is identified by its host, and a non-default port is part of that.
func siteOf(u *url.URL) string {
	host := strings.ToLower(strings.Trim(u.Hostname(), "[]"))
	if isLoopbackHost(host) {
		return fmt.Sprintf("localhost:%d", portOf(u))
	}
	if port := u.Port(); port != "" && portOf(u) != defaultPort(u.Scheme) {
		return host + ":" + port
	}
	return host
}

// defaultPort is the port a scheme implies.
func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// localize rewrites a URL printed on the remote box into one that works here.
//
// The rules, and why each exists:
//   - a public URL — an OAuth consent screen — is opened unchanged;
//   - a loopback URL is rewritten to wherever that tunnel actually landed;
//   - a port that policy is skipping is forwarded anyway, because naming a
//     port is more specific than a filter the user set in general;
//   - a login callback on a remapped port is a broken redirect, so the
//     original local port is reclaimed when it happens to be free;
//   - a loopback port with no tunnel at all is refused, rather than pointed at
//     whatever this machine is running there. Opening the wrong service is far
//     worse than opening nothing, because it looks like it worked.
func (s *Service) localize(ctx context.Context, raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("not a URL: %q", raw)
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("refusing to open a %q URL", parsed.Scheme)
	}
	if !isLoopbackHost(parsed.Hostname()) {
		return parsed.String(), nil
	}
	if s.opts.Tunnels == nil {
		return "", errors.New("no tunnels are being forwarded, so there is nothing to point this at")
	}

	remotePort := portOf(parsed)
	state, ok := s.await(ctx, remotePort)
	if !ok {
		return "", fmt.Errorf("port %d is not forwarded from this host", remotePort)
	}

	local := state.LocalPort
	// A redirect target that has moved port is a broken login flow, so take
	// the matching number back when nothing else holds it.
	if state.Remapped {
		if err := s.opts.Tunnels.TryLocalPort(remotePort, remotePort); err == nil {
			local = remotePort
		}
	}
	parsed.Host = net.JoinHostPort("localhost", strconv.Itoa(local))
	return parsed.String(), nil
}

// await waits for a tunnel on remotePort, asking for one if policy is skipping
// it. A dev server prints its URL the moment it binds, which is normally before
// the next remote scan has even run.
func (s *Service) await(ctx context.Context, remotePort int) (tunnels.State, bool) {
	deadline := time.Now().Add(s.opts.Wait)
	asked := false

	for {
		for _, state := range s.opts.Tunnels.States() {
			if state.RemotePort != remotePort {
				continue
			}
			if state.LocalPort != 0 {
				return state, true
			}
			// Naming a port is more specific than any filter, so override the
			// skip — but only once, or a refusal becomes a busy loop.
			if !asked {
				asked = true
				_ = s.opts.Tunnels.ForwardNow(remotePort)
			}
		}
		if !time.Now().Before(deadline) {
			return tunnels.State{}, false
		}
		select {
		case <-ctx.Done():
			return tunnels.State{}, false
		case <-time.After(s.opts.Poll):
		}
	}
}

// callerName renders who asked, for a message and never for a decision.
func callerName(c service.Caller) string {
	if c.Program != "" {
		return c.Program
	}
	if c.User != "" {
		return c.User
	}
	return "something on the remote"
}

// isLoopbackHost reports whether a hostname means "this machine".
//
// A literal lookup was not enough. DNS is case-insensitive and tolerates a
// trailing root dot, so `LOCALHOST` and `localhost.` both resolve to loopback
// while failing an exact match — and a URL that fails the match is treated as
// public and opened unchanged, which is precisely the case the refusal exists
// to prevent. Any address that parses as an IP is judged by what it is rather
// than by how it is spelled, which also covers 127.0.0.2 and ::ffff:127.0.0.1.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if loopback[h] {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// portOf returns the URL's port, filling in the scheme default.
func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return defaultPort(u.Scheme)
}
