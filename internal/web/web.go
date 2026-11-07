// Package web serves the same board the interface draws, in a browser.
//
// It exists for the session you leave running: devtun in a tmux pane on the
// laptop, or on the far side of an ssh you have since closed, where the port
// table and the security log are the two things you still want to see. A
// browser tab is also the one interface you can leave open on a second monitor
// without it owning a terminal.
//
// # What it will and will not do
//
// It shows the board and it takes back access: hide a port, unhide it, revoke a
// rule, revoke a grant, forget everything. Every one of those either narrows
// what the remote box can do or changes what you are looking at.
//
// It answers approvals too, which was not always true. The objection was that a
// page which can approve has to be right about tokens, origins, rebinding and
// replay all at once — and three of those were already handled here. Replay is
// the fourth, and it is answered in internal/approval rather than here: a
// request is addressed by an unguessable id that is spent on first use, and a
// choice is checked against the menu built for that one request. "Approve
// whatever is pending" is not an operation this page can perform.
//
// The alternative was worse than the risk. devtun runs in a window you are not
// looking at; that is the whole premise. A board that could show you a secret
// being asked for and then send you to another window to say yes is a board
// that turns every approval into a race against its own timeout.
//
// # Getting in
//
// Loopback only, and a token. A port on 127.0.0.1 is not private: every process
// on the machine can reach it, and a web page in your browser can too. So the
// URL carries a token that is traded — once — for a session credential, every
// API call has to present that credential, and two header checks stand in the
// way of a browser being used as the way in:
//
//   - the Host header has to be a loopback name, which is what stops DNS
//     rebinding — a hostname somebody else controls, pointed at 127.0.0.1;
//   - a mutating request has to come from this origin, which is what stops a
//     page you happened to be reading from posting to it.
//
// The credential is a bearer header the page's own script sends, kept in that
// tab's memory and sessionStorage — never a cookie. That is the port boundary,
// and it is the reason. Cookies are scoped to a host name, not a port, so a
// cookie set by the board on 127.0.0.1 is sent to every other server on
// 127.0.0.1 too — and those are exactly the remote dev servers devtun forwards.
// Opening a tunnel after opening the board handed the board's credential to
// the box it is supposed to be guarding against. sessionStorage, by contrast, is
// partitioned by origin, port included, so nothing served on another port can
// read it, and a header has to be added deliberately by script rather than
// attached by the browser to whatever asks. Serving the board on a host name of
// its own (a `*.localhost` name, a second loopback address) would also isolate
// a cookie, but neither works everywhere: macOS answers only on 127.0.0.1, and
// not every browser resolves `*.localhost`.
//
// The page also refuses to be framed (CSP frame-ancestors and X-Frame-Options),
// so a page on another port cannot overlay it and steer a click onto
// "approve".
//
// The trade is one-way and happens once. devtun opens the browser itself, so
// the tokened URL lands in history, where nothing this program does can reach
// it; making it worthless after the page that was opened has swapped it is the
// only thing that keeps history from being a way in tomorrow.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jclement/devtun/internal/approval"
	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/settings"
	"github.com/jclement/devtun/internal/tunnels"
)

// loopbackAny is a port the kernel chooses, on this machine only.
const loopbackAny = "127.0.0.1:0"

//go:embed assets/*
var assets embed.FS

// bearerPrefix introduces the credential in an Authorization header: the URL
// token on the one request that trades it, the session credential on every
// request after.
const bearerPrefix = "Bearer "

// exchangeWindow is how long the one trade stays open.
//
// One page load is not always one request: a browser may prerender the URL and
// then navigate to it, or retry a navigation it dropped, and a token that died
// on the first of those would leave the user staring at a refusal for a link
// devtun itself had just opened. Everything the window has to cover happens in
// the same second; the replay it must not cover — the same URL out of history
// — happens minutes or days later.
const exchangeWindow = 5 * time.Second

// Tunnels is the slice of the tunnels service this needs.
type Tunnels interface {
	States() []tunnels.State
	SetMode(remotePort int, mode tunnels.Mode) tunnels.Mode
	SetScheme(remotePort int, scheme tunnels.Scheme) tunnels.Scheme
	SetLabel(remotePort int, label string) error
	SetLocalPort(remotePort, local int) error
	Policy() tunnels.Policy
	SetPolicy(tunnels.Policy)
	Hidden() int
	ViewPrefs() tunnels.ViewPrefs
	SetViewPrefs(tunnels.ViewPrefs)
}

// Broker is the slice of a gated service whose rules this page lists.
type Broker interface {
	authz.Policy
}

// Forgetter is a broker that can drop everything it is holding open: the live
// grants, and the secret values cached under them. The two go together because
// a cached value whose authorisation has been withdrawn is exactly what must
// not be served.
//
// It is kept off Broker on purpose. A broker that never sees a secret has
// nothing to cache and reports one number rather than two, and folding both
// shapes into Broker would mean the ones with the shorter Forget stopped
// matching it — which would quietly drop their rules and grants off the board
// rather than failing to compile.
type Forgetter interface {
	Forget() (grants, cached int)
}

// cachelessForgetter is the same action from a broker with no cache to purge:
// the agent asks the real agent for a signature and the browser opens a URL,
// so neither ever holds key material devtun could be keeping.
type cachelessForgetter interface {
	Forget() int
}

// Options is everything the server is given.
type Options struct {
	// Addr is where to listen. Empty means 127.0.0.1 on a port the kernel
	// chooses, which is the right default: a fixed port is one another program
	// can be sitting on, and nothing needs to guess this one.
	Addr string
	// FixedAddr says Addr was named by the user rather than defaulted, so a
	// port already in use is an error rather than something to work around.
	FixedAddr bool
	// Token authenticates every request. Empty means one is generated, which
	// is what you want unless a test needs to know it in advance.
	Token string
	// Host is the box this session is attached to, for the title.
	Host string
	// Version is devtun's version, for the footer.
	Version string
	// Tunnels is the port table. Nil renders an empty one rather than failing:
	// a session running only the vault is a legitimate session.
	Tunnels Tunnels
	// Services is the registry, for the services list and for finding brokers.
	Services []service.Service
	// Store is devtun's configuration files, for the settings screen. Nil is a
	// --no-config run: the settings still list and still say what devtun is
	// doing, and only saving is missing.
	Store settings.Store
	// PromptNow is where approvals are appearing for this run, which the
	// command line can override without touching either config file.
	PromptNow func() string
	// ApplyPrompt puts a changed prompt setting into effect now rather than at
	// the next connection — the setting somebody changes *because* they are
	// missing approvals.
	ApplyPrompt func(string)
	// DialogChooser names the program this machine would raise a desktop
	// dialog with, empty when there is none.
	DialogChooser func() string
	// Bus is where events come from.
	Bus *event.Bus
	// Status reports the connection.
	Status func() session.Status
	// Retry asks the session to reconnect now.
	Retry func()
	// Approvals is the desk of questions waiting on a human. Nil means the
	// board shows none and can answer none, which is what a session with no
	// gated service has.
	Approvals *approval.Desk
	// Now is injectable for tests.
	Now func() time.Time
}

// Server is the HTTP interface to one session.
type Server struct {
	// svc is what each service is currently doing, kept from the event bus
	// because that is the only place a Probe's answer is published.
	svcMu sync.Mutex
	svc   map[string]svcState

	opts Options
	// token is the one in the URL, good for a single trade.
	token string
	// session is the credential the page presents on every API call. It is
	// deliberately not the token: were they the same, the token out of browser
	// history could be replayed as a session and the trade would have bought
	// nothing.
	session string
	mux     *http.ServeMux
	// url is filled in once the listener is bound, by Run's goroutine, and read
	// by whoever wants to announce it — a different goroutine in every caller
	// there is. Hence the lock: this was a genuine data race in shipped code,
	// found by a test that raced Run against URL the way `devtun --web`
	// already did.
	urlMu sync.Mutex
	url   string

	mu sync.Mutex
	// spentAt is when the token was traded. Zero until it has been.
	spentAt time.Time
}

// New builds the server. Nothing is listening until Run.
func New(opts Options) (*Server, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	token := opts.Token
	if token == "" {
		generated, err := randomToken()
		if err != nil {
			return nil, err
		}
		token = generated
	}
	session, err := randomToken()
	if err != nil {
		return nil, err
	}

	s := &Server{opts: opts, token: token, session: session, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generating a token for the web interface: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// URL is the address to open, token included. It is empty until Run has bound
// its listener.
func (s *Server) URL() string {
	s.urlMu.Lock()
	defer s.urlMu.Unlock()
	return s.url
}

// setURL records where the board ended up.
func (s *Server) setURL(url string) {
	s.urlMu.Lock()
	defer s.urlMu.Unlock()
	s.url = url
}

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	addr := s.opts.Addr
	if addr == "" {
		addr = loopbackAny
	}
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", addr)
	if err != nil && s.opts.Addr != "" {
		// The default port is a convenience, not a requirement: a second devtun
		// on this machine is an ordinary thing to want, and refusing to start
		// over a port number would be a poor trade for a stable URL. An address
		// somebody asked for explicitly is different — that one is honoured or
		// reported.
		if !s.opts.FixedAddr {
			listener, err = config.Listen(ctx, "tcp", loopbackAny)
		}
	}
	if err != nil {
		return fmt.Errorf("the web interface could not listen on %s: %w", addr, err)
	}
	s.setURL(fmt.Sprintf("http://%s/?t=%s", listener.Addr().String(), url.QueryEscape(s.token)))

	stopWatching := s.watchServices()
	defer stopWatching()

	server := &http.Server{
		Handler: s.mux,
		// A read that never finishes should not hold a connection forever, and
		// nothing here is a long upload. The event stream writes rather than
		// reads, so it is unaffected.
		ReadHeaderTimeout: 10 * time.Second,
	}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) routes() {
	page, err := assets.ReadFile("assets/index.html")
	if err != nil {
		// Embedded at build time: if this fails the binary is broken, and
		// there is nothing a user could do about it at runtime.
		panic("web: the page is missing from the binary: " + err.Error())
	}

	// The page itself needs no credential: it is the same static file for
	// everyone and holds nothing, and it has to load before its script can
	// trade the token. Everything it then asks for does.
	s.mux.HandleFunc("GET /", s.public(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// No caching: the page is tiny and a stale one after an upgrade is a
		// puzzle nobody should have to solve.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	}))
	s.mux.HandleFunc("POST /api/session", s.public(s.handleSession))

	s.mux.HandleFunc("GET /api/state", s.guard(s.handleState))
	s.mux.HandleFunc("GET /api/events", s.guard(s.handleEvents))
	s.mux.HandleFunc("POST /api/ports/{port}/mode", s.guard(s.handlePortMode))
	s.mux.HandleFunc("POST /api/ports/{port}/scheme", s.guard(s.handlePortScheme))
	s.mux.HandleFunc("POST /api/ports/{port}/label", s.guard(s.handlePortLabel))
	s.mux.HandleFunc("POST /api/ports/{port}/local", s.guard(s.handlePortLocal))
	s.mux.HandleFunc("POST /api/pause", s.guard(s.handlePause))
	// Access. Every one of these goes through guard like everything else; the
	// loosening ones also want confirm=1 (see access.go).
	s.mux.HandleFunc("GET /api/explain", s.guard(s.handleExplain))
	s.mux.HandleFunc("POST /api/rules/add", s.guard(s.handleAddRule))
	s.mux.HandleFunc("POST /api/rules/remove", s.guard(s.handleRemoveRule))
	s.mux.HandleFunc("POST /api/rules/action", s.guard(s.handleRuleAction))
	s.mux.HandleFunc("POST /api/rules/update", s.guard(s.handleUpdateRule))
	s.mux.HandleFunc("POST /api/grants/add", s.guard(s.handleAddGrant))
	s.mux.HandleFunc("POST /api/grants/revoke", s.guard(s.handleRevokeGrant))
	s.mux.HandleFunc("POST /api/grants/forget", s.guard(s.handleForget))
	s.mux.HandleFunc("POST /api/grants/forget-refusals", s.guard(s.handleForgetRefusals))
	s.mux.HandleFunc("POST /api/reconnect", s.guard(s.handleReconnect))
	s.mux.HandleFunc("POST /api/hidden", s.guard(s.handleShowHidden))
	s.mux.HandleFunc("POST /api/approve", s.guard(s.handleApprove))
	s.mux.HandleFunc("GET /api/config", s.guard(s.handleConfig))
	s.mux.HandleFunc("POST /api/config/{key}", s.guard(s.handleSetting))
}

// secure sets the headers every response carries.
//
// frame-ancestors and X-Frame-Options are the anti-framing pair: a page on
// another port of this same host could otherwise put the board in an
// invisible iframe and line a button of its own up over "approve". The board
// answers questions about secrets, so a click is a decision, and nobody else's
// page gets to arrange where it lands. no-referrer keeps the tokened URL out of
// the Referer of anything the page links to, and nosniff keeps a JSON reply
// from ever being read as something executable.
func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

// public is the checks that need no credential: the Host header, and the
// Origin of anything that changes state. They apply to every route, the page
// and the token trade included.
func (s *Server) public(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		if !loopbackHost(r.Host) {
			// A hostname somebody else controls, resolved to 127.0.0.1, is how
			// a page in your browser reaches a server it should not be able to
			// name. The Host header is the only part of that it cannot forge.
			http.Error(w, "devtun's web interface only answers to localhost", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// guard is the whole of the access control, in one place so that no handler can
// be added without it.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return s.public(func(w http.ResponseWriter, r *http.Request) {
		if !matches(bearer(r), s.session) {
			http.Error(w, "devtun: wrong or missing credential — open the link devtun printed", http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

// bearer is the credential in the request's Authorization header, or "".
func bearer(r *http.Request) string {
	value, ok := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// handleSession trades the URL token for the session credential.
//
// The token arrives in the Authorization header rather than the URL of this
// request, so it is not written into anything that logs request lines. Every
// trade inside the exchange window gets the same credential: one page load is
// not always one request — a prerender and then the real navigation, a retry —
// and a token that died on the first of those would strand the tab that
// devtun itself opened. After the window the token is spent, and a refusal says
// so, because it is the one refusal a person can do something about.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := bearer(r)
	if token == "" || !matches(token, s.token) {
		http.Error(w, "devtun: wrong or missing token", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	if !s.spentAt.IsZero() && s.opts.Now().Sub(s.spentAt) > exchangeWindow {
		s.mu.Unlock()
		http.Error(w, "devtun: this link has already been used — restart devtun for a new one",
			http.StatusUnauthorized)
		return
	}
	if s.spentAt.IsZero() {
		s.spentAt = s.opts.Now()
	}
	s.mu.Unlock()

	writeJSON(w, map[string]string{"session": s.session})
}

// matches compares in constant time. The comparison is not the weak point here,
// but a timing-safe compare costs nothing and removes the argument.
func matches(candidate, want string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(want)) == 1
}

// loopbackHost reports whether the Host header names this machine.
func loopbackHost(host string) bool {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.ToLower(strings.Trim(name, "[]"))
	if name == "localhost" {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// sameOrigin reports whether a mutating request came from this page.
//
// A browser sends Origin on every cross-origin POST and cannot be talked out of
// it, so an Origin that is absent is a request that did not come from a page —
// curl, a script — and one that is present has to match.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == r.Host
}

// --- the API ---------------------------------------------------------------

// statePayload is one snapshot of everything the page draws.
type statePayload struct {
	Host       string     `json:"host"`
	Version    string     `json:"version"`
	Connection connection `json:"connection"`
	Ports      []portView `json:"ports"`
	Hidden     int        `json:"hidden"`
	ShowHidden bool       `json:"showHidden"`
	// Paused is the policy's own flag: forwarding that is already up stays up,
	// and nothing new is opened automatically until it comes off.
	Paused   bool          `json:"paused"`
	Services []serviceView `json:"services"`
	Rules    []ruleView    `json:"rules"`
	Grants   []grantView   `json:"grants"`
	// Gated says something on this session decides access. It is what makes
	// forget-everything a button rather than dead chrome, and it is not the
	// same question as "are there grants": the vault's cache keeps its own
	// clock, so a value can still be held after the grant behind it lapsed.
	Gated bool `json:"gated"`
	// Waiting is every question sitting on a human right now. It is first in
	// the page's reading order for the same reason it is loud on screen: a
	// secret being asked for outranks anything else the board has to say.
	Waiting []approvalView `json:"waiting"`
	// Policies is one row per gated service: its subject fields, what
	// happens when nothing matches, and whether its policy file is readable.
	Policies []policyView `json:"policies"`
	// Revision changes whenever any service's rules do — here, at the
	// terminal, or by a hand edit picked up from disk — so the page knows to
	// re-ask anything it derived from them.
	Revision string `json:"revision"`
}

type connection struct {
	State  string `json:"state"`
	Since  string `json:"since"`
	Uptime string `json:"uptime"`
	// Detail is what the session says about a state that is not "connected":
	// which attempt this is, or why the last one failed.
	Detail string `json:"detail,omitempty"`
}

type portView struct {
	Remote   int    `json:"remote"`
	Local    int    `json:"local"`
	Addr     string `json:"addr"`
	Remapped bool   `json:"remapped"`
	Proc     string `json:"proc"`
	Cmd      string `json:"cmd"`
	Label    string `json:"label,omitempty"`
	// Pinned is a local port the user chose, or zero when the tunnel is free to
	// land wherever it can. It is not Local: a pin that is refused because
	// something else holds the port leaves the two disagreeing, and that is the
	// disagreement worth showing.
	Pinned int    `json:"pinned,omitempty"`
	Status string `json:"status"`
	Skip   string `json:"skip,omitempty"`
	Scheme string `json:"scheme"`
	Mode   string `json:"mode"`
	URL    string `json:"url,omitempty"`
	Age    string `json:"age"`
	Conns  int    `json:"conns"`
	In     uint64 `json:"in"`
	Out    uint64 `json:"out"`
}

type serviceView struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Glyph string `json:"glyph"`
	Short string `json:"short"`
	// Enabled is what the config files say for this host; Running is whether
	// it is actually attached to the connection right now. They differ more
	// often than you would think — a service switched on that this box cannot
	// support is the case the Detail exists to explain.
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Detail  string `json:"detail,omitempty"`
}

type ruleView struct {
	// Source is the broker's id, which is what the action routes take.
	Source string `json:"source"`
	// ID names the rule itself, stably: a revoke from the terminal between
	// this page's render and a click cannot redirect the click to another
	// rule, which it could when rules were addressed by position.
	ID string `json:"id"`
	// Origin is which list the rule is in: global, host or remembered.
	Origin  string `json:"origin"`
	Host    string `json:"host"`
	Subject string `json:"subject"`
	// Parts is the subject split into the broker's fields — key and
	// destination for the agent — so the page never parses a subject itself.
	Parts    []string `json:"parts"`
	Action   string   `json:"action"`
	Note     string   `json:"note,omitempty"`
	Added    string   `json:"added,omitempty"`
	Global   bool     `json:"global"`
	Editable bool     `json:"editable"`
	// Outranked is an allow that a deny beats for the very request its own
	// pattern describes: a rule that never wins.
	Outranked bool `json:"outranked,omitempty"`
}

type grantView struct {
	Source    string   `json:"source"`
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Subject   string   `json:"subject"`
	Parts     []string `json:"parts"`
	Action    string   `json:"action"`
	Expires   string   `json:"expires,omitempty"`
	Created   string   `json:"created,omitempty"`
	HostWide  bool     `json:"hostWide"`
	Outranked bool     `json:"outranked,omitempty"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	payload := statePayload{
		Host:    s.opts.Host,
		Version: s.opts.Version,
	}

	if s.opts.Status != nil {
		status := s.opts.Status()
		payload.Connection = connection{
			State:  string(status.State),
			Detail: status.Detail,
		}
		if !status.Since.IsZero() {
			payload.Connection.Since = status.Since.Format(time.RFC3339)
			payload.Connection.Uptime = s.opts.Now().Sub(status.Since).Round(time.Second).String()
		}
	}

	if s.opts.Tunnels != nil {
		for _, state := range s.opts.Tunnels.States() {
			payload.Ports = append(payload.Ports, s.portView(state))
		}
		payload.Hidden = s.opts.Tunnels.Hidden()
		payload.ShowHidden = s.opts.Tunnels.ViewPrefs().ShowHidden
		payload.Paused = s.opts.Tunnels.Policy().Paused
	}

	for _, svc := range s.opts.Services {
		meta := svc.Meta()
		state := s.serviceState(meta.ID)
		payload.Services = append(payload.Services, serviceView{
			ID: meta.ID, Title: meta.Title, Glyph: meta.Glyph, Short: meta.Short,
			Enabled: s.enabledFor(meta), Running: state.Running, Detail: state.Detail,
		})
	}

	payload.Gated = len(s.brokers()) > 0
	s.accessState(&payload)

	payload.Waiting = s.waiting()
	writeJSON(w, payload)
}

func (s *Server) portView(state tunnels.State) portView {
	view := portView{
		Remote: state.RemotePort, Local: state.LocalPort, Addr: state.LocalAddr,
		Remapped: state.Remapped, Proc: state.Proc, Cmd: state.Cmd, Label: state.Label,
		Pinned: state.PinnedLocal, Status: string(state.Status), Skip: string(state.Skip),
		Scheme: string(state.Scheme), Mode: string(state.Mode), URL: state.URL(),
		Conns: state.ActiveConns, In: state.BytesIn, Out: state.BytesOut,
	}
	if !state.FirstSeen.IsZero() {
		view.Age = s.opts.Now().Sub(state.FirstSeen).Round(time.Second).String()
	}
	return view
}

// brokers finds the gated services by interface, in registry order — the same
// rule the interface's Access tab follows, so the two cannot disagree about
// what is deciding.
// brokers are the services that gate something, in registry order.
//
// A slice rather than a map, and that is the whole point: this used to return
// a map and the caller ranged over it, so Go's randomised iteration reordered
// the rules and grants on every two-second poll. A list that will not hold
// still is one you cannot read, and worse, one where the row under your cursor
// is not the row you are about to click. The interface walks a slice and never
// had this.
func (s *Server) brokers() []gatedService {
	var out []gatedService
	for _, svc := range s.opts.Services {
		if broker, ok := svc.(Broker); ok {
			out = append(out, gatedService{id: svc.Meta().ID, broker: broker})
		}
	}
	return out
}

// gatedService pairs a broker with the id its rules are addressed by.
type gatedService struct {
	id     string
	broker Broker
}

// brokerNamed finds one by id, for a request that names the source of a rule.
func (s *Server) brokerNamed(id string) (Broker, bool) {
	for _, g := range s.brokers() {
		if g.id == id {
			return g.broker, true
		}
	}
	return nil, false
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported here", http.StatusInternalServerError)
		return
	}
	if s.opts.Bus == nil {
		http.Error(w, "no event bus", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")

	// A buffered channel and a drop-on-full policy: a browser tab that has
	// stopped reading must not be able to stall the bus, which every renderer
	// and the session itself are also delivering through.
	queue := make(chan event.Event, 256)
	cancel := s.opts.Bus.Subscribe(func(e event.Event) {
		select {
		case queue <- e:
		default:
		}
	})
	defer cancel()

	// The history first, so a tab opened an hour in is not looking at a blank
	// page until something happens.
	for _, e := range s.opts.Bus.History() {
		if err := writeEvent(w, e); err != nil {
			return
		}
	}
	flusher.Flush()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-queue:
			if err := writeEvent(w, e); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			// A comment frame keeps a proxy or a sleeping tab from deciding
			// the connection is dead.
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// eventView is one line of the log, already rendered into strings the page can
// show without knowing devtun's types.
type eventView struct {
	Time    string `json:"time"`
	Service string `json:"service"`
	Class   string `json:"class"`
	Level   string `json:"level"`
	Kind    string `json:"kind"`
	Text    string `json:"text"`
	// Fields are the event's key/value pairs. A decision carries by, rule,
	// source and grant, which is what "why?" on the page follows back to the
	// rule that made it.
	Fields map[string]string `json:"fields,omitempty"`
}

func writeEvent(w http.ResponseWriter, e event.Event) error {
	payload, err := json.Marshal(eventView{
		Time:    e.Time.Format(time.RFC3339),
		Service: e.Service,
		Class:   string(e.Class),
		Level:   e.Level.String(),
		Kind:    e.Kind,
		Text:    e.Text,
		Fields:  fieldMap(e.Fields),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", payload)
	return err
}

// fieldMap flattens an event's alternating keys and values. A key that is not
// a string is skipped rather than guessed at.
func fieldMap(fields []any) map[string]string {
	if len(fields) < 2 {
		return nil
	}
	out := make(map[string]string, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		if key, ok := fields[i].(string); ok {
			out[key] = fmt.Sprint(fields[i+1])
		}
	}
	return out
}

func (s *Server) handlePortMode(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tunnels == nil {
		http.Error(w, "no tunnels service", http.StatusServiceUnavailable)
		return
	}
	port, ok := portParam(w, r)
	if !ok {
		return
	}
	mode := tunnels.Mode(r.URL.Query().Get("mode"))
	switch mode {
	case tunnels.ModeAuto, tunnels.ModeOn, tunnels.ModeHidden:
	default:
		http.Error(w, "mode must be auto, on or hidden", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"mode": string(s.opts.Tunnels.SetMode(port, mode))})
}

func (s *Server) handlePortScheme(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tunnels == nil {
		http.Error(w, "no tunnels service", http.StatusServiceUnavailable)
		return
	}
	port, ok := portParam(w, r)
	if !ok {
		return
	}
	scheme := tunnels.Scheme(r.URL.Query().Get("scheme"))
	switch scheme {
	case tunnels.SchemeHTTP, tunnels.SchemeHTTPS:
	default:
		http.Error(w, "scheme must be http or https", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"scheme": string(s.opts.Tunnels.SetScheme(port, scheme))})
}

// handlePortLabel names a port, or clears the name when the value is empty.
//
// The board is the place you interact from under `--web`, so a thing you can
// do at the table and not here is a hole rather than a nicety — and a name is
// the one piece of a port's identity that comes from you rather than from the
// box.
func (s *Server) handlePortLabel(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tunnels == nil {
		http.Error(w, "no tunnels service", http.StatusServiceUnavailable)
		return
	}
	port, ok := portParam(w, r)
	if !ok {
		return
	}
	label := r.URL.Query().Get("label")
	// Long enough for a sentence, short enough that it cannot push the rest of
	// the row off a terminal. The manager collapses whitespace itself.
	if len(label) > 64 {
		http.Error(w, "a name has to fit in the table — 64 characters at most", http.StatusBadRequest)
		return
	}
	if err := s.opts.Tunnels.SetLabel(port, label); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]string{"label": label})
}

// handlePortLocal pins the local port a service is forwarded to, and takes the
// pin off again when the value is zero.
//
// The manager reopens the tunnel to make the change now rather than at the next
// reconnect, so a port something else on this machine already holds fails here
// and has to be said out loud — filing the preference away and reporting
// success would leave the board claiming a move that did not happen.
func (s *Server) handlePortLocal(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tunnels == nil {
		http.Error(w, "no tunnels service", http.StatusServiceUnavailable)
		return
	}
	port, ok := portParam(w, r)
	if !ok {
		return
	}
	// Zero is the one value below 1 that means something: back to mirroring the
	// remote port, which is why this cannot reuse portParam.
	local, err := strconv.Atoi(r.URL.Query().Get("local"))
	if err != nil || local < 0 || local > 65535 {
		http.Error(w, "local must be a port number, or 0 to go back to matching the remote one",
			http.StatusBadRequest)
		return
	}
	if err := s.opts.Tunnels.SetLocalPort(port, local); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]int{"local": local})
}

// handlePause suspends automatic forwarding, or lets it resume. What is already
// up stays up; it is the next port the box opens that waits.
//
// The wanted state is named rather than flipped, which is the same shape
// /api/hidden takes and for the same reason: the page polls, so a click landing
// beside a snapshot in flight — or a retry of a request whose answer was lost —
// must not be able to leave the board and the session disagreeing about which
// way the switch went.
func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tunnels == nil {
		http.Error(w, "no tunnels service", http.StatusServiceUnavailable)
		return
	}
	policy := s.opts.Tunnels.Policy()
	policy.Paused = r.URL.Query().Get("paused") == "true"
	s.opts.Tunnels.SetPolicy(policy)
	writeJSON(w, map[string]bool{"paused": policy.Paused})
}

func (s *Server) handleShowHidden(w http.ResponseWriter, r *http.Request) {
	if s.opts.Tunnels == nil {
		http.Error(w, "no tunnels service", http.StatusServiceUnavailable)
		return
	}
	prefs := s.opts.Tunnels.ViewPrefs()
	prefs.ShowHidden = r.URL.Query().Get("show") == "true"
	s.opts.Tunnels.SetViewPrefs(prefs)
	writeJSON(w, map[string]bool{"showHidden": prefs.ShowHidden})
}

// approvalView is one question waiting on a human, as the page sees it.
//
// The id is included because it is how the page answers, and it is safe to send
// to a caller that already holds the session credential: it is unguessable, it is
// good for one use, and it names one specific question.
type approvalView struct {
	ID      string        `json:"id"`
	Host    string        `json:"host"`
	Subject string        `json:"subject"`
	Noun    string        `json:"noun"`
	Scope   string        `json:"scope,omitempty"`
	Rows    []approvalRow `json:"rows,omitempty"`
	Options []optionView  `json:"options"`
	Asked   string        `json:"asked"`
	Expires string        `json:"expires,omitempty"`
}

type approvalRow struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type optionView struct {
	// Choice is the wire value the page sends back. It is the Choice's own
	// integer, checked against this request's menu on the way in.
	Choice int    `json:"choice"`
	Label  string `json:"label"`
	// Allows separates the yeses from the noes, so the page can colour them
	// without parsing the label — which would be a second place for the meaning
	// of an answer to live.
	Allows bool `json:"allows"`
}

// waiting renders the desk for the page.
func (s *Server) waiting() []approvalView {
	if s.opts.Approvals == nil {
		return nil
	}
	var out []approvalView
	for _, item := range s.opts.Approvals.Waiting() {
		view := approvalView{
			ID: item.ID, Host: item.Request.Host, Subject: item.Request.Subject,
			Noun: item.Request.SubjectNoun(), Scope: item.Request.Scope,
			Asked: item.Asked.Format(time.RFC3339),
		}
		if !item.Deadline.IsZero() {
			view.Expires = item.Deadline.Format(time.RFC3339)
		}
		for _, row := range item.Request.Rows {
			view.Rows = append(view.Rows, approvalRow{Label: row.Label, Value: row.Value})
		}
		for _, option := range item.Options {
			view.Options = append(view.Options, optionView{
				Choice: int(option.Choice), Label: option.Label, Allows: option.Choice.Allows(),
			})
		}
		out = append(out, view)
	}
	return out
}

// handleApprove answers one waiting request.
//
// Everything that makes this safe is in the desk: the id is unguessable, it is
// spent on first use, and the choice must have been on that request's own menu.
// What is left here is refusing to guess — a missing or unparseable choice is
// not treated as anything, least of all as a yes.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if s.opts.Approvals == nil {
		http.Error(w, "nothing on this session asks for approval", http.StatusServiceUnavailable)
		return
	}
	id := r.URL.Query().Get("id")
	choice, err := strconv.Atoi(r.URL.Query().Get("choice"))
	if err != nil {
		http.Error(w, "choice must be one of the options offered for this request", http.StatusBadRequest)
		return
	}

	switch err := s.opts.Approvals.Answer(id, prompt.Choice(choice)); {
	case errors.Is(err, approval.ErrUnknown):
		// Gone means answered elsewhere, timed out, or never real. Saying which
		// would tell a caller which ids once existed.
		http.Error(w, "that request is no longer waiting — it was answered or it timed out", http.StatusConflict)
	case errors.Is(err, approval.ErrNotOffered):
		http.Error(w, "that answer was not offered for this request", http.StatusBadRequest)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]bool{"ok": true})
	}
}

func (s *Server) handleReconnect(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Retry != nil {
		s.opts.Retry()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) brokerParam(w http.ResponseWriter, r *http.Request) (Broker, bool) {
	broker, ok := s.brokerNamed(r.URL.Query().Get("source"))
	if !ok {
		http.Error(w, "no such service", http.StatusNotFound)
		return nil, false
	}
	return broker, true
}

func portParam(w http.ResponseWriter, r *http.Request) (int, bool) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		http.Error(w, "not a port", http.StatusBadRequest)
		return 0, false
	}
	return port, true
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}
