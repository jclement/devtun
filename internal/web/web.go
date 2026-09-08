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
// It does not answer approvals. A prompt is the one decision where the cost of
// getting the plumbing subtly wrong is somebody else's secret, and a page that
// can approve is a page that has to be right about tokens, origins, rebinding
// and replay all at once. Approvals stay where they were — the interface's
// modal, a desktop dialog, or the terminal — and this page says so when one is
// waiting.
//
// # Getting in
//
// Loopback only, and a token. A port on 127.0.0.1 is not private: every process
// on the machine can reach it, and a web page in your browser can too. So the
// URL carries a token that is traded — once — for a cookie, every API call
// needs that cookie, and two header checks stand in the way of a browser being
// used as the way in:
//
//   - the Host header has to be a loopback name, which is what stops DNS
//     rebinding — a hostname somebody else controls, pointed at 127.0.0.1;
//   - a mutating request has to come from this origin, which is what stops a
//     page you happened to be reading from posting to it.
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

	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
)

//go:embed assets/*
var assets embed.FS

// cookieName carries the credential the URL token was traded for, so the tab
// that did the trade keeps working and the token stops appearing in the
// address bar.
const cookieName = "devtun"

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
	Hidden() int
	ViewPrefs() tunnels.ViewPrefs
	SetViewPrefs(tunnels.ViewPrefs)
}

// Broker is the slice of a gated service whose rules this page lists.
type Broker interface {
	Rules() []authz.Rule
	GlobalRules() []authz.Rule
	Revoke(index int) error
	Deny(index int) error
	Grants() []authz.Grant
	RevokeGrant(host, subject string) bool
}

// Options is everything the server is given.
type Options struct {
	// Addr is where to listen. Empty means 127.0.0.1 on a port the kernel
	// chooses, which is the right default: a fixed port is one another program
	// can be sitting on, and nothing needs to guess this one.
	Addr string
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
	// Bus is where events come from.
	Bus *event.Bus
	// Status reports the connection.
	Status func() session.Status
	// Retry asks the session to reconnect now.
	Retry func()
	// Now is injectable for tests.
	Now func() time.Time
}

// Server is the HTTP interface to one session.
type Server struct {
	opts Options
	// token is the one in the URL, good for a single trade.
	token string
	// session is what the cookie carries. It is deliberately not the token:
	// were they the same, the token out of browser history could be replayed
	// as a cookie and the trade would have bought nothing.
	session string
	mux     *http.ServeMux
	// url is filled in once the listener is bound.
	url string

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
func (s *Server) URL() string { return s.url }

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	addr := s.opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("the web interface could not listen on %s: %w", addr, err)
	}
	s.url = fmt.Sprintf("http://%s/?t=%s", listener.Addr().String(), url.QueryEscape(s.token))

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

	s.mux.HandleFunc("GET /", s.guard(func(w http.ResponseWriter, r *http.Request) {
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

	s.mux.HandleFunc("GET /api/state", s.guard(s.handleState))
	s.mux.HandleFunc("GET /api/events", s.guard(s.handleEvents))
	s.mux.HandleFunc("POST /api/ports/{port}/mode", s.guard(s.handlePortMode))
	s.mux.HandleFunc("POST /api/ports/{port}/scheme", s.guard(s.handlePortScheme))
	s.mux.HandleFunc("POST /api/rules/revoke", s.guard(s.handleRevokeRule))
	s.mux.HandleFunc("POST /api/grants/revoke", s.guard(s.handleRevokeGrant))
	s.mux.HandleFunc("POST /api/reconnect", s.guard(s.handleReconnect))
	s.mux.HandleFunc("POST /api/hidden", s.guard(s.handleShowHidden))
}

// guard is the whole of the access control, in one place so that no handler can
// be added without it.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		ok, spent := s.authorize(w, r)
		if spent {
			// The one refusal a person can do something about, so it says what
			// to do rather than leaving them to guess at a 401.
			http.Error(w, "devtun: this link has already been used — restart devtun for a new one",
				http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, "devtun: wrong or missing token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// authorize accepts the cookie, or trades the URL token for one. It also
// reports whether the refusal was a token that had already been traded, which
// is the only one worth explaining.
//
// The cookie is tried first, and that ordering is the whole race guard: one
// page load makes several requests — the page, the state, the stream — and only
// the first carries ?t=. Every request behind it already has the cookie and
// never reaches the trade at all, and neither does a reload of the bookmarked
// URL by the tab that did the trading.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (ok, spent bool) {
	if cookie, err := r.Cookie(cookieName); err == nil && matches(cookie.Value, s.session) {
		return true, false
	}
	token := r.URL.Query().Get("t")
	if token == "" || !matches(token, s.token) {
		return false, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.spentAt.IsZero() && s.opts.Now().Sub(s.spentAt) > exchangeWindow {
		return false, true
	}
	if s.spentAt.IsZero() {
		s.spentAt = s.opts.Now()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.session,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return true, false
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
	Host       string        `json:"host"`
	Version    string        `json:"version"`
	Connection connection    `json:"connection"`
	Ports      []portView    `json:"ports"`
	Hidden     int           `json:"hidden"`
	ShowHidden bool          `json:"showHidden"`
	Services   []serviceView `json:"services"`
	Rules      []ruleView    `json:"rules"`
	Grants     []grantView   `json:"grants"`
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
	Status   string `json:"status"`
	Skip     string `json:"skip,omitempty"`
	Scheme   string `json:"scheme"`
	Mode     string `json:"mode"`
	URL      string `json:"url,omitempty"`
	Age      string `json:"age"`
	Conns    int    `json:"conns"`
	In       uint64 `json:"in"`
	Out      uint64 `json:"out"`
}

type serviceView struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Glyph string `json:"glyph"`
	Short string `json:"short"`
}

type ruleView struct {
	Source  string `json:"source"`
	Index   int    `json:"index"`
	Host    string `json:"host"`
	Subject string `json:"subject"`
	Action  string `json:"action"`
	Note    string `json:"note,omitempty"`
	Global  bool   `json:"global"`
}

type grantView struct {
	Source   string `json:"source"`
	Host     string `json:"host"`
	Subject  string `json:"subject"`
	Action   string `json:"action"`
	Expires  string `json:"expires,omitempty"`
	HostWide bool   `json:"hostWide"`
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
	}

	for _, svc := range s.opts.Services {
		meta := svc.Meta()
		payload.Services = append(payload.Services, serviceView{
			ID: meta.ID, Title: meta.Title, Glyph: meta.Glyph, Short: meta.Short,
		})
	}

	for id, broker := range s.brokers() {
		for i, rule := range broker.Rules() {
			payload.Rules = append(payload.Rules, ruleView{
				Source: id, Index: i, Host: rule.Host, Subject: rule.Subject,
				Action: string(rule.Action), Note: rule.Note,
			})
		}
		for _, rule := range broker.GlobalRules() {
			payload.Rules = append(payload.Rules, ruleView{
				Source: id, Index: -1, Host: rule.Host, Subject: rule.Subject,
				Action: string(rule.Action), Note: rule.Note, Global: true,
			})
		}
		for _, grant := range broker.Grants() {
			view := grantView{
				Source: id, Host: grant.Host, Subject: grant.Subject,
				Action: string(grant.Action), HostWide: grant.HostWide,
			}
			if !grant.Expires.IsZero() {
				view.Expires = grant.Expires.Format(time.RFC3339)
			}
			payload.Grants = append(payload.Grants, view)
		}
	}

	writeJSON(w, payload)
}

func (s *Server) portView(state tunnels.State) portView {
	view := portView{
		Remote: state.RemotePort, Local: state.LocalPort, Addr: state.LocalAddr,
		Remapped: state.Remapped, Proc: state.Proc, Cmd: state.Cmd, Label: state.Label,
		Status: string(state.Status), Skip: string(state.Skip),
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
func (s *Server) brokers() map[string]Broker {
	out := map[string]Broker{}
	for _, svc := range s.opts.Services {
		if broker, ok := svc.(Broker); ok {
			out[svc.Meta().ID] = broker
		}
	}
	return out
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
}

func writeEvent(w http.ResponseWriter, e event.Event) error {
	payload, err := json.Marshal(eventView{
		Time:    e.Time.Format(time.RFC3339),
		Service: e.Service,
		Class:   string(e.Class),
		Level:   e.Level.String(),
		Kind:    e.Kind,
		Text:    e.Text,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", payload)
	return err
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

// handleRevokeRule takes back a rule devtun wrote.
//
// Only devtun's own: a global rule came out of a file the user hand-wrote, and
// a web page quietly editing it would be a worse surprise than saying no. The
// index is the broker's own, which is why the page sends back what it was given
// rather than a position on screen.
func (s *Server) handleRevokeRule(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	index, err := strconv.Atoi(r.URL.Query().Get("index"))
	if err != nil || index < 0 {
		http.Error(w, "index must be a rule devtun wrote", http.StatusBadRequest)
		return
	}
	if err := broker.Revoke(index); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	broker, ok := s.brokerParam(w, r)
	if !ok {
		return
	}
	host := r.URL.Query().Get("host")
	subject := r.URL.Query().Get("subject")
	if !broker.RevokeGrant(host, subject) {
		http.Error(w, "that grant has already lapsed", http.StatusConflict)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleReconnect(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Retry != nil {
		s.opts.Retry()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) brokerParam(w http.ResponseWriter, r *http.Request) (Broker, bool) {
	broker, ok := s.brokers()[r.URL.Query().Get("source")]
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
