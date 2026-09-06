// Package service defines what a devtun capability is.
//
// devtun is one SSH connection with things layered on top of it: port
// forwarding, a 1Password broker, a browser bridge. Each is a Service. The
// point of the interface is that adding a fourth — a forwarded Docker socket, an
// AWS SSO broker — is a new package implementing Service, not a new tool and not
// a change to the supervisor.
//
// The contract is deliberately small. A Service answers three questions: who
// are you, can you work on this host, and here is a connection — go. Everything
// else a service might want to do (draw a pane, add a subcommand, take a slice
// of the control socket) is an optional interface below, discovered by type
// assertion, so a service pays only for what it uses.
package service

import (
	"context"
	"io"
	"net"
	"os"

	"github.com/jclement/devtun/internal/event"
)

// Meta is a service's static identity. It is available before anything has
// connected, because the CLI and the config file need to name services without
// touching a network.
type Meta struct {
	// ID is the stable machine name: "tunnels", "1password", "browser". It is
	// the config key, the event Service field, and the CLI noun.
	ID string
	// Title is what a human reads: "1Password".
	Title string
	// Glyph is a single display width character for the log and the TUI.
	Glyph string
	// Class is the event class this service's activity defaults to, so a
	// service that is fundamentally about secrets is styled that way without
	// having to say so on every event.
	Class event.Class
	// Short is a one-line description for `devtun services`.
	Short string
}

// Support is the answer to "can this service work on this host". A service that
// cannot run is not an error — a dev box without the 1Password CLI is an
// ordinary dev box — so this is a value, displayed greyed out with its reason,
// and its toggle disabled.
type Support struct {
	OK bool
	// Reason explains a false OK in terms the user can act on: "op is not
	// installed on bedev", not "probe failed".
	Reason string
	// Detail is optional extra shown in the Services tab.
	Detail string
}

// Supported is a convenience for the common affirmative answer.
func Supported() Support { return Support{OK: true} }

// Unsupported reports that the service cannot run here, and why.
func Unsupported(reason string) Support { return Support{Reason: reason} }

// Facts are what one probe of the remote host discovered, shared by every
// service so nobody pays for a second round trip.
type Facts struct {
	Home       string
	RuntimeDir string // $XDG_RUNTIME_DIR, empty when unset
	User       string
	Hostname   string
	OS         string // GOOS-style: linux, darwin
	Arch       string // GOARCH-style: amd64, arm64
	// Shell is the user's login shell, as $SHELL reports it.
	Shell string
	// LoginPath is PATH as the user's own login and interactive shells see it,
	// which is not what `ssh host command` gets. A box configured perfectly for
	// the person who logs into it looks unconfigured to a naive probe, and
	// printing setup instructions to someone who has already followed them is
	// how instructions stop being read.
	LoginPath string
	// Tools maps a command name to its resolved path, empty when absent.
	// Populated for the union of what every service asks about.
	Tools map[string]string
}

// Has reports whether the remote has the named command.
func (f Facts) Has(tool string) bool { return f.Tools[tool] != "" }

// Host is the live connection and its surroundings, handed to a service on
// Attach. It is an interface rather than a struct so a service can be tested
// against an in-process SSH server, or none at all — which is how autotun's
// forwarding path and opproxy's authorisation logic are already tested.
type Host interface {
	// Label is the name the user typed — the ssh_config alias where there is
	// one. Every decision recorded on disk is keyed to it, so rules survive a
	// machine changing address or username.
	Label() string
	// Facts describes the remote box.
	Facts() Facts
	// Events is where this service reports activity. It is already stamped
	// with the service's ID.
	Events() event.Sink
	// Config is this service's own namespaced slice of the host's config file.
	Config() Config

	// Run streams a script to the remote shell, copying its stdout to w. It
	// returns when the remote command exits.
	Run(ctx context.Context, script string, w io.Writer) error
	// Output runs a script and returns its stdout.
	Output(ctx context.Context, script string) (string, error)
	// Upload writes a local file to the remote path, atomically.
	Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error
	// DialTCP opens a direct-tcpip channel to an address on the remote side.
	DialTCP(ctx context.Context, address string) (net.Conn, error)
	// ShimPath is where the devtun shim lives on this host, for a service that
	// needs to name it in setup advice.
	ShimPath() string
	// SocketPath is the control socket this session is serving.
	SocketPath() string
}

// Config is a service's persistent per-host state. It is a small key/document
// store rather than a typed struct because the shape belongs to the service,
// not to the config package: tunnels stores a port table, 1Password stores
// rules, and neither should have to teach hostcfg about the other.
type Config interface {
	// Get unmarshals the stored document for key into v. A missing key leaves
	// v untouched and reports false.
	Get(key string, v any) (bool, error)
	// GetLocal is Get without falling back to any shared or global document.
	//
	// The distinction matters to any service that writes back what it read: a
	// value inherited from elsewhere, read through Get and then saved, becomes
	// a copy that no longer tracks its source. Policy rules are the case that
	// made this necessary.
	GetLocal(key string, v any) (bool, error)
	// Set marshals v and stores it under key, marking the file dirty. It does
	// not write to disk; the session saves once, on exit.
	Set(key string, v any) error
}

// Service is one capability layered onto a session.
type Service interface {
	Meta() Meta
	// Probe reports whether this service can work on the host. It runs once
	// per connection, after Facts are gathered and before Attach. It may use
	// the host's Run/Output, but should prefer Facts — that is what Facts are
	// for.
	Probe(ctx context.Context, h Host) Support
	// Attach binds the service to a freshly established connection. The
	// returned Instance is used exactly once and then discarded: a reconnect
	// is Close followed by a new Attach, never a special case inside the
	// service. State that must survive a reconnect — a grant, a local port
	// assignment — belongs on the Service, not on the Instance.
	Attach(ctx context.Context, h Host) (Instance, error)
}

// Instance is a service bound to one SSH connection.
type Instance interface {
	// Run blocks until ctx is cancelled or the service fails. Returning nil
	// means an orderly stop; returning an error tears down the connection and
	// triggers a reconnect, so return nil for anything recoverable.
	Run(ctx context.Context) error
	// Close releases remote state. It is called exactly once, after Run has
	// returned, and must tolerate a connection that is already dead.
	Close() error
}

// --- Optional interfaces -------------------------------------------------
//
// Discovered by type assertion. A service implements the ones it needs.

// SocketHandler takes a slice of the shared control socket. The session reads
// the Hello frame, routes on its Service field, and hands the connection over.
// The handler owns the connection from that point, including closing it.
type SocketHandler interface {
	// HandleConn serves one accepted connection that named this service.
	HandleConn(ctx context.Context, conn net.Conn, caller Caller) error
}

// Caller is what the remote shim says about itself. Every field is self-
// reported by a process on a machine devtun treats as only semi-trusted, so it
// is displayed — "deploy.sh in ~/projects/api wants this" is what makes an
// approval decision possible — and never used to decide anything. Decisions are
// made from the SSH destination, which is authenticated.
type Caller struct {
	Version string `json:"version"`
	User    string `json:"user,omitempty"`
	Host    string `json:"host,omitempty"`
	PID     int    `json:"pid,omitempty"`
	CWD     string `json:"cwd,omitempty"`
	Program string `json:"program,omitempty"`
}

// Advisor is implemented by a service that needs something in the user's shell
// rc on the remote box. Lines are printed only when they are actually missing.
type Advisor interface {
	// SetupLines returns the rc lines this service needs, or nil when the host
	// already has everything.
	SetupLines(h Host) []string
}

// Configurable exposes settings for the TUI's config popup. Settings change
// what you look at; they never start or stop anything, which is a different
// question and conflating the two produces surprises.
type Configurable interface {
	Settings() []Setting
}

// Setting is one toggle or choice in the config popup.
type Setting struct {
	Key     string
	Title   string
	Help    string
	Options []string // nil for a boolean
	Get     func() string
	Set     func(string)
}
