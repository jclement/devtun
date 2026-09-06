package session

import (
	"context"
	"io"
	"net"
	"os"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// host is what a service is handed on Attach. It adapts the live SSH client,
// the shared facts and the config store onto service.Host, and narrows all
// three: a service gets exactly the surface the contract names and no more,
// which is why a service can be tested against a fake without an SSH server.
type host struct {
	label  string
	facts  service.Facts
	paths  shim.RemotePaths
	events event.Sink
	config service.Config
	client remoteClient
}

// remoteClient is the slice of sshx.Client a host needs. Declaring it here
// rather than importing the concrete type keeps the session testable and stops
// services from reaching past the contract.
type remoteClient interface {
	Run(ctx context.Context, script string, w io.Writer) error
	Output(ctx context.Context, script string) (string, error)
	Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error
	DialTCP(ctx context.Context, address string) (net.Conn, error)
}

func (h *host) Label() string          { return h.label }
func (h *host) Facts() service.Facts   { return h.facts }
func (h *host) Events() event.Sink     { return h.events }
func (h *host) Config() service.Config { return h.config }
func (h *host) ShimPath() string       { return h.paths.Binary }
func (h *host) SocketPath() string     { return h.paths.Socket }

func (h *host) Run(ctx context.Context, script string, w io.Writer) error {
	return h.client.Run(ctx, script, w)
}

func (h *host) Output(ctx context.Context, script string) (string, error) {
	return h.client.Output(ctx, script)
}

func (h *host) Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	return h.client.Upload(ctx, localPath, remotePath, mode)
}

func (h *host) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	return h.client.DialTCP(ctx, address)
}
