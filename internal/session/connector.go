package session

import (
	"context"

	"github.com/jclement/devtun/internal/sshx"
)

// sshConnector adapts the SSH transport onto the supervisor's Connector, which
// is deliberately narrower: the supervisor needs to dial, name the host, and
// describe it, and knowing nothing else is what lets it be tested without a
// network.
type sshConnector struct {
	dest *sshx.Destination
	opts sshx.Options
}

// NewSSHConnector returns a Connector that dials dest.
func NewSSHConnector(dest *sshx.Destination, opts sshx.Options) Connector {
	return &sshConnector{dest: dest, opts: opts}
}

func (c *sshConnector) Connect(ctx context.Context) (Conn, error) {
	client, err := sshx.Dial(ctx, c.dest, c.opts)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Label is the ssh_config alias where there is one. Every persistent decision
// — a hidden port, an approved secret — is keyed to it, so a box that changes
// address or username keeps its settings.
func (c *sshConnector) Label() string { return c.dest.Label() }

func (c *sshConnector) Describe() string { return c.dest.String() }

// GoUnattended drops the interactive prompter.
//
// A passphrase or an unknown host key can only be asked about while a terminal
// is still ours, which is before the TUI takes the screen. Every reconnection
// after that happens behind it, where a prompt would be drawn into a frame
// nobody is reading and would block the supervisor for ever. Failing is the
// honest answer there, and the reconnect loop will say so.
func (c *sshConnector) GoUnattended() { c.opts.Prompter = nil }
