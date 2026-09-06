//go:build !windows

// SSH agent transport on unix: a plain unix socket, which is what SSH_AUTH_SOCK
// names for OpenSSH's agent, gpg-agent's ssh emulation, yubikey-agent, 1Password
// and every other implementation.
package sshx

import (
	"net"
)

func dialAgentAt(path string) (net.Conn, error) {
	// A plain Dial on purpose: this is a local unix socket, reached from a
	// signer callback that has no context to carry and nothing that would
	// cancel it. The agent's own handshake timeout is the bound that matters.
	return net.Dial("unix", path) //nolint:noctx // local unix socket, no context at this layer
}

// defaultAgentPath is empty on unix: there is no well-known location, only
// whatever SSH_AUTH_SOCK points at.
func defaultAgentPath() string { return "" }
