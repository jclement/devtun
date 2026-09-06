//go:build windows

// SSH agent transport on Windows. The OpenSSH agent shipped with Windows
// listens on a named pipe rather than a unix socket, so it needs its own dialer;
// a unix-style path is still honoured first for MSYS and WSL-adjacent setups
// that provide one.
package sshx

import (
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// WindowsAgentPipe is where the Windows OpenSSH agent listens.
const WindowsAgentPipe = `\\.\pipe\openssh-ssh-agent`

func dialAgentAt(path string) (net.Conn, error) {
	timeout := 2 * time.Second
	if strings.HasPrefix(path, `\\`) {
		return winio.DialPipe(path, &timeout)
	}
	if conn, err := net.Dial("unix", path); err == nil {
		return conn, nil
	}
	return winio.DialPipe(WindowsAgentPipe, &timeout)
}

// defaultAgentPath is the well-known pipe, so the Windows agent is found even
// with no SSH_AUTH_SOCK set — which is the normal state there.
func defaultAgentPath() string { return WindowsAgentPipe }
