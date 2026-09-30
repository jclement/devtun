//go:build !windows

package opcli

import (
	"os/exec"
	"syscall"
)

// detach starts op in a session of its own, with no controlling terminal.
//
// op opens /dev/tty directly when it wants to ask something — most often which
// account to use when more than one is signed in and the reference did not
// decide. Inheriting devtun's terminal, that picker drew itself over the
// interface and read the keystrokes meant for it. Without a terminal op fails
// instead, with an error that names the fix, and the error reaches the remote
// box like any other.
func detach(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
