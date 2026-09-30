package opcli

import "os/exec"

// detach is a no-op on Windows, which has no /dev/tty for op to open behind
// devtun's back.
func detach(*exec.Cmd) {}
