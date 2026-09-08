package ui

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// A sound when a request is waiting, and a specific one.
//
// The terminal bell was what this used to be, and a bell is the wrong
// instrument: half of terminals have it turned off, the other half use it for
// tab completion, and either way it means "something happened somewhere" rather
// than "devtun has stopped and needs an answer". A request that goes unheard
// becomes a timeout, and a timeout reads as a refusal nobody made.
//
// So devtun plays a sound of its own, using whatever the machine already has —
// the same bargain as the approval dialog, and for the same reason: a bundled
// audio library would want cgo, and this is a static binary for three operating
// systems.
//
// The bell is still rung alongside it. A terminal that shows an urgent-bell
// badge on its tab is doing exactly the job we want, and on a machine where no
// player is found it is the only thing left.

// alertTimeout bounds the player. A sound that has not started in this long is
// a sound nobody is waiting for.
const alertTimeout = 5 * time.Second

// macSound is the alert. Submarine is a sonar ping: short, distinctive, and —
// unlike Glass or Ping — not the sound five other applications on the machine
// already use, which is the whole point of picking one rather than beeping.
const macSound = "/System/Library/Sounds/Submarine.aiff"

// Alert plays the approval sound and rings the terminal bell.
//
// It never blocks the caller and never reports a failure: this is a courtesy on
// top of a modal that is already on screen, and a session that fell over
// because a sound player was missing would be a poor trade.
func Alert() {
	Bell()
	go playAlert()
}

// Bell writes BEL to the controlling terminal.
//
// To /dev/tty rather than stdout, so it works when output is redirected, and it
// is dropped entirely rather than risking a stray byte in a pipe when there is
// no terminal to ring.
func Bell() {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer func() { _ = tty.Close() }()
	_, _ = tty.WriteString("\a")
}

// playAlert finds a player and uses it. The first one that exists wins; a
// machine with none is silent beyond the bell.
func playAlert() {
	ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
	defer cancel()

	name, args := alertPlayer()
	if name == "" {
		return
	}
	_ = exec.CommandContext(ctx, name, args...).Run()
}

// alertPlayer returns the command that makes the noise on this platform.
func alertPlayer() (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat(macSound); err == nil {
			if path, err := exec.LookPath("afplay"); err == nil {
				return path, []string{macSound}
			}
		}
	case "windows":
		// Two short tones rather than one, because a single system beep is
		// what every other thing on Windows already sounds like.
		if path, err := exec.LookPath("powershell.exe"); err == nil {
			return path, []string{"-NoProfile", "-NonInteractive", "-Command",
				"[console]::beep(880,120); [console]::beep(1320,160)"}
		}
	default:
		// A desktop Linux has one of these; a headless one has none, and the
		// bell is the whole of the alert there.
		for _, candidate := range []struct {
			name string
			args []string
		}{
			{"canberra-gtk-play", []string{"-i", "message-new-instant"}},
			{"paplay", []string{"/usr/share/sounds/freedesktop/stereo/message-new-instant.oga"}},
			{"aplay", []string{"-q", "/usr/share/sounds/alsa/Front_Center.wav"}},
		} {
			if path, err := exec.LookPath(candidate.name); err == nil {
				return path, candidate.args
			}
		}
	}
	return "", nil
}
