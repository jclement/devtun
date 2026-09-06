package tui

import (
	tea "charm.land/bubbletea/v2"
)

// yank copies text to the clipboard of the machine the human is sitting at.
//
// OSC 52 is the only clipboard mechanism that works from inside an SSH
// session: the sequence travels back up the same terminal stream the UI is
// drawn on, through tmux and any number of nested hops, and the terminal
// emulator at the far end performs the copy. No X11, no pbcopy, no cgo.
//
// Bubble Tea v2 emits the sequence itself, which is why this is a wrapper
// rather than the hand-built escape autotun spliced into its frame: v2 renders
// through a cell buffer that would swallow a raw escape in the view, and
// SetClipboard writes straight to the terminal instead.
func yank(text string) tea.Cmd { return tea.SetClipboard(text) }
