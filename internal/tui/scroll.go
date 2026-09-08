package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/ui"
)

// The scroll gutter: the last cell inside the frame's right border, on every
// tab's list.
//
// It is one column spent on the question no tab could answer before — is there
// more of this below? A busy box forwards thirty ports and the eighteen that
// fit looked exactly like all there were, which is the worst way for a board to
// be wrong: it is not obviously missing anything.
const (
	trackCell = "│"
	thumbCell = "█"
)

// scrollTrack draws one cell per visible line: a thumb whose length and
// position are the visible slice's share of the whole list, and blanks when
// everything fits.
//
// The gutter is reserved either way. A column that appeared the moment a
// thirty-first port showed up would shift the table under the cursor and clip
// the right-aligned byte counts by one cell, which is a worse trade than the
// column costs.
func (m *Model) scrollTrack(height int) []string {
	cells := make([]string, max(height, 1))
	total := m.rowCount()
	if height <= 0 || total <= height {
		for i := range cells {
			cells[i] = " "
		}
		return cells
	}

	thumb := max(height*height/total, 1)
	top := m.offset() * height / total
	// The thumb has to touch the bottom on the last page, or a list scrolled
	// all the way down still looks like it has somewhere left to go.
	if m.offset()+height >= total {
		top = height - thumb
	}
	top = min(max(top, 0), height-thumb)

	for i := range cells {
		if i >= top && i < top+thumb {
			cells[i] = ui.Header.Render(thumbCell)
			continue
		}
		cells[i] = ui.Muted.Render(trackCell)
	}
	return cells
}

// withTrack fits one list line beside the gutter.
func (m *Model) withTrack(line, cell string) string {
	w := m.inner() - 1
	if w < 1 {
		return line
	}
	line = clampWidth(line, w)
	if pad := w - ansi.StringWidth(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	return line + cell
}
