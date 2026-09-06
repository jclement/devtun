package tui

import (
	"math/rand"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jclement/devtun/internal/ui"
)

// matrixRunes are half-width katakana plus digits. Half-width forms matter:
// full-width katakana occupy two cells and would shear the layout as they
// replace single-width characters.
var matrixRunes = []rune(
	"ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍｦｲｸｺｿﾁﾄﾉﾌﾔﾖﾙﾚﾛﾝ" + "0123456789" + "=+*<>|:.")

// dissolve turns a captured frame into green rain.
//
// Each column has its own start delay and speed, so the screen comes apart
// unevenly, the way the effect it is imitating does. A column's "head" descends
// through the text; characters at the head are lit, those just above it fade,
// and everything further above has already fallen away.
type dissolve struct {
	lines  [][]rune
	width  int
	height int

	delay []int // frames before column c starts falling
	speed []int // rows per frame for column c
	noise []int // per-cell random seed offset, flattened row-major

	frame  int
	frames int
}

const (
	litTrail  = 2  // rows at the head drawn bright
	fadeTrail = 7  // rows behind the head drawn dim
	minSpeed  = 1  // rows per frame
	maxSpeed  = 3  //
	maxDelay  = 14 // frames
)

// newDissolve captures a rendered view and prepares the animation.
func newDissolve(view string, width, height int, rng *rand.Rand) *dissolve {
	raw := strings.Split(strings.TrimRight(view, "\n"), "\n")
	if height > 0 && len(raw) > height {
		raw = raw[:height]
	}

	d := &dissolve{height: len(raw)}
	for _, line := range raw {
		// Strip styling: the animation supplies its own colours, and leaving
		// escape sequences in would corrupt per-cell replacement.
		plain := []rune(ansi.Strip(line))
		if len(plain) > d.width {
			d.width = len(plain)
		}
		d.lines = append(d.lines, plain)
	}
	if width > 0 && d.width > width {
		d.width = width
	}
	for i, l := range d.lines {
		if len(l) < d.width {
			d.lines[i] = append(l, []rune(strings.Repeat(" ", d.width-len(l)))...)
		} else {
			d.lines[i] = l[:d.width]
		}
	}

	d.delay = make([]int, d.width)
	d.speed = make([]int, d.width)
	for c := range d.delay {
		d.delay[c] = rng.Intn(maxDelay + 1)
		d.speed[c] = minSpeed + rng.Intn(maxSpeed-minSpeed+1)
	}
	d.noise = make([]int, d.width*d.height)
	for i := range d.noise {
		d.noise[i] = rng.Intn(len(matrixRunes))
	}

	// The animation ends once the slowest column has cleared its trail.
	d.frames = 1
	for c := range d.delay {
		if n := d.delay[c] + (d.height+fadeTrail)/d.speed[c] + 2; n > d.frames {
			d.frames = n
		}
	}
	return d
}

// Done reports whether the animation has finished.
func (d *dissolve) Done() bool { return d.frame >= d.frames }

// Advance steps one frame.
func (d *dissolve) Advance() { d.frame++ }

// View renders the current frame.
//
// The two greens are derived from the palette's OK colour rather than being a
// pair of their own: the rain is decoration, and decoration does not get to
// introduce colours the rest of the interface has never heard of.
func (d *dissolve) View() string {
	lit := lipgloss.NewStyle().Foreground(ui.ColorOK).Bold(true)
	dim := lipgloss.NewStyle().Foreground(ui.ColorOK).Faint(true)

	var b strings.Builder
	for r := 0; r < d.height; r++ {
		var line strings.Builder
		for c := 0; c < d.width; c++ {
			head := (d.frame - d.delay[c]) * d.speed[c]
			depth := head - r
			switch {
			case d.frame < d.delay[c] || depth < 0:
				line.WriteRune(d.lines[r][c])
			case depth < litTrail:
				line.WriteString(lit.Render(string(d.runeAt(r, c))))
			case depth < fadeTrail:
				line.WriteString(dim.Render(string(d.runeAt(r, c))))
			default:
				line.WriteByte(' ')
			}
		}
		b.WriteString(strings.TrimRight(line.String(), " "))
		if r < d.height-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// runeAt picks this cell's glyph. It advances slowly with the frame counter so
// the rain shimmers without turning into unreadable static.
func (d *dissolve) runeAt(row, col int) rune {
	i := (d.noise[row*d.width+col] + d.frame/2) % len(matrixRunes)
	return matrixRunes[i]
}
