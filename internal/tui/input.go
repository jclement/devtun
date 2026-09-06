package tui

import (
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/jclement/devtun/internal/ui"
)

// textInput is a single-line editor. The search box and the two little
// per-port editors are the only text entry in the app, so a purpose-built
// hundred lines beats pulling in a widget library and its version churn.
type textInput struct {
	value  []rune
	cursor int
}

func (t *textInput) Value() string { return string(t.value) }

func (t *textInput) SetValue(s string) {
	t.value = []rune(s)
	t.cursor = len(t.value)
}

func (t *textInput) Reset() {
	t.value = t.value[:0]
	t.cursor = 0
}

// Update applies a key press, reporting whether it was consumed.
//
// Bubble Tea v2 reports printable input as Key.Text rather than as a rune
// slice and a key type, which collapses the old runes/space special case: if
// there is text, it is text, and space is no longer a key of its own.
func (t *textInput) Update(msg tea.KeyPressMsg) bool {
	switch msg.String() {
	case "backspace":
		if t.cursor > 0 {
			t.value = append(t.value[:t.cursor-1], t.value[t.cursor:]...)
			t.cursor--
		}
		return true
	case "delete":
		if t.cursor < len(t.value) {
			t.value = append(t.value[:t.cursor], t.value[t.cursor+1:]...)
		}
		return true
	case "left":
		if t.cursor > 0 {
			t.cursor--
		}
		return true
	case "right":
		if t.cursor < len(t.value) {
			t.cursor++
		}
		return true
	case "home", "ctrl+a":
		t.cursor = 0
		return true
	case "end", "ctrl+e":
		t.cursor = len(t.value)
		return true
	case "ctrl+u":
		t.value = t.value[:0]
		t.cursor = 0
		return true
	case "ctrl+w":
		t.deleteWord()
		return true
	}

	if msg.Text == "" {
		return false
	}
	for _, r := range msg.Text {
		if unicode.IsControl(r) {
			continue
		}
		t.value = append(t.value, 0)
		copy(t.value[t.cursor+1:], t.value[t.cursor:])
		t.value[t.cursor] = r
		t.cursor++
	}
	return true
}

func (t *textInput) deleteWord() {
	i := t.cursor
	for i > 0 && unicode.IsSpace(t.value[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(t.value[i-1]) {
		i--
	}
	t.value = append(t.value[:i], t.value[t.cursor:]...)
	t.cursor = i
}

// Render draws the value with a block cursor. The cursor is drawn rather than
// placed with tea.View's real one, because the editor lives in the frame's
// bottom border and a terminal cursor there would be lost against it.
func (t *textInput) Render() string {
	var b strings.Builder
	for i, r := range t.value {
		if i == t.cursor {
			b.WriteString(styleCursor().Render(string(r)))
		} else {
			b.WriteString(string(r))
		}
	}
	if t.cursor >= len(t.value) {
		b.WriteString(styleCursor().Render(" "))
	}
	return b.String()
}

// styleCursor is the block cursor. Reverse video rather than a colour of its
// own, so it stays visible when the palette has been stripped by --no-color.
func styleCursor() lipgloss.Style { return ui.Selected.Reverse(true) }
