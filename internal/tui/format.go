package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
)

// FormatBytes renders a byte count in the shortest unambiguous form.
func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	suffix := [...]string{"KB", "MB", "GB", "TB", "PB"}[exp]
	if val < 10 {
		return fmt.Sprintf("%.1f %s", val, suffix)
	}
	return fmt.Sprintf("%.0f %s", val, suffix)
}

// FormatAge renders a duration compactly: 4s, 12m, 3h07, 2d04.
func FormatAge(d time.Duration) string {
	switch {
	case d < 0:
		return "—"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02d", int(d.Hours()), int(d.Minutes())%60)
	case d < 100*24*time.Hour:
		return fmt.Sprintf("%dd%02d", int(d.Hours())/24, int(d.Hours())%24)
	default:
		// Past 100 days the hours stop earning their column width.
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}

// FormatUptime renders a clock-style elapsed time for the header.
func FormatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, (total/60)%60, total%60)
}

// pad left-aligns s in a field of width w, truncating with an ellipsis.
func pad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > w {
		return ansi.Truncate(s, w, "…")
	}
	return s + strings.Repeat(" ", w-ansi.StringWidth(s))
}

// padLeft right-aligns s in a field of width w.
func padLeft(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) > w {
		return ansi.Truncate(s, w, "…")
	}
	return strings.Repeat(" ", w-ansi.StringWidth(s)) + s
}

// clampWidth trims a rendered line so it can never wrap.
func clampWidth(s string, w int) string {
	if w <= 0 || ansi.StringWidth(s) <= w {
		return s
	}
	// An ellipsis, so a line that has been cut says so. Without one a sentence
	// simply stops — and a reader cannot tell a truncated help string from a
	// terse one, or a shortened URL from a broken one.
	if w > 1 {
		return ansi.Truncate(s, w, "…")
	}
	return ansi.Truncate(s, w, "")
}

// firstLine keeps a multi-line error readable inside a box.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
