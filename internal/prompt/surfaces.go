package prompt

import (
	"fmt"
	"strings"
)

// Where an approval appears.
//
// This used to be one choice out of four, and the shape was wrong. devtun runs
// in a window you are not looking at — that is the premise of the whole thing —
// so "which single place should the question appear" is a question with no good
// answer. Put it in the terminal and you miss it because you are in a browser.
// Put it on the board and you miss it because the board is on the other
// monitor. Whichever one you pick is the one you were not looking at, and a
// request nobody sees becomes a timeout, and a timeout reads as a refusal
// nobody made.
//
// So the default is every surface at once, and the first answer wins. Naming
// one is still allowed — an unattended box that should only ever be answered
// from the board, a machine where a dialog would be drawn on a screen nobody
// can see — but it is now a deliberate narrowing rather than the only option.

// Surface is one place a question can be put.
type Surface string

const (
	// SurfaceTUI is the terminal devtun is running in: the interface's modal
	// when the interface is up, and a form in the terminal when it is not.
	SurfaceTUI Surface = "tui"
	// SurfaceNative is the desktop dialog — prettyprompt where it is
	// installed, and whatever the platform supplies otherwise.
	SurfaceNative Surface = "native"
	// SurfaceWeb is the board in a browser, which only exists under --web.
	SurfaceWeb Surface = "web"
)

// AllSurfaces is every surface, in the order they are listed in help and in
// the settings screen.
var AllSurfaces = []Surface{SurfaceTUI, SurfaceNative, SurfaceWeb}

// Surfaces is where a session will ask. Empty means deny: there is nowhere to
// put the question, so the answer is the zero value of a decision.
type Surfaces struct {
	set map[Surface]bool
}

// ParseSurfaces reads the --prompt value, or the `prompt:` setting.
//
// Accepts "all", "deny", a single surface, or a comma-separated list. The two
// names this setting used to have are still accepted and always will be:
// "auto" was the old default and means all, and "dialog" is what "native" was
// called. A config file that has been sitting on somebody's disk since before
// this changed keeps working.
func ParseSurfaces(value string) (Surfaces, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "all", "auto":
		return Surfaces{set: setOf(AllSurfaces...)}, nil
	case "deny", "none":
		return Surfaces{set: map[Surface]bool{}}, nil
	}

	out := map[Surface]bool{}
	for _, part := range strings.Split(value, ",") {
		switch name := Surface(strings.TrimSpace(part)); name {
		case SurfaceTUI, SurfaceNative, SurfaceWeb:
			out[name] = true
		case "dialog":
			out[SurfaceNative] = true
		case "":
			continue
		default:
			return Surfaces{}, fmt.Errorf("unknown prompt surface %q (want all, deny, or any of %s)",
				name, strings.Join(surfaceNames(), ", "))
		}
	}
	if len(out) == 0 {
		return Surfaces{}, fmt.Errorf("no prompt surface in %q", value)
	}
	return Surfaces{set: out}, nil
}

// MustParseSurfaces is ParseSurfaces for a value known good, such as a default.
func MustParseSurfaces(value string) Surfaces {
	s, err := ParseSurfaces(value)
	if err != nil {
		panic(err)
	}
	return s
}

// Has reports whether a question goes to this surface.
func (s Surfaces) Has(name Surface) bool { return s.set[name] }

// Any reports whether there is anywhere at all to ask. False is `deny`.
func (s Surfaces) Any() bool { return len(s.set) > 0 }

// Names lists the chosen surfaces in a stable order, for a message.
func (s Surfaces) Names() []string {
	var out []string
	for _, name := range AllSurfaces {
		if s.set[name] {
			out = append(out, string(name))
		}
	}
	return out
}

// String is the value that would parse back to this set: "all", "deny", or the
// list. It is what the settings screen shows and what gets written to a file.
func (s Surfaces) String() string {
	if !s.Any() {
		return "deny"
	}
	names := s.Names()
	if len(names) == len(AllSurfaces) {
		return "all"
	}
	return strings.Join(names, ",")
}

// Without removes a surface that does not exist in this session, so the set
// describes where a question will actually go rather than where it was aimed.
func (s Surfaces) Without(name Surface) Surfaces {
	out := map[Surface]bool{}
	for k := range s.set {
		if k != name {
			out[k] = true
		}
	}
	return Surfaces{set: out}
}

func setOf(names ...Surface) map[Surface]bool {
	out := make(map[Surface]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

func surfaceNames() []string {
	out := make([]string, 0, len(AllSurfaces))
	for _, name := range AllSurfaces {
		out = append(out, string(name))
	}
	return out
}

// PrompterFor builds the prompter for one surface.
//
// SurfaceWeb has none: the board watches the desk rather than being asked, so
// it is a surface in the sense that matters to a person and not a Prompter.
//
// The dialog gets no fallback here. Under `all` the terminal is already being
// asked alongside it, so falling back would ask twice; and when somebody has
// named `native` on its own, quietly asking somewhere else is not honouring
// what they asked for. A dialog that cannot be drawn is a surface that does not
// answer, which the desk already understands.
func PrompterFor(surface Surface) (Prompter, error) {
	switch surface {
	case SurfaceTUI:
		return Serialize(&TUI{}), nil
	case SurfaceNative:
		if !dialogAvailable() {
			return nil, fmt.Errorf("no desktop dialog program here: devtun looked for %s",
				strings.Join(ChooserNames(), ", "))
		}
		return Serialize(&Dialog{}), nil
	case SurfaceWeb:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown prompt surface %q", surface)
	}
}

// Available reports whether a surface can exist in this session at all.
//
// tui is a terminal to draw in — the interface's modal when the interface is
// running, a form in the terminal when it is not. web is the board, which
// exists only when one was asked for.
func Available(surface Surface, interactive, web bool) bool {
	switch surface {
	case SurfaceTUI:
		return interactive
	case SurfaceNative:
		return dialogAvailable()
	case SurfaceWeb:
		return web
	}
	return false
}

// Why says what is missing, for the error when somebody names a surface this
// session cannot offer.
func Why(surface Surface) string {
	switch surface {
	case SurfaceTUI:
		return "this is not a terminal"
	case SurfaceNative:
		return "no desktop dialog program here: devtun looked for " + strings.Join(ChooserNames(), ", ")
	case SurfaceWeb:
		return "the board is not running — add --web"
	}
	return "unknown surface"
}
