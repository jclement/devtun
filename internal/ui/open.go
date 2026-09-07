package ui

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// OpenURL hands a URL to the platform's browser.
//
// The URL always originates on the remote box, so it is never trusted as a
// command line: every launcher here takes it as a single argument to a fixed
// program, never through a shell. A URL containing `; rm -rf ~` is then just a
// URL that fails to resolve, rather than a sentence the shell reads.
func OpenURL(ctx context.Context, rawURL string) error {
	// Reject anything that is not plainly a web URL before it reaches an
	// launcher. `open` on macOS will happily act on file:// and custom
	// schemes, and the remote box does not get to choose which.
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return fmt.Errorf("refusing to open %q: only http and https URLs are opened", rawURL)
	}

	name, args := launcher()
	if name == "" {
		return fmt.Errorf("no way to open a browser on %s", runtime.GOOS)
	}
	cmd := exec.CommandContext(ctx, name, append(args, rawURL)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		if detail := strings.TrimSpace(string(out)); detail != "" {
			return fmt.Errorf("%s: %s", name, detail)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// launcher returns the platform's URL opener.
func launcher() (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", nil
	case "windows":
		// rundll32 avoids `cmd /c start`, whose argument quoting is its own
		// small horror and which would put a remote-supplied string in front
		// of a shell.
		return "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		for _, candidate := range []string{"xdg-open", "gio", "sensible-browser", "x-www-browser"} {
			if path, err := exec.LookPath(candidate); err == nil {
				if candidate == "gio" {
					return path, []string{"open"}
				}
				return path, nil
			}
		}
		return "", nil
	}
}

// OpenerName is the program a URL would be handed to on this machine, empty
// when there is none. It is what `devtun doctor` reports: "the browser service
// is running" and "a URL can actually be opened here" are different claims, and
// on a bare Linux box without xdg-open only the first one is true.
func OpenerName() string {
	name, _ := launcher()
	return name
}
