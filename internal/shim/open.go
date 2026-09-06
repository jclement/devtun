// xdg-open and friends on the remote box.
//
// Everything these names are asked to do is one round trip: hand the URL to
// the workstation, which decides what it points at and opens it there. The
// shim has no view on the URL at all — rewriting a loopback port to the one its
// tunnel landed on is the session's job, and it is the only side that knows.
package shim

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// openCallTimeout bounds a whole open exchange. It is far shorter than the
// `op` one because nothing on the other end waits for a human: the session
// gives the tunnel a few seconds to appear and the platform opener a few more.
// A program that shelled out to xdg-open should not hang for minutes because
// the workstation wedged.
const openCallTimeout = 30 * time.Second

// DispatchOpen runs one opener invocation and returns the process exit code.
func (c *Client) DispatchOpen(ctx context.Context, argv []string, s Streams) int {
	c.Notify = s.Err

	// `gio open URL` is how some desktop stacks spell xdg-open, so the
	// subcommand is shifted off before the URL is read.
	if len(argv) > 1 && argv[0] == "open" && argv[1] != "" {
		argv = argv[1:]
	}
	if len(argv) == 0 || argv[0] == "" {
		return fail(s, errors.New("no URL given"))
	}
	url := argv[0]

	var response openResponse
	if err := c.converse(ctx, ServiceOpen, openCallTimeout, openRequest{URL: url}, &response); err != nil {
		return handItBack(s, url, err.Error())
	}
	if !response.OK {
		reason := response.Error
		if reason == "" {
			reason = "the workstation refused it"
		}
		return handItBack(s, url, reason)
	}
	return 0
}

// handItBack tells the user what they now have to do themselves.
//
// There is deliberately no fallback to a real opener: ~/.devtun/bin sits ahead
// of it on PATH, so exec'ing xdg-open from here would find this binary again
// and recurse. Printing the URL is the honest end of the line, and it goes to
// stderr because a program that captured our stdout is not expecting one.
func handItBack(s Streams, url, reason string) int {
	fmt.Fprintf(s.Err, "devtun: %s; open this yourself:\n", reason)
	fmt.Fprintf(s.Err, "  %s\n", url)
	return 1
}
