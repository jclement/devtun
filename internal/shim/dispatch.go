// The remote side's entry point: what happens once argv[0] has decided which
// service an invocation belongs to.
package shim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"
)

// Streams groups the shim's own stdio, passed explicitly so every dispatch
// path is testable without a terminal.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
	// InIsTerminal suppresses reading stdin. Without it, a passthrough command
	// run interactively would block forever waiting for input nobody is going
	// to type.
	InIsTerminal bool
}

// RunAsShim is the whole remote-side entry point: main dispatches on argv[0],
// and everything after that decision happens here. name is os.Args[0] and argv
// is the rest.
func RunAsShim(ctx context.Context, name string, argv []string, version string) int {
	// The handshake is answered before the argv[0] lookup, deliberately: the
	// session runs it against ~/.devtun/devtun-shim, which is the binary
	// itself rather than one of the symlinked names. It is also the only
	// reliable way to tell this binary from the real 1Password CLI.
	if len(argv) == 1 && argv[0] == VersionFlag {
		fmt.Printf("%s %s\n", Handshake, version)
		return 0
	}

	svc, ok := ServiceFor(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "devtun: %s is not a name the shim answers to\n", filepath.Base(name))
		return 1
	}

	c, err := NewClient("", version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "devtun: "+err.Error())
		return 1
	}
	streams := Streams{
		In:           os.Stdin,
		Out:          os.Stdout,
		Err:          os.Stderr,
		InIsTerminal: term.IsTerminal(int(os.Stdin.Fd())),
	}

	switch svc {
	case ServiceOp:
		return c.DispatchOp(ctx, argv, streams)
	case ServiceOpen:
		return c.DispatchOpen(ctx, argv, streams)
	default:
		// ShimNames has gained a service that nothing here knows how to run,
		// which is a wiring mistake and should say so rather than exit 0.
		fmt.Fprintf(os.Stderr, "devtun: no shim behaviour for the %q service\n", svc)
		return 1
	}
}

// converse sends one request and reads the reply on a connection of its own,
// matching the session, which serves exactly one request per connection.
func (c *Client) converse(ctx context.Context, svc string, timeout time.Duration, request, response any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := c.Open(ctx, svc)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Closing the connection when the context ends is what interrupts a
	// blocked read: a connection forwarded over SSH ignores SetDeadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := WriteFrame(conn, request); err != nil {
		return fmt.Errorf("sending the request: %w", err)
	}
	if err := ReadFrame(conn, response); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("devtun did not answer within %s", timeout)
		}
		if errors.Is(err, io.EOF) {
			return errors.New("devtun closed the connection without answering")
		}
		return fmt.Errorf("reading the response: %w", err)
	}
	return nil
}

// fail reports a shim-level error and yields the conventional exit code for
// one. It never prints a secret, because by definition nothing was fetched.
func fail(s Streams, err error) int {
	fmt.Fprintln(s.Err, "devtun: "+err.Error())
	return 1
}
