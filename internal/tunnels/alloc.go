package tunnels

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// ListenFunc opens a local listening socket. It is a field on Allocator so
// tests can inject failures without racing real ports.
type ListenFunc func(network, address string) (net.Listener, error)

// Allocator hands out local ports for remote services.
//
// It always prefers to mirror the remote port number, because typing
// localhost:3000 for a remote :3000 is the entire point. When that port is
// busy it falls back to an ephemeral port and flags the mapping as remapped,
// so the UI can mark it — a silently different port is a debugging trap.
type Allocator struct {
	bind     string
	samePort bool
	listen   ListenFunc

	mu     sync.Mutex
	sticky map[int]int // remote port -> local port last used
}

// NewAllocator returns an Allocator binding local listeners to bind.
// If samePort is set, a busy local port is an error rather than a remap.
func NewAllocator(bind string, samePort bool) *Allocator {
	if bind == "" {
		bind = "127.0.0.1"
	}
	return &Allocator{
		bind:     bind,
		samePort: samePort,
		listen:   net.Listen,
		sticky:   map[int]int{},
	}
}

// ConflictError reports that a desired local port could not be bound.
type ConflictError struct {
	Port int
	Err  error
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("local port %d is already in use", e.Port)
}
func (e *ConflictError) Unwrap() error { return e.Err }

// Allocate opens a local listener for the given remote port.
//
// Preference order: the port the user pinned for this service, then the one it
// used previously (so a reconnect does not invalidate open browser tabs), then
// the remote port itself, then an ephemeral port.
func (a *Allocator) Allocate(remotePort, preferred int) (net.Listener, bool, error) {
	a.mu.Lock()
	prev, hasPrev := a.sticky[remotePort]
	a.mu.Unlock()

	var firstErr error
	try := func(port int) (net.Listener, bool) {
		ln, err := a.listen("tcp", net.JoinHostPort(a.bind, strconv.Itoa(port)))
		if err != nil {
			if firstErr == nil {
				firstErr = &ConflictError{Port: port, Err: err}
			}
			return nil, false
		}
		return ln, true
	}

	if preferred > 0 {
		if ln, ok := try(preferred); ok {
			return a.record(remotePort, ln), preferred != remotePort, nil
		}
	}
	if hasPrev && prev != remotePort {
		if ln, ok := try(prev); ok {
			return a.record(remotePort, ln), true, nil
		}
	}
	if ln, ok := try(remotePort); ok {
		return a.record(remotePort, ln), false, nil
	}
	if a.samePort {
		return nil, false, firstErr
	}
	ln, err := a.listen("tcp", net.JoinHostPort(a.bind, "0"))
	if err != nil {
		return nil, false, errors.Join(firstErr, err)
	}
	return a.record(remotePort, ln), true, nil
}

// record remembers the assignment so a later reconnect can reuse it.
func (a *Allocator) record(remotePort int, ln net.Listener) net.Listener {
	a.mu.Lock()
	a.sticky[remotePort] = LocalPort(ln)
	a.mu.Unlock()
	return ln
}

// Forget drops the remembered local port for a remote port.
func (a *Allocator) Forget(remotePort int) {
	a.mu.Lock()
	delete(a.sticky, remotePort)
	a.mu.Unlock()
}

// Bind reports the local address listeners are bound to.
func (a *Allocator) Bind() string { return a.bind }

// LocalPort extracts the port a listener actually bound.
func LocalPort(ln net.Listener) int {
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		return ta.Port
	}
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
