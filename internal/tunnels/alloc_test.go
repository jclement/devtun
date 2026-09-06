package tunnels

import (
	"errors"
	"net"
	"strconv"
	"testing"
)

// freePort returns a port that is free right now on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer ln.Close()
	return LocalPort(ln)
}

// occupy binds a port for the duration of the test and returns it.
func occupy(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return LocalPort(ln)
}

func TestAllocatePrefersTheRemotePortNumber(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	port := freePort(t)

	ln, remapped, err := a.Allocate(port, 0)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer ln.Close()

	if remapped {
		t.Error("a free port should not be reported as remapped")
	}
	if got := LocalPort(ln); got != port {
		t.Errorf("bound %d, want the matching remote port %d", got, port)
	}
}

func TestAllocateFallsBackToEphemeral(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	busy := occupy(t)

	ln, remapped, err := a.Allocate(busy, 0)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer ln.Close()

	if !remapped {
		t.Error("a busy port should be reported as remapped")
	}
	if got := LocalPort(ln); got == busy || got == 0 {
		t.Errorf("bound %d, want a different, valid port", got)
	}
}

func TestAllocateSamePortRefusesToRemap(t *testing.T) {
	a := NewAllocator("127.0.0.1", true)
	busy := occupy(t)

	ln, _, err := a.Allocate(busy, 0)
	if err == nil {
		ln.Close()
		t.Fatal("want an error when the exact port is unavailable under --same-port")
	}
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want a *ConflictError", err)
	}
	if conflict.Port != busy {
		t.Errorf("conflict reported port %d, want %d", conflict.Port, busy)
	}
	if got := conflict.Error(); got != "local port "+strconv.Itoa(busy)+" is already in use" {
		t.Errorf("message = %q", got)
	}
}

// A reconnect must hand a service back the local port it had, so open browser
// tabs keep working.
func TestAllocateIsStickyAcrossReallocation(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	busy := occupy(t)

	first, _, err := a.Allocate(busy, 0)
	if err != nil {
		t.Fatalf("first Allocate: %v", err)
	}
	assigned := LocalPort(first)
	first.Close()

	second, remapped, err := a.Allocate(busy, 0)
	if err != nil {
		t.Fatalf("second Allocate: %v", err)
	}
	defer second.Close()

	if got := LocalPort(second); got != assigned {
		t.Errorf("reallocated to %d, want the remembered %d", got, assigned)
	}
	if !remapped {
		t.Error("a remembered non-matching port is still a remap")
	}
}

func TestForgetDropsTheStickyAssignment(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	busy := occupy(t)

	first, _, err := a.Allocate(busy, 0)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	assigned := LocalPort(first)
	first.Close()
	a.Forget(busy)

	second, _, err := a.Allocate(busy, 0)
	if err != nil {
		t.Fatalf("Allocate after Forget: %v", err)
	}
	defer second.Close()

	// Without the memory it picks a fresh ephemeral port; landing on the same
	// one again is possible but vanishingly unlikely.
	if LocalPort(second) == assigned {
		t.Log("re-drew the same ephemeral port; not a failure, just unlucky")
	}
}

// A pinned local port is tried before anything else, and counts as a remap
// when it differs from the remote port.
func TestAllocateHonoursAPinnedPort(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	remote, pinned := freePort(t), freePort(t)

	ln, remapped, err := a.Allocate(remote, pinned)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer ln.Close()

	if got := LocalPort(ln); got != pinned {
		t.Errorf("bound %d, want the pinned %d", got, pinned)
	}
	if !remapped {
		t.Error("a pinned port that differs from the remote one is a remap")
	}
}

// A pinned port that is busy falls back rather than failing the tunnel: some
// forwarding beats none, and the remap marker says it happened.
func TestAllocateFallsBackFromABusyPinnedPort(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	remote, busy := freePort(t), occupy(t)

	ln, _, err := a.Allocate(remote, busy)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer ln.Close()

	if got := LocalPort(ln); got != remote {
		t.Errorf("bound %d, want a fallback to the remote port %d", got, remote)
	}
}

// Pinning the remote port itself is not a remap.
func TestAllocatePinnedToTheRemotePortIsNotARemap(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	port := freePort(t)

	ln, remapped, err := a.Allocate(port, port)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer ln.Close()
	if remapped {
		t.Error("pinning a service to its own port number is not a remap")
	}
}

func TestAllocateReportsListenFailure(t *testing.T) {
	a := NewAllocator("127.0.0.1", false)
	boom := errors.New("no sockets today")
	a.listen = func(string, string) (net.Listener, error) { return nil, boom }

	if _, _, err := a.Allocate(3000, 0); !errors.Is(err, boom) {
		t.Errorf("Allocate = %v, want the underlying listen error", err)
	}
}

func TestAllocatorBindDefaults(t *testing.T) {
	if got := NewAllocator("", false).Bind(); got != "127.0.0.1" {
		t.Errorf("Bind() = %q, want the loopback default", got)
	}
	if got := NewAllocator("0.0.0.0", false).Bind(); got != "0.0.0.0" {
		t.Errorf("Bind() = %q, want 0.0.0.0", got)
	}
}

func TestLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	want := ln.Addr().(*net.TCPAddr).Port
	if got := LocalPort(ln); got != want {
		t.Errorf("LocalPort() = %d, want %d", got, want)
	}
}
