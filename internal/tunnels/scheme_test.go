package tunnels

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSchemeNext(t *testing.T) {
	tests := []struct {
		in   Scheme
		want Scheme
	}{
		{SchemeUnknown, SchemeHTTP},
		{SchemeHTTP, SchemeHTTPS},
		{SchemeHTTPS, SchemeUnknown},
		{Scheme("garbage"), SchemeHTTP},
	}
	for _, tt := range tests {
		if got := tt.in.Next(); got != tt.want {
			t.Errorf("Scheme(%q).Next() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseScheme(t *testing.T) {
	tests := map[string]Scheme{
		"http":  SchemeHTTP,
		"https": SchemeHTTPS,
		"":      SchemeUnknown,
		"ftp":   SchemeUnknown,
	}
	for in, want := range tests {
		if got := ParseScheme(in); got != want {
			t.Errorf("ParseScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// An unknown scheme still opens as http, because that is right far more often
// than not on a development box.
func TestSchemeURLScheme(t *testing.T) {
	tests := map[Scheme]string{
		SchemeUnknown: "http",
		SchemeHTTP:    "http",
		SchemeHTTPS:   "https",
	}
	for in, want := range tests {
		if got := in.URLScheme(); got != want {
			t.Errorf("Scheme(%q).URLScheme() = %q, want %q", in, got, want)
		}
	}
}

func TestSchemeLabel(t *testing.T) {
	// Plain words, not punctuation the reader has to decode.
	if got := SchemeUnknown.Label(); got != "unknown" {
		t.Errorf("unknown label = %q, want unknown", got)
	}
	if got := SchemeHTTPS.Label(); got != "https" {
		t.Errorf("https label = %q", got)
	}
}

// storedScheme reports what a port's scheme was persisted as, if anything.
func storedScheme(s *Store, port int) (string, bool) {
	p := s.Port(port)
	return p.Scheme, p.Scheme != ""
}

func TestManagerCycleSchemeIsRemembered(t *testing.T) {
	echo := newEchoServer(t)
	store := NewStore(newFakeConfig())
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy:   DefaultPolicy(),
		Settings: store,
	})
	defer m.Close()

	port := freePort(t)
	m.Sync(snapshotOf(port))

	if got := m.CycleScheme(port); got != SchemeHTTP {
		t.Fatalf("first cycle = %q, want http", got)
	}
	if got, ok := storedScheme(store, port); !ok || got != "http" {
		t.Errorf("the choice was not persisted: %q, %v", got, ok)
	}
	if st := stateFor(t, m, port); st.Scheme != SchemeHTTP || !st.SchemePinned {
		t.Errorf("state = %q pinned %v, want http/true", st.Scheme, st.SchemePinned)
	}
	if got := stateFor(t, m, port).URL(); got == "" {
		t.Error("an active tunnel should have a URL")
	}

	if got := m.CycleScheme(port); got != SchemeHTTPS {
		t.Fatalf("second cycle = %q, want https", got)
	}
	if got := stateFor(t, m, port).URL(); got[:5] != "https" {
		t.Errorf("URL = %q, want an https URL", got)
	}

	// Cycling back to unknown clears the memory rather than storing a blank.
	if got := m.CycleScheme(port); got != SchemeUnknown {
		t.Fatalf("third cycle = %q, want unknown", got)
	}
	if _, ok := storedScheme(store, port); ok {
		t.Error("cycling back to unknown should forget the entry")
	}
	if st := stateFor(t, m, port); st.SchemePinned {
		t.Error("unknown should release the pin so detection can run again")
	}
}

func TestManagerRestoresRememberedScheme(t *testing.T) {
	echo := newEchoServer(t)
	store := NewStore(newFakeConfig())
	port := freePort(t)
	store.SetPort(port, PortPrefs{Scheme: "https"})

	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy:   DefaultPolicy(),
		Settings: store,
	})
	defer m.Close()

	m.Sync(snapshotOf(port))

	st := stateFor(t, m, port)
	if st.Scheme != SchemeHTTPS {
		t.Errorf("scheme = %q, want the remembered https", st.Scheme)
	}
	if !st.SchemePinned {
		t.Error("a remembered scheme should be pinned")
	}
}

func TestManagerSetSchemeDirectly(t *testing.T) {
	echo := newEchoServer(t)
	store := NewStore(newFakeConfig())
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{
		Policy: DefaultPolicy(), Settings: store,
	})
	defer m.Close()
	port := freePort(t)
	m.Sync(snapshotOf(port))

	if got := m.SetScheme(port, SchemeHTTPS); got != SchemeHTTPS {
		t.Fatalf("SetScheme = %q", got)
	}
	if st := stateFor(t, m, port); st.Scheme != SchemeHTTPS || !st.SchemePinned {
		t.Errorf("state = %q pinned %v", st.Scheme, st.SchemePinned)
	}
	if got := store.Port(port).Scheme; got != "https" {
		t.Errorf("remembered scheme = %q", got)
	}
}

func TestSniffScheme(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want Scheme
	}{
		{"tls handshake", []byte{0x16, 0x03, 0x01, 0x00}, SchemeHTTPS},
		{"tls alert", []byte{0x15, 0x03, 0x01}, SchemeHTTPS},
		{"http status line", []byte("HTTP/1.1 200 OK"), SchemeHTTP},
		{"http 400", []byte("HTTP/1.0 400 Bad Request"), SchemeHTTP},
		{"ssh banner", []byte("SSH-2.0-OpenSSH"), SchemeUnknown},
		{"postgres", []byte{0x52, 0x00, 0x00}, SchemeUnknown},
		{"empty", nil, SchemeUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SniffScheme(tt.in); got != tt.want {
				t.Errorf("SniffScheme(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The service is identified from bytes already crossing the tunnel. Nothing is
// sent to it that a client did not send, so a plain HTTP server never logs a
// mysterious binary request.
func TestManagerLearnsTheSchemeFromTraffic(t *testing.T) {
	reply := newReplyServer(t, "HTTP/1.1 200 OK\r\n\r\nhi")
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: reply}, ManagerOptions{
		Policy: DefaultPolicy(),
	})
	defer m.Close()

	port := freePort(t)
	m.Sync(snapshotOf(port))

	st := stateFor(t, m, port)
	if st.Scheme != SchemeUnknown {
		t.Fatalf("scheme = %q before any traffic, want unknown", st.Scheme)
	}

	// One real connection is all it takes.
	if got := readAll(t, st.LocalPort); !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("reply = %q", got)
	}
	waitUntil(t, func() bool {
		return stateFor(t, m, port).Scheme == SchemeHTTP
	}, "the scheme to be learned from the reply")
}

// A TLS service answers a plaintext request with an alert record, which is
// exactly the case worth catching.
func TestManagerLearnsHTTPSFromATLSAlert(t *testing.T) {
	reply := newReplyServer(t, "\x15\x03\x01\x00\x02\x02\x46")
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: reply}, ManagerOptions{
		Policy: DefaultPolicy(),
	})
	defer m.Close()

	port := freePort(t)
	m.Sync(snapshotOf(port))

	readAll(t, stateFor(t, m, port).LocalPort)
	waitUntil(t, func() bool {
		return stateFor(t, m, port).Scheme == SchemeHTTPS
	}, "an alert record to be read as https")
}

// Sniffing must not eat or reorder the reply.
func TestSniffingRelaysTheReplyIntact(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	reply := newReplyServer(t, body)
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: reply}, ManagerOptions{Policy: DefaultPolicy()})
	defer m.Close()

	port := freePort(t)
	m.Sync(snapshotOf(port))

	if got := readAll(t, stateFor(t, m, port).LocalPort); got != body {
		t.Errorf("relayed %q, want the reply unchanged", got)
	}
}

// A reply shorter than the sniff window must still arrive.
func TestSniffingRelaysAShortReply(t *testing.T) {
	reply := newReplyServer(t, "ok")
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: reply}, ManagerOptions{Policy: DefaultPolicy()})
	defer m.Close()

	port := freePort(t)
	m.Sync(snapshotOf(port))

	if got := readAll(t, stateFor(t, m, port).LocalPort); got != "ok" {
		t.Errorf("relayed %q, want %q", got, "ok")
	}
}

func TestObservedSchemeDoesNotOverrideAPin(t *testing.T) {
	store := NewStore(newFakeConfig())
	port := freePort(t)
	store.SetPort(port, PortPrefs{Scheme: "http"})

	// The service answers with a TLS record, which would otherwise be read as
	// https and overwrite the pin.
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: newReplyServer(t, "\x16\x03\x01")}, ManagerOptions{
		Policy:   DefaultPolicy(),
		Settings: store,
	})
	defer m.Close()

	m.Sync(snapshotOf(port))

	readAll(t, stateFor(t, m, port).LocalPort)
	time.Sleep(200 * time.Millisecond)
	if st := stateFor(t, m, port); st.Scheme != SchemeHTTP {
		t.Errorf("scheme = %q, want the pinned http to survive what the wire said", st.Scheme)
	}
}

func TestManagerCycleSchemeOnAnUnknownPort(t *testing.T) {
	echo := newEchoServer(t)
	m := NewManager(NewAllocator("127.0.0.1", false), &fixedDialer{addr: echo.addr()}, ManagerOptions{Policy: DefaultPolicy()})
	defer m.Close()

	if got := m.CycleScheme(9999); got != SchemeUnknown {
		t.Errorf("CycleScheme on an unknown port = %q, want unknown", got)
	}
}

// newReplyServer accepts a connection, sends a fixed reply and closes.
func newReplyServer(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, reply)
			}()
		}
	}()
	return ln.Addr().String()
}

// readAll opens a local tunnel port and reads until the far side closes.
func readAll(t *testing.T, port int) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("dialing local port %d: %v", port, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	return string(data)
}
