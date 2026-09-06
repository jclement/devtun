package probe

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return string(b)
}

// find returns the listener for a port/proto pair.
func find(ls []Listener, port int, proto string) (Listener, bool) {
	for _, l := range ls {
		if l.Port == port && l.Proto == proto {
			return l, true
		}
	}
	return Listener{}, false
}

func TestParseSS(t *testing.T) {
	got := ParseSS(readFixture(t, "ss.txt"))
	if len(got) != 7 {
		t.Fatalf("got %d listeners, want 7: %+v", len(got), got)
	}

	tests := []struct {
		port  int
		proto string
		addr  string
		pid   int
		proc  string
	}{
		{53, "tcp", "127.0.0.53", 612, "systemd-resolve"},
		{22, "tcp", "0.0.0.0", 901, "sshd"},
		{3000, "tcp", "127.0.0.1", 14523, "node"},
		{8080, "tcp", "*", 2201, "java"},
		{22, "tcp6", "::", 901, "sshd"},
		{3000, "tcp6", "::1", 14523, "node"},
		{5432, "tcp", "127.0.0.1", 0, ""}, // no process attribution
	}
	for _, tt := range tests {
		l, ok := find(got, tt.port, tt.proto)
		if !ok {
			t.Errorf("no %s listener on port %d", tt.proto, tt.port)
			continue
		}
		if l.Addr != tt.addr || l.PID != tt.pid || l.Proc != tt.proc {
			t.Errorf("port %d/%s = %+v, want addr=%s pid=%d proc=%s",
				tt.port, tt.proto, l, tt.addr, tt.pid, tt.proc)
		}
	}
}

// The %lo zone suffix must not leak into the address.
func TestParseSSStripsZone(t *testing.T) {
	l, ok := find(ParseSS(readFixture(t, "ss.txt")), 53, "tcp")
	if !ok {
		t.Fatal("port 53 missing")
	}
	if l.Addr != "127.0.0.53" {
		t.Errorf("addr = %q, want 127.0.0.53", l.Addr)
	}
}

// Pre-iproute2-4 builds print users:(("name",pid,fd)) without the pid= label.
func TestParseSSLegacyProcessFormat(t *testing.T) {
	got := ParseSS(readFixture(t, "ss_old.txt"))
	if len(got) != 2 {
		t.Fatalf("got %d listeners, want 2", len(got))
	}
	if got[0].PID != 901 || got[0].Proc != "sshd" {
		t.Errorf("got %+v, want pid=901 proc=sshd", got[0])
	}
	if got[1].Port != 25 || got[1].PID != 1201 {
		t.Errorf("got %+v, want port=25 pid=1201", got[1])
	}
}

func TestParseSSContinuationLine(t *testing.T) {
	in := "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"LISTEN 0      511    127.0.0.1:3000     0.0.0.0:*\n" +
		"\tusers:((\"node\",pid=42,fd=7))\n"
	got := ParseSS(in)
	if len(got) != 1 {
		t.Fatalf("got %d listeners, want 1", len(got))
	}
	if got[0].PID != 42 || got[0].Proc != "node" {
		t.Errorf("continuation not folded in: %+v", got[0])
	}
}

func TestParseSSIgnoresNonListen(t *testing.T) {
	in := "ESTAB 0 0 127.0.0.1:3000 127.0.0.1:5555\nLISTEN 0 5 127.0.0.1:9000 0.0.0.0:*\n"
	got := ParseSS(in)
	if len(got) != 1 || got[0].Port != 9000 {
		t.Errorf("got %+v, want only port 9000", got)
	}
}

func TestParseNetstat(t *testing.T) {
	got := ParseNetstat(readFixture(t, "netstat.txt"))
	if len(got) != 5 {
		t.Fatalf("got %d listeners, want 5 (udp must be dropped): %+v", len(got), got)
	}
	tests := []struct {
		port  int
		proto string
		addr  string
		pid   int
		proc  string
	}{
		{3000, "tcp", "127.0.0.1", 14523, "node"},
		{22, "tcp", "0.0.0.0", 901, "sshd"},
		{5432, "tcp", "127.0.0.1", 0, ""},
		{22, "tcp6", "::", 901, "sshd"},
		{8080, "tcp6", "::1", 2201, "java"},
	}
	for _, tt := range tests {
		l, ok := find(got, tt.port, tt.proto)
		if !ok {
			t.Errorf("no %s listener on port %d", tt.proto, tt.port)
			continue
		}
		if l.Addr != tt.addr || l.PID != tt.pid || l.Proc != tt.proc {
			t.Errorf("port %d/%s = %+v, want addr=%s pid=%d proc=%s",
				tt.port, tt.proto, l, tt.addr, tt.pid, tt.proc)
		}
	}
}

func TestParseLsof(t *testing.T) {
	got := ParseLsof(readFixture(t, "lsof.txt"))
	// The established connection (n...->...) must be dropped.
	if len(got) != 4 {
		t.Fatalf("got %d listeners, want 4: %+v", len(got), got)
	}
	if l, ok := find(got, 22, "tcp"); !ok || l.Proc != "sshd" || l.PID != 901 {
		t.Errorf("sshd listener wrong: %+v", l)
	}
	if l, ok := find(got, 3000, "tcp6"); !ok || l.Addr != "::1" || l.Proc != "node" {
		t.Errorf("node v6 listener wrong: %+v", l)
	}
	if l, ok := find(got, 8080, "tcp6"); !ok || l.PID != 2201 || l.Proc != "java" {
		t.Errorf("java listener wrong: %+v", l)
	}
}

func TestParseProc(t *testing.T) {
	got := ParseProc(readFixture(t, "proc_net_tcp.txt"), readFixture(t, "proc_sockmap.txt"))
	// Two v4 listeners plus two v6; the ESTABLISHED row is dropped.
	if len(got) != 4 {
		t.Fatalf("got %d listeners, want 4: %+v", len(got), got)
	}

	l, ok := find(got, 3000, "tcp")
	if !ok {
		t.Fatal("no listener on 3000")
	}
	if l.Addr != "127.0.0.1" {
		t.Errorf("addr = %q, want 127.0.0.1 (little-endian hex decode)", l.Addr)
	}
	if l.PID != 14523 {
		t.Errorf("pid = %d, want 14523 (via socket inode 445566)", l.PID)
	}

	if l, ok := find(got, 22, "tcp"); !ok || l.Addr != "0.0.0.0" || l.PID != 1 {
		t.Errorf("sshd v4 = %+v, want 0.0.0.0 pid 1", l)
	}
	if l, ok := find(got, 22, "tcp6"); !ok || l.Addr != "::" || l.PID != 1 {
		t.Errorf("sshd v6 = %+v, want :: pid 1", l)
	}
	// An IPv4-mapped v6 address decodes back to dotted quad.
	if l, ok := find(got, 8081, "tcp"); !ok || l.Addr != "127.0.0.1" || l.PID != 14523 {
		t.Errorf("mapped v4 = %+v, want 127.0.0.1 pid 14523", l)
	}
}

func TestParseProcWithoutSockMap(t *testing.T) {
	got := ParseProc(readFixture(t, "proc_net_tcp.txt"), "")
	if len(got) != 4 {
		t.Fatalf("got %d listeners, want 4", len(got))
	}
	for _, l := range got {
		if l.PID != 0 {
			t.Errorf("expected no pid attribution without a sockmap, got %+v", l)
		}
	}
}

func TestParseProcAddr(t *testing.T) {
	tests := []struct {
		in   string
		addr string
		port int
		ok   bool
	}{
		{"0100007F:0BB8", "127.0.0.1", 3000, true},
		{"00000000:0016", "0.0.0.0", 22, true},
		{"00000000000000000000000000000000:1F90", "::", 8080, true},
		{"0000000000000000FFFF00000100007F:1F90", "127.0.0.1", 8080, true},
		{"0000000000000000000000000000000001:0016", "", 0, false}, // odd length
		{"notgood:0016", "", 0, false},
		{"0100007F", "", 0, false},
		{"0100007F:ZZZZ", "", 0, false},
	}
	for _, tt := range tests {
		addr, port, ok := parseProcAddr(tt.in)
		if ok != tt.ok || addr != tt.addr || port != tt.port {
			t.Errorf("parseProcAddr(%q) = %q, %d, %v; want %q, %d, %v",
				tt.in, addr, port, ok, tt.addr, tt.port, tt.ok)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in   string
		host string
		port int
		ok   bool
	}{
		{"127.0.0.1:3000", "127.0.0.1", 3000, true},
		{"[::1]:8080", "::1", 8080, true},
		{":::22", "::", 22, true},       // netstat's IPv6 wildcard
		{"::1:8080", "::1", 8080, true}, // netstat's IPv6 loopback
		{"*:22", "*", 22, true},
		{"0.0.0.0:0", "0.0.0.0", 0, true},
		{"[fe80::1%eth0]:546", "fe80::1", 546, true},
		{"127.0.0.1", "", 0, false},
		{"127.0.0.1:notaport", "", 0, false},
		{"127.0.0.1:99999", "", 0, false},
	}
	for _, tt := range tests {
		host, port, ok := splitHostPort(tt.in)
		if ok != tt.ok || host != tt.host || port != tt.port {
			t.Errorf("splitHostPort(%q) = %q, %d, %v; want %q, %d, %v",
				tt.in, host, port, ok, tt.host, tt.port, tt.ok)
		}
	}
}

func TestProtoFor(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1": "tcp",
		"0.0.0.0":   "tcp",
		"*":         "tcp",
		"::":        "tcp6",
		"::1":       "tcp6",
		"fe80::1":   "tcp6",
	}
	for in, want := range tests {
		if got := protoFor(in); got != want {
			t.Errorf("protoFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSockMap(t *testing.T) {
	got := parseSockMap(readFixture(t, "proc_sockmap.txt"))
	want := map[string]int{"12345": 1, "12346": 1, "445566": 14523, "778899": 14523}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSockMap = %v, want %v", got, want)
	}
}

func TestParsersToleratEmptyInput(t *testing.T) {
	for name, fn := range map[string]func(string) []Listener{
		"ss":      ParseSS,
		"netstat": ParseNetstat,
		"lsof":    ParseLsof,
		"proc":    func(s string) []Listener { return ParseProc(s, "") },
	} {
		for _, in := range []string{"", "\n", "garbage\n\n  \n"} {
			if got := fn(in); len(got) != 0 {
				t.Errorf("%s(%q) = %+v, want empty", name, in, got)
			}
		}
	}
}
