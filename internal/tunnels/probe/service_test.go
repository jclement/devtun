package probe

import (
	"reflect"
	"testing"
)

func TestMergeCombinesAddressFamilies(t *testing.T) {
	got := merge([]Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 3000, PID: 0, Proc: ""},
		{Proto: "tcp6", Addr: "::", Port: 3000, PID: 42, Proc: "node"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 5432, PID: 7, Proc: "postgres"},
	})
	if len(got) != 2 {
		t.Fatalf("got %d services, want 2", len(got))
	}
	svc := got[3000]
	if len(svc.Binds) != 2 {
		t.Errorf("port 3000 binds = %+v, want 2", svc.Binds)
	}
	// Process attribution from any address family applies to the service.
	if svc.PID != 42 || svc.Proc != "node" {
		t.Errorf("port 3000 = pid %d proc %q, want 42/node", svc.PID, svc.Proc)
	}
}

func TestMergeDeduplicatesIdenticalBinds(t *testing.T) {
	got := merge([]Listener{
		{Proto: "tcp", Addr: "127.0.0.1", Port: 3000},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 3000},
	})
	if n := len(got[3000].Binds); n != 1 {
		t.Errorf("binds = %d, want 1", n)
	}
}

func TestMergeRejectsInvalidPorts(t *testing.T) {
	got := merge([]Listener{
		{Proto: "tcp", Addr: "127.0.0.1", Port: 0},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 70000},
		{Proto: "tcp", Addr: "127.0.0.1", Port: -1},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 8080},
	})
	if len(got) != 1 {
		t.Fatalf("got %d services, want only 8080: %+v", len(got), got)
	}
}

func TestSnapshotPortsSorted(t *testing.T) {
	snap := Snapshot{8080: {Port: 8080}, 22: {Port: 22}, 3000: {Port: 3000}}
	want := []int{22, 3000, 8080}
	if got := snap.Ports(); !reflect.DeepEqual(got, want) {
		t.Errorf("Ports() = %v, want %v", got, want)
	}
}

func TestServiceDialAddr(t *testing.T) {
	tests := []struct {
		name  string
		binds []Bind
		want  string
	}{
		{"ipv4 loopback", []Bind{{"tcp", "127.0.0.1"}}, "127.0.0.1:3000"},
		{"ipv4 wildcard", []Bind{{"tcp", "0.0.0.0"}}, "127.0.0.1:3000"},
		{"star wildcard", []Bind{{"tcp", "*"}}, "127.0.0.1:3000"},
		{"ipv6 wildcard only", []Bind{{"tcp6", "::"}}, "127.0.0.1:3000"},
		{"ipv6 loopback only", []Bind{{"tcp6", "::1"}}, "[::1]:3000"},
		{"both families", []Bind{{"tcp", "0.0.0.0"}, {"tcp6", "::"}}, "127.0.0.1:3000"},
		{"prefers v4 loopback", []Bind{{"tcp6", "::1"}, {"tcp", "127.0.0.1"}}, "127.0.0.1:3000"},
		{"specific address", []Bind{{"tcp", "10.0.0.5"}}, "10.0.0.5:3000"},
		{"no binds", nil, "127.0.0.1:3000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := Service{Port: 3000, Binds: tt.binds}
			if got := svc.DialAddr(); got != tt.want {
				t.Errorf("DialAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServiceLoopbackOnly(t *testing.T) {
	tests := []struct {
		name  string
		binds []Bind
		want  bool
	}{
		{"v4 loopback", []Bind{{"tcp", "127.0.0.1"}}, true},
		{"both loopbacks", []Bind{{"tcp", "127.0.0.1"}, {"tcp6", "::1"}}, true},
		{"loopback alias", []Bind{{"tcp", "127.0.0.53"}}, true},
		{"wildcard", []Bind{{"tcp", "0.0.0.0"}}, false},
		{"mixed", []Bind{{"tcp", "127.0.0.1"}, {"tcp", "0.0.0.0"}}, false},
		{"specific", []Bind{{"tcp", "10.0.0.5"}}, false},
		{"none", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := Service{Port: 1, Binds: tt.binds}
			if got := svc.LoopbackOnly(); got != tt.want {
				t.Errorf("LoopbackOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceBindSummary(t *testing.T) {
	svc := Service{Binds: []Bind{{"tcp", "0.0.0.0"}, {"tcp6", "::"}, {"tcp", "127.0.0.1"}}}
	if got := svc.BindSummary(); got != "*,127.0.0.1" {
		t.Errorf("BindSummary() = %q, want %q", got, "*,127.0.0.1")
	}
}

func TestServiceCommandFallback(t *testing.T) {
	if got := (Service{Cmd: "node server.js", Proc: "node"}).Command(); got != "node server.js" {
		t.Errorf("want the full command line, got %q", got)
	}
	if got := (Service{Proc: "node"}).Command(); got != "node" {
		t.Errorf("want the process name, got %q", got)
	}
	if got := (Service{}).Command(); got != "?" {
		t.Errorf("want a placeholder, got %q", got)
	}
}

func TestParseMode(t *testing.T) {
	for _, m := range Modes {
		got, err := ParseMode(string(m))
		if err != nil || got != m {
			t.Errorf("ParseMode(%q) = %q, %v", m, got, err)
		}
	}
	if _, err := ParseMode("telepathy"); err == nil {
		t.Error("want an error for an unknown mode")
	}
}
