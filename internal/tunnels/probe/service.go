// Package probe discovers TCP services listening on a remote host.
//
// Discovery runs entirely over a single SSH session: a small POSIX shell script
// is piped to the remote `sh`, which emits a framed stream of raw output from
// whichever port-listing tool is available. All parsing happens here, in Go, so
// it can be tested against captured fixtures.
package probe

import (
	"fmt"
	"github.com/jclement/devtun/internal/event"
	"net"
	"sort"
	"strings"
)

// Mode identifies the discovery tool used on the remote host.
type Mode string

const (
	ModeSS      Mode = "ss"
	ModeLsof    Mode = "lsof"
	ModeNetstat Mode = "netstat"
	ModeProc    Mode = "proc"
)

// Modes lists every supported discovery mode, most preferred first.
var Modes = []Mode{ModeSS, ModeLsof, ModeNetstat, ModeProc}

// ParseMode validates a mode name reported by the remote prober.
func ParseMode(s string) (Mode, error) {
	for _, m := range Modes {
		if string(m) == s {
			return m, nil
		}
	}
	return "", fmt.Errorf("unknown discovery mode %q", s)
}

// HasProcessInfo reports whether the mode can attribute sockets to processes.
// Every mode can in principle, but unprivileged users only see their own
// processes, which is exactly the set we care about.
func (m Mode) HasProcessInfo() bool { return true }

// Bind is a single listening socket address of a service.
type Bind struct {
	Proto string // "tcp" or "tcp6"
	Addr  string // "127.0.0.1", "0.0.0.0", "::", "::1", or a specific address
}

// Listener is one raw listening socket, as reported by the remote.
type Listener struct {
	Proto string
	Addr  string
	Port  int
	PID   int
	Proc  string
}

// Service is the merged view of every listener sharing a port. A process bound
// to both 0.0.0.0:3000 and [::]:3000 is one Service with two Binds.
type Service struct {
	Port  int
	Binds []Bind
	PID   int
	Proc  string
	Cmd   string // full command line, resolved lazily; may be empty
}

// Command returns the most descriptive process label available.
func (s Service) Command() string {
	if s.Cmd != "" {
		return s.Cmd
	}
	if s.Proc != "" {
		return s.Proc
	}
	return "?"
}

// loopbackAddrs are bind addresses reachable only from the remote host itself.
// These are the services devtun exists to reach.
func isLoopback(addr string) bool {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	return ip != nil && ip.IsLoopback()
}

// isWildcard reports whether the bind address accepts connections on every
// interface.
func isWildcard(addr string) bool {
	switch strings.Trim(addr, "[]") {
	case "0.0.0.0", "::", "*", "":
		return true
	}
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	return ip != nil && ip.IsUnspecified()
}

// LoopbackOnly reports whether every bind of the service is on a loopback
// address, meaning the service is unreachable from outside the remote host.
func (s Service) LoopbackOnly() bool {
	if len(s.Binds) == 0 {
		return false
	}
	for _, b := range s.Binds {
		if !isLoopback(b.Addr) {
			return false
		}
	}
	return true
}

// DialAddr returns the host:port that the remote end of the tunnel should
// connect to. Wildcard binds are dialed on IPv4 loopback; a service bound only
// to a specific address is dialed there.
func (s Service) DialAddr() string {
	best := ""
	rank := -1
	for _, b := range s.Binds {
		addr := strings.Trim(b.Addr, "[]")
		var r int
		switch {
		case addr == "127.0.0.1":
			r = 4
		case isWildcard(addr) && b.Proto == "tcp":
			r = 3
		case isWildcard(addr):
			r = 2
		case isLoopback(addr):
			r = 1
		default:
			r = 0
		}
		if r > rank {
			rank, best = r, addr
		}
	}
	switch {
	case best == "" || isWildcard(best):
		best = "127.0.0.1"
	}
	return net.JoinHostPort(best, fmt.Sprint(s.Port))
}

// BindSummary renders the service's bind addresses for display.
func (s Service) BindSummary() string {
	seen := map[string]bool{}
	var out []string
	for _, b := range s.Binds {
		a := strings.Trim(b.Addr, "[]")
		if isWildcard(a) {
			a = "*"
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// Snapshot is the set of services observed in a single remote scan, keyed by
// port.
type Snapshot map[int]Service

// Ports returns the snapshot's ports in ascending order.
func (s Snapshot) Ports() []int {
	out := make([]int, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// merge folds raw listeners into per-port services.
// merge folds listeners into one record per port.
//
// Process names and command lines come from a machine devtun treats as only
// semi-trusted and end up in event text drawn on a terminal, so they are
// sanitised here — at the one place they enter — rather than at each of the
// several renderers. See event.Sanitize.
func merge(ls []Listener) Snapshot {
	snap := Snapshot{}
	for _, l := range ls {
		if l.Port <= 0 || l.Port > 65535 {
			continue
		}
		svc, ok := snap[l.Port]
		if !ok {
			svc = Service{Port: l.Port}
		}
		dup := false
		for _, b := range svc.Binds {
			if b.Proto == l.Proto && b.Addr == l.Addr {
				dup = true
				break
			}
		}
		if !dup {
			svc.Binds = append(svc.Binds, Bind{Proto: l.Proto, Addr: l.Addr})
		}
		// The first listener with process attribution wins; tools list the
		// owning process inconsistently across address families.
		if svc.PID == 0 && l.PID != 0 {
			svc.PID = l.PID
		}
		if svc.Proc == "" && l.Proc != "" {
			// Sanitised here, at the one place a remote process name enters:
			// it ends up in event text drawn straight to a terminal, where an
			// escape sequence is an instruction rather than a name.
			svc.Proc = event.SanitizeTo(l.Proc, 64)
		}
		snap[l.Port] = svc
	}
	for p, svc := range snap {
		sort.Slice(svc.Binds, func(i, j int) bool {
			if svc.Binds[i].Proto != svc.Binds[j].Proto {
				return svc.Binds[i].Proto < svc.Binds[j].Proto
			}
			return svc.Binds[i].Addr < svc.Binds[j].Addr
		})
		snap[p] = svc
	}
	return snap
}
