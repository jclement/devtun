package probe

import (
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// splitHostPort splits an address of the form produced by ss, netstat and lsof.
// net.SplitHostPort is not usable here: netstat renders the IPv6 wildcard as
// ":::22" and IPv6 loopback as "::1:8080", neither of which is valid RFC 3986
// syntax. Splitting on the final colon handles every form we see.
func splitHostPort(s string) (host string, port int, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	host, portStr := s[:i], s[i+1:]
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return "", 0, false
	}
	host = strings.Trim(host, "[]")
	// Drop a zone identifier: fe80::1%lo -> fe80::1
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, p, true
}

// protoFor guesses the address family from a textual bind address.
func protoFor(host string) string {
	if host == "*" {
		return "tcp"
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "tcp6"
	}
	if strings.Contains(host, ":") {
		return "tcp6"
	}
	return "tcp"
}

// ssUsers matches both the modern users:(("name",pid=123,fd=4)) rendering and
// the older users:(("name",123,4)) one.
var ssUsers = regexp.MustCompile(`\("([^"]*)",(?:pid=)?(\d+)`)

// ParseSS parses the output of `ss -ltnp`.
func ParseSS(out string) []Listener {
	var res []Listener
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Some ss builds wrap the process column onto an indented
		// continuation line.
		if (line[0] == ' ' || line[0] == '\t') && len(res) > 0 {
			if name, pid, ok := parseSSUsers(line); ok {
				last := &res[len(res)-1]
				if last.PID == 0 {
					last.PID, last.Proc = pid, name
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// An explicit Netid column appears when ss is asked for multiple
		// socket families; skip past it.
		if f[0] == "tcp" || f[0] == "tcp6" || f[0] == "udp" {
			f = f[1:]
		}
		if !strings.EqualFold(f[0], "LISTEN") || len(f) < 4 {
			continue
		}
		host, port, ok := splitHostPort(f[3])
		if !ok {
			continue
		}
		l := Listener{Proto: protoFor(host), Addr: host, Port: port}
		if name, pid, ok := parseSSUsers(line); ok {
			l.Proc, l.PID = name, pid
		}
		res = append(res, l)
	}
	return res
}

func parseSSUsers(line string) (name string, pid int, ok bool) {
	m := ssUsers.FindStringSubmatch(line)
	if m == nil {
		return "", 0, false
	}
	p, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	return m[1], p, true
}

// ParseNetstat parses the output of `netstat -ltnp`.
func ParseNetstat(out string) []Listener {
	var res []Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) < 6 {
			continue
		}
		if f[0] != "tcp" && f[0] != "tcp6" && f[0] != "tcp4" {
			continue
		}
		if !strings.EqualFold(f[5], "LISTEN") {
			continue
		}
		host, port, ok := splitHostPort(f[3])
		if !ok {
			continue
		}
		proto := "tcp"
		if f[0] == "tcp6" {
			proto = "tcp6"
		}
		l := Listener{Proto: proto, Addr: host, Port: port}
		if len(f) >= 7 && f[6] != "-" {
			if pid, name, ok := strings.Cut(f[6], "/"); ok {
				if n, err := strconv.Atoi(pid); err == nil {
					l.PID, l.Proc = n, name
				}
			}
		}
		res = append(res, l)
	}
	return res
}

// ParseLsof parses the field output of
// `lsof -nP -iTCP -sTCP:LISTEN -Fpcn`, which emits one field per line prefixed
// by a type character: p=pid, c=command, f=fd, n=name.
func ParseLsof(out string) []Listener {
	var res []Listener
	var pid int
	var cmd string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		val := line[1:]
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(val)
			cmd = ""
		case 'c':
			cmd = val
		case 'n':
			// lsof appends "(LISTEN)" when -F is combined with some
			// versions' default output.
			val = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(val), "(LISTEN)"))
			if strings.Contains(val, "->") {
				continue // an established connection, not a listener
			}
			host, port, ok := splitHostPort(val)
			if !ok {
				continue
			}
			res = append(res, Listener{
				Proto: protoFor(host), Addr: host, Port: port, PID: pid, Proc: cmd,
			})
		}
	}
	return res
}

// tcpStateListen is the value of the "st" column in /proc/net/tcp for a
// listening socket.
const tcpStateListen = "0A"

// ParseProc parses concatenated /proc/net/tcp and /proc/net/tcp6, optionally
// followed by the output of `ls -l /proc/[0-9]*/fd/` used to attribute socket
// inodes to processes.
func ParseProc(netTCP, sockMap string) []Listener {
	inodeToPID := parseSockMap(sockMap)
	var res []Listener
	for _, line := range strings.Split(netTCP, "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		if !strings.EqualFold(f[3], tcpStateListen) {
			continue
		}
		host, port, ok := parseProcAddr(f[1])
		if !ok {
			continue
		}
		l := Listener{Proto: protoFor(host), Addr: host, Port: port}
		if pid, ok := inodeToPID[f[9]]; ok {
			l.PID = pid
		}
		res = append(res, l)
	}
	return res
}

// parseProcAddr decodes the hex address:port pairs used throughout /proc/net.
// Each 32-bit word of the address is stored in host byte order, so on the
// little-endian machines this runs on the bytes of each word are reversed.
func parseProcAddr(s string) (string, int, bool) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil || port > 65535 {
		return "", 0, false
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String(), int(port), true
}

var fdHeader = regexp.MustCompile(`^/proc/(\d+)/fd/?:$`)
var socketLink = regexp.MustCompile(`socket:\[(\d+)\]`)

// parseSockMap builds an inode -> pid index from `ls -l /proc/[0-9]*/fd/`,
// which prints a "/proc/<pid>/fd/:" header before each directory's entries.
func parseSockMap(out string) map[string]int {
	res := map[string]int{}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := fdHeader.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			pid, _ = strconv.Atoi(m[1])
			continue
		}
		if pid == 0 {
			continue
		}
		if m := socketLink.FindStringSubmatch(line); m != nil {
			if _, dup := res[m[1]]; !dup {
				res[m[1]] = pid
			}
		}
	}
	return res
}
