package tunnels

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PortSet is a set of TCP ports expressed as a list of inclusive ranges, parsed
// from a spec like "3000,8000-9000".
type PortSet []portRange

type portRange struct{ lo, hi int }

// ParsePortSet parses a comma- or space-separated list of ports and ranges.
// An empty spec yields an empty (never-matching) set.
func ParsePortSet(spec string) (PortSet, error) {
	var ps PortSet
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	for _, f := range fields {
		lo, hi, err := parseRange(f)
		if err != nil {
			return nil, err
		}
		ps = append(ps, portRange{lo, hi})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].lo < ps[j].lo })
	return ps, nil
}

func parseRange(f string) (int, int, error) {
	if loStr, hiStr, ok := strings.Cut(f, "-"); ok {
		lo, err1 := parsePort(loStr)
		hi, err2 := parsePort(hiStr)
		if err1 != nil {
			return 0, 0, err1
		}
		if err2 != nil {
			return 0, 0, err2
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("invalid port range %q: %d is above %d", f, lo, hi)
		}
		return lo, hi, nil
	}
	p, err := parsePort(f)
	return p, p, err
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", strings.TrimSpace(s))
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", p)
	}
	return p, nil
}

// Empty reports whether the set matches nothing.
func (ps PortSet) Empty() bool { return len(ps) == 0 }

// Contains reports whether port is a member.
func (ps PortSet) Contains(port int) bool {
	for _, r := range ps {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// String renders the set back into spec form.
func (ps PortSet) String() string {
	parts := make([]string, 0, len(ps))
	for _, r := range ps {
		if r.lo == r.hi {
			parts = append(parts, strconv.Itoa(r.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
		}
	}
	return strings.Join(parts, ",")
}
