package tui

import (
	"sort"
	"strconv"
	"strings"

	"github.com/jclement/devtun/internal/tunnels"
)

// SortKey selects the tunnel table's ordering.
type SortKey int

const (
	SortRemote SortKey = iota
	SortLocal
	SortProcess
	SortAge
	SortTraffic
	SortConns
)

// sortKeys is the cycle order for the `s` key.
var sortKeys = []SortKey{SortRemote, SortLocal, SortProcess, SortAge, SortTraffic, SortConns}

// String names the key for the status bar and for the persisted preference.
func (s SortKey) String() string {
	switch s {
	case SortLocal:
		return "local"
	case SortProcess:
		return "process"
	case SortAge:
		return "age"
	case SortTraffic:
		return "traffic"
	case SortConns:
		return "conns"
	default:
		return "port"
	}
}

// Next returns the following key in the cycle.
func (s SortKey) Next() SortKey {
	for i, k := range sortKeys {
		if k == s {
			return sortKeys[(i+1)%len(sortKeys)]
		}
	}
	return SortRemote
}

// sortKeyNamed maps a persisted sort name back to a key. "recent" is accepted
// as well as "age" because that is what the config popup calls it, and a
// hand-edited host file may well say either.
func sortKeyNamed(name string) SortKey {
	if name == "recent" {
		return SortAge
	}
	for _, k := range sortKeys {
		if k.String() == name {
			return k
		}
	}
	return SortRemote
}

// sortStates orders rows in place.
//
// Age and traffic default to descending (newest and busiest first) because that
// is what you want to see without pressing anything; reverse flips whichever
// direction the key considers natural.
func sortStates(rows []tunnels.State, key SortKey, reverse, inactiveLast bool) {
	less := func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case SortLocal:
			if a.LocalPort != b.LocalPort {
				return a.LocalPort < b.LocalPort
			}
		case SortProcess:
			an, bn := a.Label, b.Label
			if an == "" {
				an = a.Cmd
			}
			if bn == "" {
				bn = b.Cmd
			}
			if c := strings.Compare(strings.ToLower(an), strings.ToLower(bn)); c != 0 {
				return c < 0
			}
		case SortAge:
			if !a.FirstSeen.Equal(b.FirstSeen) {
				return a.FirstSeen.After(b.FirstSeen)
			}
		case SortTraffic:
			at, bt := a.BytesIn+a.BytesOut, b.BytesIn+b.BytesOut
			if at != bt {
				return at > bt
			}
		case SortConns:
			if a.TotalConns != b.TotalConns {
				return a.TotalConns > b.TotalConns
			}
		}
		return a.RemotePort < b.RemotePort
	}
	ordered := less
	if reverse {
		ordered = func(i, j int) bool { return less(j, i) }
	}
	if inactiveLast {
		// Grouping wraps the chosen order rather than replacing it: live
		// tunnels stay together at the top, sorted among themselves.
		inner := ordered
		ordered = func(i, j int) bool {
			ai := rows[i].Status == tunnels.StatusActive
			bj := rows[j].Status == tunnels.StatusActive
			if ai != bj {
				return ai
			}
			return inner(i, j)
		}
	}
	sort.SliceStable(rows, ordered)
}

// filterStates keeps rows matching a case-insensitive query against the port
// numbers, the name and the process command.
func filterStates(rows []tunnels.State, query string) []tunnels.State {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		if matches(r, q) {
			out = append(out, r)
		}
	}
	return out
}

func matches(r tunnels.State, q string) bool {
	return strings.Contains(strings.ToLower(r.Cmd), q) ||
		strings.Contains(strings.ToLower(r.Label), q) ||
		strings.Contains(strings.ToLower(r.Proc), q) ||
		strings.Contains(strconv.Itoa(r.RemotePort), q) ||
		strings.Contains(strconv.Itoa(r.LocalPort), q) ||
		strings.Contains(string(r.Status), q)
}
