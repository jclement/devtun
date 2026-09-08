package tui

import (
	"sort"
	"strings"

	"github.com/sahilm/fuzzy"

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
	// A search orders by how well each row matched and by nothing else. The
	// answer to "which of these did I mean" is the ranking, so re-sorting it by
	// port — or sinking the inactive rows under the live ones — would bury the
	// best match somewhere in the middle of the list it was picked from.
	if rank := searchRank; rank != nil {
		byRank := func(i, j int) bool { return rank[rows[i].RemotePort] < rank[rows[j].RemotePort] }
		if reverse {
			sort.SliceStable(rows, func(i, j int) bool { return byRank(j, i) })
			return
		}
		sort.SliceStable(rows, byRank)
		return
	}

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

// searchRank carries the last filter's ranking, by remote port, to the sort
// that immediately follows it.
//
// reloadTunnels filters and then sorts, so a slice already in score order is
// re-sorted by port before anyone sees it and the ranking is thrown away. The
// two are called back to back from that one place, which is why the ranking can
// be left here rather than threaded through a signature: filterStates clears it
// on every call, so a stale ranking cannot outlive the query that produced it.
var searchRank map[int]int

// filterStates keeps the rows matching a query, best match first.
//
// Fuzzy rather than substring: the query is usually a fragment of a name you
// half remember — "pg" for postgres, "vt" for vite — and on a box forwarding
// thirty ports typing the exact substring is the part you wanted to skip.
func filterStates(rows []tunnels.State, query string) []tunnels.State {
	searchRank = nil
	q := strings.TrimSpace(query)
	if q == "" {
		return rows
	}
	matches := fuzzy.FindFrom(q, tunnelNames(rows))
	out := make([]tunnels.State, 0, len(matches))
	rank := make(map[int]int, len(matches))
	for i, match := range matches {
		row := rows[match.Index]
		rank[row.RemotePort] = i
		out = append(out, row)
	}
	searchRank = rank
	return out
}

// tunnelNames is the searchable text of each row: everything on it that names
// the thing, so a port number and a process name are one query away from each
// other rather than two different searches.
type tunnelNames []tunnels.State

func (t tunnelNames) Len() int { return len(t) }

func (t tunnelNames) String(i int) string {
	r := t[i]
	return strings.Join([]string{
		r.Label, r.Proc, r.Cmd, itoa(r.RemotePort), itoa(r.LocalPort), string(r.Status),
	}, " ")
}
