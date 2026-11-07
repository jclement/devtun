package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Where rules live, and who may change them.
//
// There are three places, and the difference between them is authorship, not
// scope. The global file is the user's, applies everywhere, and is never
// edited by devtun. A host file's `rules:` is also the user's — hand-written,
// usually — and may be edited from the interface because it is per-host and
// the interface is asked to. `remembered:`, beside it, is devtun's: every
// "always" answer and every rule made in the interface lands there, so the
// list a person typed is never the list devtun appends to.
//
// Rules used to be addressed by their position in the host list. The terminal
// re-read the list twice a second and the board sent back whatever position it
// had rendered, so a revoke from one surface between the other's render and
// its click deleted, or flipped, the wrong rule. A rule's ID is derived from
// what the rule says, so it means the same thing on every surface, in every
// process, and across a restart.

// Source is where a rule is written down.
type Source string

const (
	// SourceGlobal is the `rules:` list in the global config file. Read-only
	// here: devtun did not write it and will not change it.
	SourceGlobal Source = "global"
	// SourceHost is the `rules:` list in the host's own file, which a person
	// wrote by hand. It may be edited through the interface.
	SourceHost Source = "host"
	// SourceRemembered is the `remembered:` list in the host's file, which is
	// where devtun writes.
	SourceRemembered Source = "remembered"
)

// Rule is one persistent policy entry. Host and Subject are globs (see Match
// and Schema.Match). The YAML tags are load-bearing: rules are round-tripped
// through the host's config document.
type Rule struct {
	// ID is stable for as long as the rule says the same thing. It is not
	// written to the file: it is derived from the rule, which is what lets a
	// rule typed by hand have one.
	ID string `yaml:"-"`
	// Source is which list the rule came from.
	Source Source `yaml:"-"`

	Host    string    `yaml:"host,omitempty"`
	Subject string    `yaml:"subject"`
	Action  Action    `yaml:"action"`
	Note    string    `yaml:"note,omitempty"`
	Added   time.Time `yaml:"added,omitempty"`
}

// Editable reports whether the interface may change this rule.
func (r Rule) Editable() bool { return r.Source != SourceGlobal }

// HostPattern is the host glob with the empty default spelled out.
func (r Rule) HostPattern() string {
	if r.Host == "" {
		return HostWildcard
	}
	return r.Host
}

// sameContent compares what a rule says, ignoring where it was read from.
func (r Rule) sameContent(o Rule) bool {
	return r.Host == o.Host && r.Subject == o.Subject && r.Action == o.Action &&
		r.Note == o.Note && r.Added.Equal(o.Added)
}

// Errors the rule operations return.
var (
	// ErrReadOnly is a change to a rule from the global file.
	ErrReadOnly = errors.New("that rule is in your global config file; devtun does not edit it")
	// ErrNotFound is an ID that names no rule or grant now — it was changed or
	// removed by somebody else since it was read. Reload and try again.
	ErrNotFound = errors.New("no such rule or grant — it may have changed underneath you")
	// ErrUnreadable is a policy file that cannot be read or parsed. Nothing is
	// written, and every request is refused until it is fixed.
	ErrUnreadable = errors.New("a policy file cannot be read")
)

// assignIDs gives every rule in one list its ID.
//
// Two rules that say exactly the same thing would hash alike, so the second and
// later copies get an ordinal. That keeps the IDs distinct; it also means
// removing the first of two identical rules hands its ID to the second, which
// is harmless precisely because the two are identical.
func assignIDs(source Source, rules []Rule) []Rule {
	seen := make(map[string]int, len(rules))
	out := make([]Rule, len(rules))
	for i, r := range rules {
		r.Source = source
		id := ruleHash(source, r)
		seen[id]++
		if n := seen[id]; n > 1 {
			id = fmt.Sprintf("%s-%d", id, n)
		}
		r.ID = id
		out[i] = r
	}
	return out
}

func ruleHash(source Source, r Rule) string {
	added := ""
	if !r.Added.IsZero() {
		added = r.Added.UTC().Format(time.RFC3339)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		string(source), r.Host, r.Subject, string(r.Action), r.Note, added,
	}, "\x00")))
	return "r" + hex.EncodeToString(sum[:6])
}

// Loaded is everything a store reads from its rule book in one go.
type Loaded struct {
	Global     []Rule
	Host       []Rule
	Remembered []Rule
	// Unmatched is what the files say happens when nothing matches, empty when
	// neither does; UnmatchedLevel says which file ("host" or "global").
	Unmatched      string
	UnmatchedLevel string
}

// RuleBook is where a store's rules are written down.
//
// It is an interface because the store has no business knowing: in devtun the
// rules are in the host's and the global config files, read through hostcfg so
// a hand edit is seen as soon as it is made; in tests they are in memory.
type RuleBook interface {
	// Load reads everything as it is now. An error means some of it could not
	// be read, and the store refuses every request rather than act on part of
	// a policy.
	Load() (Loaded, error)
	// Edit changes one list — host or remembered — as a transaction against
	// wherever it is kept: edit is handed the list as it is right now, IDs
	// assigned, and returns the list to write.
	Edit(source Source, edit func([]Rule) ([]Rule, error)) error
	// Revision changes whenever what Load would return may have changed.
	Revision() uint64
}

// memoryBook keeps host rules in memory. It is what a store has until a host
// adopts it, and what tests use.
type memoryBook struct {
	mu       sync.Mutex
	loaded   Loaded
	revision uint64
	// fail, when set, is returned by every Edit — for a test that wants a
	// write to fail.
	fail error
}

func (m *memoryBook) Load() (Loaded, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Loaded{
		Global:     append([]Rule(nil), m.loaded.Global...),
		Host:       append([]Rule(nil), m.loaded.Host...),
		Remembered: append([]Rule(nil), m.loaded.Remembered...),
		Unmatched:  m.loaded.Unmatched, UnmatchedLevel: m.loaded.UnmatchedLevel,
	}, nil
}

func (m *memoryBook) Edit(source Source, edit func([]Rule) ([]Rule, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	list := &m.loaded.Remembered
	if source == SourceHost {
		list = &m.loaded.Host
	}
	next, err := edit(assignIDs(source, *list))
	if err != nil {
		return err
	}
	*list = next
	m.revision++
	return nil
}

func (m *memoryBook) Revision() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revision
}
