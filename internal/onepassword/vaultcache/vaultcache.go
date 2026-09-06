// Package vaultcache holds secret values the proxy has already fetched, so that
// a script reading the same reference twenty times costs one call to the
// 1Password CLI instead of twenty.
//
// This is the one place in devtun that keeps secret material in memory beyond
// a single `op` invocation, and it is off unless asked for. Two rules make it
// defensible:
//
//   - A cached value never outlives the authorisation that produced it. Every
//     entry carries an expiry that is the *earlier* of the cache TTL and the
//     moment the grant lapses.
//   - A cached value is never served without re-authorising first. The cache is
//     consulted after the policy decision, never instead of it, so an expired
//     grant cannot be satisfied from memory.
//
// Given those, the exposure it adds inside a live grant window is small: anyone
// who can reach the socket while the grant holds can simply ask for the secret
// and be given it. What the cache changes is that the value is also sitting in
// this process, where a core dump or a swapped page could catch it — which is
// exactly why it is opt-in.
package vaultcache

import (
	"sync"
	"time"
)

// DefaultMaxEntries bounds the cache. A remote box can ask for an unbounded
// number of distinct references, and every one of them would otherwise be
// secret material held until its TTL ran out.
const DefaultMaxEntries = 256

// Cache is a TTL cache of raw `op read` output, safe for concurrent use. A nil
// *Cache is a working cache that stores nothing, so callers need no branches.
type Cache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]*entry
}

type entry struct {
	value   []byte
	expires time.Time
}

// New returns a cache holding values for at most ttl. A non-positive ttl
// returns nil, which behaves as a cache that never stores anything.
func New(ttl time.Duration) *Cache {
	if ttl <= 0 {
		return nil
	}
	return &Cache{ttl: ttl, maxEntries: DefaultMaxEntries, entries: make(map[string]*entry)}
}

// Get returns a cached value. The second result reports whether there was one.
func (c *Cache) Get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	found, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(found.expires) {
		c.dropLocked(key)
		return nil, false
	}
	// A copy, so a caller that mutates its response cannot corrupt the entry.
	value := make([]byte, len(found.value))
	copy(value, found.value)
	return value, true
}

// Put stores value until the cache TTL runs out, or until authorisedUntil,
// whichever comes first. A zero authorisedUntil means the authorisation has no
// expiry of its own and only the TTL applies.
func (c *Cache) Put(key string, value []byte, authorisedUntil time.Time) {
	if c == nil || len(value) == 0 {
		return
	}
	expires := time.Now().Add(c.ttl)
	if !authorisedUntil.IsZero() && authorisedUntil.Before(expires) {
		expires = authorisedUntil
	}
	if !time.Now().Before(expires) {
		return // the authorisation has already lapsed; nothing worth keeping
	}

	stored := make([]byte, len(value))
	copy(stored, value)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
	if len(c.entries) >= c.maxEntries {
		c.evictSoonestLocked()
	}
	c.dropLocked(key)
	c.entries[key] = &entry{value: stored, expires: expires}
}

// Purge forgets everything, and reports how many entries were dropped. It is
// what a revoked rule or a cleared set of grants must trigger: a cached value
// whose authorisation has been withdrawn is exactly what this must not serve.
func (c *Cache) Purge() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	count := len(c.entries)
	for key := range c.entries {
		c.dropLocked(key)
	}
	return count
}

// Len reports how many live entries are held.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
	return len(c.entries)
}

// TTL reports the configured lifetime, or zero when caching is off.
func (c *Cache) TTL() time.Duration {
	if c == nil {
		return 0
	}
	return c.ttl
}

// dropLocked removes an entry, overwriting the value first. Go's garbage
// collector may already have copied the bytes elsewhere, so this is a partial
// measure — but it costs nothing and shortens the window in which a core dump
// would contain the secret.
func (c *Cache) dropLocked(key string) {
	found, ok := c.entries[key]
	if !ok {
		return
	}
	for i := range found.value {
		found.value[i] = 0
	}
	delete(c.entries, key)
}

func (c *Cache) pruneLocked() {
	now := time.Now()
	for key, found := range c.entries {
		if !now.Before(found.expires) {
			c.dropLocked(key)
		}
	}
}

// evictSoonestLocked makes room by dropping whichever entry expires next, so
// the cache sheds what it was about to lose anyway.
func (c *Cache) evictSoonestLocked() {
	var soonestKey string
	var soonest time.Time
	for key, found := range c.entries {
		if soonestKey == "" || found.expires.Before(soonest) {
			soonestKey, soonest = key, found.expires
		}
	}
	if soonestKey != "" {
		c.dropLocked(soonestKey)
	}
}
