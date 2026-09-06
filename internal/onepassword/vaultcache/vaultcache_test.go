package vaultcache

import (
	"testing"
	"time"
)

func TestNilCacheStoresNothing(t *testing.T) {
	var cache *Cache
	cache.Put("k", []byte("v"), time.Time{})
	if _, ok := cache.Get("k"); ok {
		t.Error("a nil cache must never return a value")
	}
	if cache.Len() != 0 || cache.Purge() != 0 || cache.TTL() != 0 {
		t.Error("a nil cache should report itself empty and disabled")
	}
}

func TestNewRejectsANonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		if cache := New(ttl); cache != nil {
			t.Errorf("New(%s) = a live cache, want nil so caching stays off", ttl)
		}
	}
}

func TestPutAndGet(t *testing.T) {
	cache := New(time.Minute)
	cache.Put("op://V/I/F", []byte("s3cret\n"), time.Time{})

	value, ok := cache.Get("op://V/I/F")
	if !ok {
		t.Fatal("the value was not cached")
	}
	if string(value) != "s3cret\n" {
		t.Errorf("Get() = %q, want the raw value including its newline", value)
	}
	if _, ok := cache.Get("op://V/I/other"); ok {
		t.Error("an unrelated key must not hit")
	}
}

// The caller gets a copy: a response buffer that someone later mutates must not
// corrupt what the next reader sees.
func TestGetReturnsACopy(t *testing.T) {
	cache := New(time.Minute)
	cache.Put("k", []byte("secret"), time.Time{})

	first, _ := cache.Get("k")
	for i := range first {
		first[i] = 'x'
	}
	second, _ := cache.Get("k")
	if string(second) != "secret" {
		t.Errorf("second Get() = %q, want the value unchanged", second)
	}
}

func TestEntriesExpire(t *testing.T) {
	cache := New(20 * time.Millisecond)
	cache.Put("k", []byte("v"), time.Time{})
	if _, ok := cache.Get("k"); !ok {
		t.Fatal("fresh entry should hit")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := cache.Get("k"); ok {
		t.Error("an expired entry must not be served")
	}
}

// The rule the whole design rests on: a cached value must never outlive the
// authorisation that produced it, even when the cache TTL is longer.
func TestAuthorisationExpiryWinsOverTheTTL(t *testing.T) {
	cache := New(time.Hour)
	cache.Put("k", []byte("v"), time.Now().Add(20*time.Millisecond))

	if _, ok := cache.Get("k"); !ok {
		t.Fatal("fresh entry should hit")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := cache.Get("k"); ok {
		t.Error("the entry outlived the grant that authorised it")
	}
}

func TestPutIgnoresAnAlreadyLapsedAuthorisation(t *testing.T) {
	cache := New(time.Hour)
	cache.Put("k", []byte("v"), time.Now().Add(-time.Second))
	if _, ok := cache.Get("k"); ok {
		t.Error("a value authorised only in the past must not be cached")
	}
}

// "Allow once" authorises exactly one request, so nothing derived from it may
// be kept — the proxy signals that by passing an expiry of now.
func TestAllowOnceLeavesNothingBehind(t *testing.T) {
	cache := New(time.Hour)
	cache.Put("k", []byte("v"), time.Now())
	if _, ok := cache.Get("k"); ok {
		t.Error("a one-shot approval must not populate the cache")
	}
}

func TestPutIgnoresEmptyValues(t *testing.T) {
	cache := New(time.Minute)
	cache.Put("k", nil, time.Time{})
	if cache.Len() != 0 {
		t.Error("an empty value is not worth caching")
	}
}

func TestPurgeForgetsEverything(t *testing.T) {
	cache := New(time.Minute)
	cache.Put("a", []byte("1"), time.Time{})
	cache.Put("b", []byte("2"), time.Time{})

	if got := cache.Purge(); got != 2 {
		t.Errorf("Purge() = %d, want 2", got)
	}
	if _, ok := cache.Get("a"); ok {
		t.Error("purged entries must not be served")
	}
}

// A remote box can ask for an unbounded number of distinct references, and each
// one would otherwise be secret material held for the full TTL.
func TestCacheIsBounded(t *testing.T) {
	cache := New(time.Minute)
	cache.maxEntries = 4

	for i := 0; i < 20; i++ {
		cache.Put(string(rune('a'+i)), []byte("value"), time.Time{})
	}
	if got := cache.Len(); got > 4 {
		t.Errorf("cache holds %d entries, want at most 4", got)
	}
}

// Dropping an entry overwrites the bytes. The garbage collector may already
// have copied them, so this is partial — but it shortens the window in which a
// core dump would contain the secret, and it must actually happen.
func TestDroppingAnEntryZeroesIt(t *testing.T) {
	cache := New(time.Minute)
	original := []byte("s3cret")
	cache.Put("k", original, time.Time{})

	cache.mu.Lock()
	stored := cache.entries["k"].value
	cache.mu.Unlock()

	cache.Purge()

	for i, b := range stored {
		if b != 0 {
			t.Fatalf("stored byte %d is %q after purge, want it zeroed", i, b)
		}
	}
	if string(original) != "s3cret" {
		t.Error("Put must copy its input rather than take ownership of the caller's buffer")
	}
}
