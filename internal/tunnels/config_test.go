package tunnels

import (
	"encoding/json"
	"sync"
	"testing"
)

// fakeConfig is an in-memory service.Config. It round-trips every document
// through JSON rather than holding the value, so a shape that could not
// survive the real host file — an unmarshalable map key, say — fails here too.
type fakeConfig struct {
	mu   sync.Mutex
	docs map[string][]byte
}

func newFakeConfig() *fakeConfig { return &fakeConfig{docs: map[string][]byte{}} }

// GetLocal behaves as Get here: these fakes hold no shared layer for a local
// read to differ from.
func (c *fakeConfig) GetLocal(key string, v any) (bool, error) { return c.Get(key, v) }

func (c *fakeConfig) Get(key string, v any) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, ok := c.docs[key]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, err
	}
	return true, nil
}

func (c *fakeConfig) Set(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.docs[key] = raw
	return nil
}

func TestStoreRoundTripsPortPrefs(t *testing.T) {
	cfg := newFakeConfig()
	s := NewStore(cfg)
	s.SetPort(3000, PortPrefs{Label: "frontend", Scheme: "https", Mode: "hidden", Local: 13000})

	// A second Store is what the next run of devtun sees.
	got := NewStore(cfg).Port(3000)
	want := PortPrefs{Label: "frontend", Scheme: "https", Mode: "hidden", Local: 13000}
	if got != want {
		t.Errorf("reloaded prefs = %+v, want %+v", got, want)
	}
}

// An entry holding nothing is clutter in a file meant to be read by hand.
func TestStoreDropsEmptyPortPrefs(t *testing.T) {
	cfg := newFakeConfig()
	s := NewStore(cfg)
	s.SetPort(3000, PortPrefs{Mode: "hidden"})
	s.SetPort(3000, PortPrefs{Mode: "auto"})

	if got := NewStore(cfg).Port(3000); got != (PortPrefs{}) {
		t.Errorf("reloaded prefs = %+v, want the entry removed", got)
	}
}

func TestStoreViewPrefsDefaults(t *testing.T) {
	s := NewStore(newFakeConfig())
	if got := s.View(); got != DefaultViewPrefs() {
		t.Errorf("View() = %+v, want the defaults %+v", got, DefaultViewPrefs())
	}
}

// inactive_last defaults to true, so "explicitly off" has to be distinguishable
// from "never set" in the stored document.
func TestStoreViewPrefsRoundTripInactiveLastOff(t *testing.T) {
	cfg := newFakeConfig()
	p := DefaultViewPrefs()
	p.InactiveLast = false
	p.ShowHidden = true
	NewStore(cfg).SetView(p)

	if got := NewStore(cfg).View(); got != p {
		t.Errorf("reloaded view = %+v, want %+v", got, p)
	}
}

// A store with no config behaves, so a session that cannot write anywhere
// still runs.
func TestStoreWithoutConfig(t *testing.T) {
	s := NewStore(nil)
	s.SetPort(3000, PortPrefs{Mode: "on"})
	if got := s.Port(3000).Mode; got != "on" {
		t.Errorf("in-memory prefs = %q, want on", got)
	}
	s.SetView(ViewPrefs{ShowHidden: true})
	if !s.View().ShowHidden {
		t.Error("in-memory view prefs were not kept")
	}
}
