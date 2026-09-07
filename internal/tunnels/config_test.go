package tunnels

import (
	"encoding/json"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
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

// yamlConfig is a service.Config that round-trips through YAML, which is what
// the real host file is. The JSON fake above cannot stand in for these: the
// whole point of the `hide` key is that `hide: 5432`, `hide: "1-2"` and a list
// of both are all accepted, and that is UnmarshalYAML's doing.
type yamlConfig map[string]string

func (c yamlConfig) Get(key string, v any) (bool, error) { return c.GetLocal(key, v) }

func (c yamlConfig) GetLocal(key string, v any) (bool, error) {
	doc, ok := c[key]
	if !ok {
		return false, nil
	}
	if err := yaml.Unmarshal([]byte(doc), v); err != nil {
		return false, err
	}
	return true, nil
}

func (c yamlConfig) Set(string, any) error { return nil }

func TestStoreReadsTheHostsHideList(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		in   []int
		out  []int
	}{
		{name: "a bare port", doc: "5432", in: []int{5432}, out: []int{3000}},
		{name: "a range", doc: `"32768-60999"`, in: []int{32768, 40000, 60999}, out: []int{3000, 61000}},
		{name: "a list of both", doc: "[5432, \"6000-6100\"]", in: []int{5432, 6050}, out: []int{3000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore(yamlConfig{keyHide: tc.doc})
			if err := s.HideErr(); err != nil {
				t.Fatalf("reading %s: %v", tc.doc, err)
			}
			for _, port := range tc.in {
				if !s.Hide().Contains(port) {
					t.Errorf("%d is not hidden by %s", port, tc.doc)
				}
			}
			for _, port := range tc.out {
				if s.Hide().Contains(port) {
					t.Errorf("%d should not be hidden by %s", port, tc.doc)
				}
			}
		})
	}
}

// A hide list that will not parse fails open — the port gets forwarded — so the
// error has to survive for the service to say so. Silently reading it as empty
// is how you find out from the port table instead.
func TestStoreKeepsABrokenHideList(t *testing.T) {
	s := NewStore(yamlConfig{keyHide: `"9000-8000"`})
	if s.HideErr() == nil {
		t.Fatal("a backwards range parsed without complaint")
	}
	if !s.Hide().Empty() {
		t.Error("a broken list still hid something")
	}
}
