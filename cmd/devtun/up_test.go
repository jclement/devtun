package main

import (
	"context"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/tunnels"
)

func defaults() upFlags {
	return upFlags{
		minPort: 1024, maxPort: 65535, remoteBind: "any",
		interval: 2 * time.Second, bind: "127.0.0.1",
	}
}

func TestDefaultPolicyForwardsUnprivilegedPortsOnly(t *testing.T) {
	policy, err := tunnelPolicy(defaults())
	if err != nil {
		t.Fatalf("tunnelPolicy: %v", err)
	}
	if policy.MinPort != 1024 {
		t.Errorf("the default window should start above the privileged ports, got %d", policy.MinPort)
	}
	if policy.MaxPort != 65535 {
		t.Errorf("unexpected max port %d", policy.MaxPort)
	}
}

func TestBadPortWindowIsRejected(t *testing.T) {
	for name, mutate := range map[string]func(*upFlags){
		"min above max": func(f *upFlags) { f.minPort, f.maxPort = 9000, 8000 },
		"min below one": func(f *upFlags) { f.minPort = 0 },
		"max too high":  func(f *upFlags) { f.maxPort = 70000 },
	} {
		t.Run(name, func(t *testing.T) {
			f := defaults()
			mutate(&f)
			if _, err := tunnelPolicy(f); err == nil {
				t.Error("want an error")
			}
		})
	}
}

// Scanning faster than this spends more time asking than working, and the
// remote shell is doing the asking.
func TestTooFastAnIntervalIsRejected(t *testing.T) {
	f := defaults()
	f.interval = 10 * time.Millisecond
	if _, err := tunnelPolicy(f); err == nil {
		t.Error("an absurd scan interval should be refused")
	}
}

func TestMalformedPortSetsAreNamedInTheError(t *testing.T) {
	f := defaults()
	f.include = "not-a-port"
	_, err := tunnelPolicy(f)
	if err == nil || !strings.Contains(err.Error(), "--include") {
		t.Errorf("the error should name the flag at fault, got %v", err)
	}

	f = defaults()
	f.exclude = "3000-"
	if _, err := tunnelPolicy(f); err == nil || !strings.Contains(err.Error(), "--exclude") {
		t.Errorf("the error should name the flag at fault, got %v", err)
	}
}

func TestOnlySelectsServicesByID(t *testing.T) {
	all := []service.Service{
		tunnels.New(tunnels.Options{}),
		stubService{id: "1password"},
		stubService{id: "browser"},
	}

	got := filterServices(all, []string{"tunnels", "browser"})

	if len(got) != 2 {
		t.Fatalf("want 2 services, got %d", len(got))
	}
	if got[0].Meta().ID != "tunnels" || got[1].Meta().ID != "browser" {
		t.Errorf("wrong services selected: %s, %s", got[0].Meta().ID, got[1].Meta().ID)
	}
}

func TestOnlyEmptyKeepsEverything(t *testing.T) {
	all := []service.Service{stubService{id: "a"}, stubService{id: "b"}}
	if len(filterServices(all, nil)) != 2 {
		t.Error("no --only should keep every service")
	}
}

// Whitespace is what you get from `--only tunnels, browser`.
func TestOnlyToleratesSpaces(t *testing.T) {
	all := []service.Service{stubService{id: "tunnels"}, stubService{id: "browser"}}
	if len(filterServices(all, []string{"tunnels", " browser"})) != 2 {
		t.Error("a space after a comma should not lose a service")
	}
}

// Turning the cache on with no explicit TTL must still produce a bounded one:
// a zero TTL means "no cache", so falling through to it would silently
// disable the flag the user just passed.
func TestCacheTTLIsBoundedWhenTheFlagIsOn(t *testing.T) {
	f := defaults()
	if got := cacheTTL(f); got != 0 {
		t.Errorf("without --cache nothing should be held, got %s", got)
	}

	f.cache = true
	if got := cacheTTL(f); got <= 0 {
		t.Errorf("--cache with no TTL must still bound itself, got %s", got)
	}

	f.cacheTTL = 90 * time.Second
	if got := cacheTTL(f); got != 90*time.Second {
		t.Errorf("an explicit TTL should win, got %s", got)
	}
}

type stubService struct{ id string }

func (s stubService) Meta() service.Meta { return service.Meta{ID: s.id} }
func (s stubService) Probe(_ context.Context, _ service.Host) service.Support {
	return service.Supported()
}
func (s stubService) Attach(_ context.Context, _ service.Host) (service.Instance, error) {
	return nil, nil
}

// The interface is what devtun is; the log is what you ask for when you want
// to pipe it or watch it in a corner. But a TUI written into a pipe is line
// noise, so anything that is not a terminal still gets machine-readable output
// without being asked.
func TestModeSelection(t *testing.T) {
	tests := []struct {
		name    string
		flags   upFlags
		tty     bool
		wantTUI bool
	}{
		{"a terminal gets the interface", upFlags{}, true, true},
		{"--log opts out", upFlags{logMode: true}, true, false},
		{"--json opts out", upFlags{jsonOut: true}, true, false},
		{"--plain opts out", upFlags{plain: true}, true, false},
		{"a pipe never gets the interface", upFlags{}, false, false},
		{"--tui cannot force it into a pipe", upFlags{tui: true}, false, false},
		{"--tui on a terminal is the default anyway", upFlags{tui: true}, true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := wantsTUI(test.flags, test.tty); got != test.wantTUI {
				t.Errorf("wantsTUI = %v, want %v", got, test.wantTUI)
			}
		})
	}
}

// The assembled registry, checked as a whole.
//
// Every bug that reached a release lived here rather than inside a package:
// the SSH agent got no prompter, the helper had no way to be downloaded, the
// hide list could not express a range. Each package was correct and well
// tested; what was wrong was how they were wired together, and nothing looked
// at that.
func TestTheAssembledRegistry(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	services, tunnelSvc, opSvc, agentSvc, err := buildServices(defaults(), store, false)
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}

	t.Run("every service is present and uniquely named", func(t *testing.T) {
		want := map[string]bool{"tunnels": false, "1password": false, "ssh-agent": false, "browser": false}
		for _, svc := range services {
			id := svc.Meta().ID
			seen, known := want[id]
			if !known {
				t.Errorf("unexpected service %q", id)
				continue
			}
			if seen {
				t.Errorf("service %q appears twice; ids are config keys and event fields", id)
			}
			want[id] = true
		}
		for id, seen := range want {
			if !seen {
				t.Errorf("service %q was not registered", id)
			}
		}
	})

	t.Run("every service has the metadata the interface needs", func(t *testing.T) {
		for _, svc := range services {
			m := svc.Meta()
			if m.Title == "" || m.Glyph == "" || m.Short == "" {
				t.Errorf("%s is missing display metadata: %+v", m.ID, m)
			}
			if m.Class == "" {
				t.Errorf("%s has no event class, so its events would render as lifecycle", m.ID)
			}
		}
	})

	// The bug that shipped: a broker with no prompter refuses everything
	// silently, and only the 1Password service was being given one.
	t.Run("every broker can be given a prompter", func(t *testing.T) {
		var brokers int
		for _, svc := range services {
			if _, ok := svc.(interface{ SetPrompter(prompt.Prompter) }); ok {
				brokers++
			}
		}
		if brokers != 2 {
			t.Errorf("found %d promptable brokers, want 1Password and the SSH agent", brokers)
		}
	})

	t.Run("the concrete services are returned for the interface to drive", func(t *testing.T) {
		if tunnelSvc == nil || opSvc == nil || agentSvc == nil {
			t.Error("the interface needs all three to render its tabs")
		}
	})
}

// --only must be able to name every service, or a flag silently selects
// nothing and devtun starts with no services at all.
func TestOnlyAcceptsEveryServiceName(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	services, _, _, _, err := buildServices(defaults(), store, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, svc := range services {
		id := svc.Meta().ID
		if got := filterServices(services, []string{id}); len(got) != 1 {
			t.Errorf("--only %s selected %d services", id, len(got))
		}
	}
}

// A hide list that will not parse must stop devtun rather than being read as
// empty: an empty hide list forwards everything, which is the wrong direction.
func TestABrokenHideListIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("hide: \"not-a-port\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err := buildServices(defaults(), hostcfg.Open(dir), false)
	if err == nil {
		t.Fatal("an unparseable hide list must not be read as 'hide nothing'")
	}
	if !strings.Contains(err.Error(), "hide") {
		t.Errorf("the error should name the setting, got %v", err)
	}
}
