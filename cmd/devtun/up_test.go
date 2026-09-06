package main

import (
	"context"
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
