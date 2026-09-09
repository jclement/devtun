package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/approval"
	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
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

		// A board and an interface are two implementations of one surface.
		// Asking for the board says where you intend to interact, so the
		// terminal becomes the record rather than a second copy of the board.
		{"--web makes the terminal a log", upFlags{web: "on"}, true, false},
		{"--web with an address does too", upFlags{web: "127.0.0.1:8765"}, true, false},
		// ...unless you say otherwise. The command line is about this run.
		{"--tui --web is both, deliberately", upFlags{web: "on", tui: true}, true, true},
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
	services, tunnelSvc, err := buildServices(defaults(), store, prompt.MustParseSurfaces("all"), false, approval.New(approval.Options{}))
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}

	t.Run("every service is present and uniquely named", func(t *testing.T) {
		want := map[string]bool{
			"tunnels": false, "1password": false, "ssh-agent": false,
			"gpg-agent": false, "browser": false,
		}
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

	// A service that has to be asked for is one nobody finds unless it is on
	// the Services tab saying so. Registered and off is the only combination
	// that works; omitted-until-configured is a feature with no way in.
	t.Run("an opt-in service is registered rather than omitted", func(t *testing.T) {
		var found bool
		for _, svc := range services {
			if svc.Meta().ID == "gpg-agent" {
				found = svc.Meta().OptIn
			}
		}
		if !found {
			t.Error("the GPG bridge is either missing or not marked opt-in")
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
		// 1Password, the SSH agent, and the browser: every service that puts
		// a question to a human. A count rather than a list of names, because
		// the point is that nothing gated is missing one.
		if brokers != 3 {
			t.Errorf("found %d promptable brokers, want 1Password, the SSH agent and the browser", brokers)
		}
	})

	// The bug that shipped after that one: they *can* be given a prompter, and
	// only two of them were.
	//
	// The prompter was handed to each constructor by name and the SSH agent was
	// not on the list. Under the interface it went unnoticed, because tui.Run
	// installs one on everything it can by interface — so this only bit in log
	// mode and under --web, where every signature was refused the instant it
	// was asked for, with a browser open in front of you that could have
	// answered. A count is not enough: the question is whether one arrived.
	t.Run("every broker was actually given one", func(t *testing.T) {
		for _, svc := range services {
			asker, ok := svc.(interface{ CanAsk() bool })
			if !ok {
				continue
			}
			if !asker.CanAsk() {
				t.Errorf("%s has nowhere to put a question, so it refuses everything "+
					"policy does not already allow — and says so as though somebody meant it",
					svc.Meta().ID)
			}
		}
	})

	t.Run("the tunnels service is returned for the interface to drive", func(t *testing.T) {
		if tunnelSvc == nil {
			t.Error("the interface renders its port table from this")
		}
	})

	// Everything that gates something has to turn up on the Access tab, or it
	// is access nobody can see or take back. The tab finds them by interface,
	// so this is the check that the interface is actually implemented.
	t.Run("every broker exposes its rules", func(t *testing.T) {
		var brokers int
		for _, svc := range services {
			if _, ok := svc.(interface {
				Rules() []authz.Rule
				Grants() []authz.Grant
			}); ok {
				brokers++
			}
		}
		if brokers != 3 {
			t.Errorf("%d services expose rules, want the three that gate something", brokers)
		}
	})
}

// --only must be able to name every service, or a flag silently selects
// nothing and devtun starts with no services at all.
func TestOnlyAcceptsEveryServiceName(t *testing.T) {
	store := hostcfg.Open(t.TempDir())
	services, _, err := buildServices(defaults(), store, prompt.MustParseSurfaces("all"), false, approval.New(approval.Options{}))
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

	_, _, err := buildServices(defaults(), hostcfg.Open(dir), prompt.MustParseSurfaces("all"), false, approval.New(approval.Options{}))
	if err == nil {
		t.Fatal("an unparseable hide list must not be read as 'hide nothing'")
	}
	if !strings.Contains(err.Error(), "hide") {
		t.Errorf("the error should name the setting, got %v", err)
	}
}

// How approvals are asked for is a property of the machine you sit at, so it
// lives in config — and the flag still wins, because the command line is about
// this run.
func TestPromptBackendResolution(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("prompt: dialog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts", "quiet.yaml"), []byte("prompt: tui\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := hostcfg.Open(dir)

	if got := promptSetting(defaults(), store, "bedev"); got != "dialog" {
		t.Errorf("a host with no setting = %q, want the global one", got)
	}
	if got := promptSetting(defaults(), store, "quiet"); got != "tui" {
		t.Errorf("a host that says tui = %q, want tui", got)
	}

	flags := defaults()
	flags.promptBackend = "deny"
	if got := promptSetting(flags, store, "bedev"); got != "deny" {
		t.Errorf("--prompt lost to the config file: %q", got)
	}

	// And with nothing configured anywhere, all — every surface this session
	// has, which is what makes the empty flag default readable as "not set"
	// rather than as a choice.
	if got := promptSetting(defaults(), hostcfg.Open(t.TempDir()), "bedev"); got != "all" {
		t.Errorf("an unconfigured machine = %q, want all", got)
	}
}

// `setup:` in the config file has to reach the session, or the setting is one
// the Config tab offers and nothing reads.
func TestSetupModeResolution(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("setup: never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := hostcfg.Open(dir)

	got, err := setupMode(defaults(), store)
	if err != nil {
		t.Fatalf("setupMode: %v", err)
	}
	if got != session.SetupNever {
		t.Errorf("the config file said never and the session got %q", got)
	}

	// The command line is about this run and must always be able to win.
	flags := defaults()
	flags.setup = "auto"
	if got, err := setupMode(flags, store); err != nil || got != session.SetupAuto {
		t.Errorf("--setup lost to the config file: %q, %v", got, err)
	}

	// And with nothing configured, ask — the answer that leaves the user's file
	// alone until they say otherwise.
	if got, err := setupMode(defaults(), hostcfg.Open(t.TempDir())); err != nil || got != session.SetupAsk {
		t.Errorf("an unconfigured machine = %q, %v", got, err)
	}

	flags.setup = "yolo"
	if _, err := setupMode(flags, store); err == nil {
		t.Error("an unknown setup mode was accepted")
	}
}

// A prompt setting this session cannot honour must fail at startup with
// something a person can act on, rather than at the moment a secret is asked
// for.
func TestAPromptSettingThisSessionCannotHonourIsRefusedUpFront(t *testing.T) {
	if _, err := resolveSurfaces("gui", true, true); err == nil {
		t.Error("an unknown prompt surface was accepted")
	} else if !strings.Contains(err.Error(), "gui") {
		t.Errorf("the error does not name the setting: %v", err)
	}

	// Naming the board without running one is the case worth catching: it
	// reads as configured and answers nothing.
	_, err := resolveSurfaces("web", true, false)
	if err == nil {
		t.Fatal("--prompt web was accepted with no board to ask on")
	}
	if !strings.Contains(err.Error(), "--web") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}

	// The terminal, likewise, when there is no terminal.
	if _, err := resolveSurfaces("tui", false, false); err == nil {
		t.Error("--prompt tui was accepted with no terminal")
	}
}

// `all` is a wish rather than an instruction: a surface this session does not
// have is one fewer place to ask, not a refusal to start. That difference is
// the whole reason naming one is worth doing.
func TestAllQuietlyUsesWhateverThisSessionHas(t *testing.T) {
	got, err := resolveSurfaces("all", true, false)
	if err != nil {
		t.Fatalf("all with no board: %v", err)
	}
	if got.Has(prompt.SurfaceWeb) {
		t.Error("`all` kept the board on a session that has none")
	}
	if !got.Has(prompt.SurfaceTUI) {
		t.Error("`all` dropped the terminal, which this session has")
	}

	// But `all` with nothing at all behind it is still an error: it means
	// every request would be refused without anybody being asked, and that is
	// worth saying at startup rather than discovering from a failed push.
	//
	// Through the injected check, because every Mac has osascript and no test
	// running on one can reach this branch otherwise.
	nothing := func(prompt.Surface) bool { return false }
	if _, err := resolveSurfacesWith("all", nothing); err == nil {
		t.Error("a session with nowhere to ask started anyway")
	} else if !strings.Contains(err.Error(), "--prompt deny") {
		t.Errorf("the error does not offer the way out: %v", err)
	}
}

// deny is a decision, and must not be mistaken for having nowhere to ask.
func TestDenyStartsFineWithNoSurfacesAtAll(t *testing.T) {
	got, err := resolveSurfaces("deny", false, false)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if got.Any() {
		t.Error("deny left somewhere to ask")
	}
}

// A malformed host file must stop devtun, not read as an empty one.
//
// Host files load lazily and Err() reports only what has been read, so the
// refusal gate used to be looking at the global file alone. A broken
// hosts/<host>.yaml therefore became an empty host config — its deny rules and
// hide ranges silently gone — and devtun carried on with wider access than the
// file asked for. That is the exact failure the gate exists to prevent,
// arriving through the door it was not watching.
func TestABrokenHostFileStopsStartup(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts", "bedev.yaml"),
		[]byte("1password:\n  rules:\n   - {subject: \"op://Private/**\", action: deny}\n  bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := hostcfg.Open(dir)
	if err := store.Err(); err != nil {
		t.Fatalf("the global file is fine; Err() should be quiet until a host is read: %v", err)
	}

	store.LoadHost("bedev")
	if store.Err() == nil {
		t.Fatal("a host file that will not parse was read as an empty one, taking its deny rules with it")
	}
}

// Each broker gets its own global rules.
//
// One slice used to be read from the 1Password section and handed to all three,
// so a global 1Password deny also refused every signature and every browser
// open, while ssh-agent and browser rules written globally were read by nobody.
func TestEachBrokerReadsItsOwnGlobalRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
1password:
  rules:
    - {host: "**", subject: "op://Private/**", action: deny}
ssh-agent:
  rules:
    - {host: "**", subject: "** → github.com", action: allow}
browser:
  rules:
    - {host: "**", subject: "example.com", action: deny}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := hostcfg.Open(dir)

	for _, tc := range []struct{ service, subject string }{
		{"1password", "op://Private/**"},
		{"ssh-agent", "** → github.com"},
		{"browser", "example.com"},
	} {
		rules, err := globalRules(store, tc.service)
		if err != nil {
			t.Fatalf("%s: %v", tc.service, err)
		}
		if len(rules) != 1 || rules[0].Subject != tc.subject {
			t.Errorf("%s got %+v, want only its own rule", tc.service, rules)
		}
	}
}
