package web

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jclement/devtun/internal/approval"
	"github.com/jclement/devtun/internal/authz"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/tunnels"
)

// TestDemoBoard serves the board with a realistic session behind it — two
// gated brokers, rules from all three sources, live grants and refusals, a
// port table, a log with decisions in it — and blocks, so a person or a
// headless browser can look at it. It is how the board's screenshots are
// taken, and it never touches a real host.
//
//	DEVTUN_WEB_DEMO=127.0.0.1:7788 go test ./internal/web -run TestDemoBoard -timeout 0
//
// then open http://127.0.0.1:7788/?t=demo. Skipped unless the variable is set.
func TestDemoBoard(t *testing.T) {
	addr := os.Getenv("DEVTUN_WEB_DEMO")
	if addr == "" {
		t.Skip("set DEVTUN_WEB_DEMO=host:port to serve the demo board")
	}
	now := time.Now()

	vault := newVault(t, &testBook{loaded: authz.Loaded{
		Global: []authz.Rule{
			{Subject: "op://Private/Root Keys/**", Action: authz.ActionDeny, Note: "never, from anywhere"},
			{Subject: "op://Shared/Dev/**", Action: authz.ActionAllow, Note: "dev-only creds"},
		},
		Host: []authz.Rule{
			{Host: "bedev", Subject: "op://Barreleye/CI/*", Action: authz.ActionAllow, Note: "pipeline tokens"},
		},
		Remembered: []authz.Rule{
			{Host: "bedev", Subject: "op://Personal/GitHub/token", Action: authz.ActionAllow,
				Note: "approved interactively", Added: now.Add(-8 * 24 * time.Hour)},
			{Host: "bedev", Subject: "op://Barreleye/Sentry/dsn", Action: authz.ActionAllow,
				Note: "approved interactively", Added: now.Add(-4 * 24 * time.Hour)},
			{Host: "bedev", Subject: "op://Personal/Stripe/secret key", Action: authz.ActionDeny,
				Note: "refused interactively", Added: now.Add(-26 * time.Hour)},
			{Host: "bedev", Subject: "op://Private/Root Keys/gpg", Action: authz.ActionAllow,
				Added: now.Add(-3 * 24 * time.Hour)},
			{Host: "bedev", Subject: "[work] op://Barreleye/Deploy/*", Action: authz.ActionAllow,
				Note: "deploy keys, work account", Added: now.Add(-2 * time.Hour)},
		},
	}}, authz.Schema{
		Noun:     "secret",
		Fields:   []authz.Field{{Name: "reference", Label: "reference", Help: "op://vault/item/field, or an op command line"}},
		PathLike: true,
	})
	agent := newVault(t, &testBook{loaded: authz.Loaded{
		Host:           []authz.Rule{{Host: "bedev", Subject: "** → **", Action: authz.ActionDeny, Note: "nowhere else, from this box"}},
		Unmatched:      "deny",
		UnmatchedLevel: "host",
		Remembered: []authz.Rule{{Host: "bedev",
			Subject: "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZ/DTMczCvj3tD2s → github.com",
			Action:  authz.ActionAllow, Added: now.Add(-17 * 24 * time.Hour)},
			{Host: "bedev", Subject: "* → sshsig:git", Action: authz.ActionAllow,
				Note: "commit signing", Added: now.Add(-9 * 24 * time.Hour)},
		},
	}}, sshSchema)
	mustGrant := func(v *gatedVault, spec authz.GrantSpec) {
		if _, err := v.AddGrant(spec); err != nil {
			t.Fatal(err)
		}
	}
	mustGrant(vault, authz.GrantSpec{Host: "bedev", Subject: "op://Personal/Docker/PAT", Action: authz.ActionAllow, TTL: 3 * time.Minute})
	mustGrant(vault, authz.GrantSpec{Host: "bedev", Subject: "op://Barreleye/Azure DevOps/token", Action: authz.ActionAllow})
	mustGrant(vault, authz.GrantSpec{Host: "bedev", Subject: "op://Personal/AWS root/password", Action: authz.ActionDeny})
	mustGrant(agent, authz.GrantSpec{Host: "bedev", Subject: authz.HostWildcard, Action: authz.ActionAllow})

	bus := event.NewBus(200)
	emit := func(ago time.Duration, svc, kind string, class event.Class, text string, fields ...any) {
		bus.Emit(event.Event{Time: now.Add(-ago), Service: svc, Kind: kind, Class: class, Level: event.Info, Text: text, Fields: fields})
	}
	emit(14*time.Minute, "session", "connected", event.Lifecycle, "connected to bedev")
	emit(14*time.Minute, "1password", "started", event.Lifecycle, "vault ready on bedev")
	emit(14*time.Minute, "ssh-agent", "started", event.Lifecycle, "agent forwarded to bedev")
	emit(13*time.Minute, "tunnels", "opened", event.Network, "forwarding 3000 → localhost:3000 (node vite)")
	emit(9*time.Minute, "1password", "denied", event.Security, "refused bedev op://Personal/AWS root/password — you said no, and stop asking",
		"host", "bedev", "subject", "op://Personal/AWS root/password", "by", "grant", "grant", "g3")
	ruleID := func(v *gatedVault, subject string) string {
		for _, r := range v.Rules() {
			if r.Subject == subject {
				return r.ID
			}
		}
		return ""
	}
	emit(3*time.Minute, "1password", "allowed", event.Security, "gave bedev op://Personal/GitHub/token (always, 8d ago)",
		"host", "bedev", "subject", "op://Personal/GitHub/token", "by", "rule",
		"rule", ruleID(vault, "op://Personal/GitHub/token"), "source", "remembered")
	emit(2*time.Minute, "1password", "denied", event.Security, "refused bedev op://Private/Root Keys/ssh — a rule you wrote",
		"host", "bedev", "subject", "op://Private/Root Keys/ssh", "by", "rule",
		"rule", ruleID(vault, "op://Private/Root Keys/**"), "source", "global")
	emit(40*time.Second, "ssh-agent", "denied", event.Security,
		"refused bedev a signature with ssh-ed25519 SHA256:uNiV…tD2s → github.com — nowhere else, from this box",
		"host", "bedev", "subject", "ssh-ed25519 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZ/DTMczCvj3tD2s → github.com",
		"by", "rule", "rule", ruleID(agent, "** → **"), "source", "host")
	emit(20*time.Second, "1password", "requested", event.Security, "bedev wants op://Barreleye/CI/npm — deploy.sh · pid 4412")

	ports := newFakeTunnels(
		tunnels.State{RemotePort: 3000, LocalPort: 3000, Proc: "node", Cmd: "node node_modules/.bin/vite --port 3000",
			Status: tunnels.StatusActive, Scheme: tunnels.SchemeHTTP, Mode: tunnels.ModeAuto, Label: "web",
			FirstSeen: now.Add(-13 * time.Minute), ActiveConns: 2, BytesIn: 48211, BytesOut: 1903122},
		tunnels.State{RemotePort: 5432, LocalPort: 15432, Remapped: true, Proc: "postgres", Cmd: "postgres -D /var/lib/postgresql",
			Status: tunnels.StatusActive, Scheme: tunnels.SchemeHTTP, Mode: tunnels.ModeAuto, FirstSeen: now.Add(-12 * time.Minute)},
		tunnels.State{RemotePort: 8443, LocalPort: 8443, Proc: "caddy", Cmd: "caddy run",
			Status: tunnels.StatusActive, Scheme: tunnels.SchemeHTTPS, Mode: tunnels.ModeAuto, FirstSeen: now.Add(-5 * time.Minute), ActiveConns: 1},
	)

	// DEVTUN_WEB_DEMO_ASK=n puts n questions on the desk, oldest first, for
	// trying the approval dialog — answering one shows the next.
	var desk *approval.Desk
	if n, _ := strconv.Atoi(os.Getenv("DEVTUN_WEB_DEMO_ASK")); n > 0 {
		desk = approval.New(approval.Options{Publish: true})
		for i := 0; i < n; i++ {
			subject := fmt.Sprintf("op://Barreleye/Deploy/token-%d", i+1)
			go func() {
				_, _ = desk.Ask(context.Background(), prompt.Request{
					Host: "bedev", Subject: subject, TTL: 5 * time.Minute,
					Rows: []prompt.Row{{Label: "caller", Value: "deploy.sh"}},
				})
			}()
			for len(desk.Waiting()) < i+1 {
				time.Sleep(time.Millisecond)
			}
		}
	}

	agentSvc := &namedVault{gatedVault: agent, id: "ssh-agent", title: "SSH agent", glyph: "⚿"}
	s, err := New(Options{
		Addr: addr, FixedAddr: true, Token: "demo", Host: "bedev", Version: "v0.1.22-demo",
		Tunnels:   ports,
		Services:  []service.Service{vault, agentSvc},
		Store:     &mapStore{values: map[string]string{"bedev/ssh-agent/unmatched": "deny"}},
		Bus:       bus,
		Approvals: desk,
		Status: func() session.Status {
			return session.Status{State: session.Connected, Since: now.Add(-14 * time.Minute)}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Logf("demo board on http://%s/?t=demo", addr)
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

// namedVault is a second gated broker under its own id.
type namedVault struct {
	*gatedVault
	id, title, glyph string
}

func (v *namedVault) Meta() service.Meta {
	return service.Meta{ID: v.id, Title: v.title, Glyph: v.glyph}
}

// mapStore is the config files, in a map keyed label/section/key.
type mapStore struct {
	mu     sync.Mutex
	values map[string]string
}

func (m *mapStore) Setting(label, section, key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[label+"/"+section+"/"+key]
}

func (m *mapStore) SetSetting(label, section, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[label+"/"+section+"/"+key] = value
	return nil
}

func (m *mapStore) Save() error { return nil }
