package sshx

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// configFrom writes each block of ssh_config text to its own file and loads
// them as a chain, in the order given.
func configFrom(t *testing.T, blocks ...string) *Config {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, block := range blocks {
		path := filepath.Join(dir, fmt.Sprintf("config%d", i))
		if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
			t.Fatalf("writing ssh config: %v", err)
		}
		paths = append(paths, path)
	}
	cfg, err := LoadConfigFiles(paths...)
	if err != nil {
		t.Fatalf("LoadConfigFiles: %v", err)
	}
	return cfg
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in   string
		user string
		host string
		port int
		err  bool
	}{
		{"devbox", "", "devbox", 0, false},
		{"jeff@devbox", "jeff", "devbox", 0, false},
		{"devbox:2222", "", "devbox", 2222, false},
		{"jeff@devbox:2222", "jeff", "devbox", 2222, false},
		{"ssh://jeff@devbox:2222", "jeff", "devbox", 2222, false},
		{"192.168.1.10", "", "192.168.1.10", 0, false},
		{"[::1]", "", "::1", 0, false},
		{"[::1]:2222", "", "::1", 2222, false},
		{"jeff@[fe80::1]:22", "jeff", "fe80::1", 22, false},
		{"fe80::1:2:3", "", "fe80::1:2:3", 0, false}, // bare v6 keeps every colon
		{"", "", "", 0, true},
		{"  ", "", "", 0, true},
		{"@devbox", "", "", 0, true},
		{"jeff@", "", "", 0, true},
		{"devbox:0", "", "", 0, true},
		{"devbox:99999", "", "", 0, true},
		{"devbox:http", "", "", 0, true},
		{"[::1:2222", "", "", 0, true},
		{"[::1]x", "", "", 0, true},
	}
	for _, tt := range tests {
		user, host, port, err := ParseTarget(tt.in)
		if tt.err {
			if err == nil {
				t.Errorf("ParseTarget(%q) should have failed", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q) = %v", tt.in, err)
			continue
		}
		if user != tt.user || host != tt.host || port != tt.port {
			t.Errorf("ParseTarget(%q) = %q, %q, %d; want %q, %q, %d",
				tt.in, user, host, port, tt.user, tt.host, tt.port)
		}
	}
}

func TestResolveUsesSSHConfig(t *testing.T) {
	cfg := configFrom(t, `Host devbox
  HostName 10.0.0.7
  User jeff
  Port 2222
  IdentityFile /keys/devbox_ed25519
  ProxyJump bastion
`)
	d, err := Resolve("devbox", cfg, Overrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "10.0.0.7" || d.User != "jeff" || d.Port != 2222 {
		t.Errorf("got %+v, want 10.0.0.7 / jeff / 2222", d)
	}
	if d.ProxyJump != "bastion" {
		t.Errorf("ProxyJump = %q, want bastion", d.ProxyJump)
	}
	// A configured key is kept whether or not it exists: a name that was asked
	// for deserves a complaint when it is loaded, not a silent omission.
	if !reflect.DeepEqual(d.IdentityFiles, []string{"/keys/devbox_ed25519"}) {
		t.Errorf("IdentityFiles = %v", d.IdentityFiles)
	}
	// The alias, not the resolved address, is what everything is filed under.
	if d.Alias != "devbox" || d.Label() != "devbox" {
		t.Errorf("Alias/Label = %q/%q, want devbox", d.Alias, d.Label())
	}
}

func TestResolveReadsEveryIdentityFile(t *testing.T) {
	cfg := configFrom(t, `Host devbox
  IdentityFile /keys/one
  IdentityFile /keys/two
`)
	d, err := Resolve("devbox", cfg, Overrides{User: "u"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(d.IdentityFiles, []string{"/keys/one", "/keys/two"}) {
		t.Errorf("IdentityFiles = %v, want both configured keys", d.IdentityFiles)
	}
}

func TestResolveCommandLineWinsOverConfig(t *testing.T) {
	cfg := configFrom(t, `Host devbox
  HostName 10.0.0.7
  User jeff
  Port 2222
  IdentityFile /keys/from_config
  ProxyJump bastion
`)
	d, err := Resolve("devbox", cfg, Overrides{
		User:          "root",
		Port:          22,
		IdentityFiles: []string{"/keys/explicit"},
		ProxyJump:     "other-bastion",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.User != "root" || d.Port != 22 || d.ProxyJump != "other-bastion" {
		t.Errorf("overrides not applied: %+v", d)
	}
	// -i replaces rather than appends, matching ssh(1), and implies
	// IdentitiesOnly.
	if !reflect.DeepEqual(d.IdentityFiles, []string{"/keys/explicit"}) {
		t.Errorf("IdentityFiles = %v, want only the explicit key", d.IdentityFiles)
	}
	if !d.IdentitiesOnly {
		t.Error("naming a key with -i should imply IdentitiesOnly")
	}
}

func TestResolveTypedValuesWinOverConfig(t *testing.T) {
	cfg := configFrom(t, "Host devbox\n  User jeff\n  Port 2222\n")
	d, err := Resolve("root@devbox:2200", cfg, Overrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.User != "root" || d.Port != 2200 {
		t.Errorf("got %s@%d, want root@2200", d.User, d.Port)
	}
}

func TestResolveDefaults(t *testing.T) {
	d, err := Resolve("plainhost", nil, Overrides{User: "someone"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "plainhost" || d.Port != DefaultPort {
		t.Errorf("got %s:%d, want plainhost:22", d.Host, d.Port)
	}
	if d.Addr() != "plainhost:22" {
		t.Errorf("Addr() = %q", d.Addr())
	}
}

func TestResolveExpandsHostNameToken(t *testing.T) {
	cfg := configFrom(t, "Host web1\n  HostName %h.internal.example.com\n")
	d, err := Resolve("web1", cfg, Overrides{User: "u"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "web1.internal.example.com" {
		t.Errorf("Host = %q, want the %%h expansion", d.Host)
	}
}

func TestResolveIgnoresProxyJumpNone(t *testing.T) {
	cfg := configFrom(t, "Host devbox\n  ProxyJump none\n")
	d, err := Resolve("devbox", cfg, Overrides{User: "u"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.ProxyJump != "" {
		t.Errorf("ProxyJump = %q, want empty for \"none\"", d.ProxyJump)
	}
}

func TestResolveReadsStrictHostKeyChecking(t *testing.T) {
	cfg := configFrom(t, "Host devbox\n  StrictHostKeyChecking accept-new\n")
	d, err := Resolve("devbox", cfg, Overrides{User: "u"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ParseHostKeyMode(d.StrictHostKey) != HostKeyAcceptNew {
		t.Errorf("StrictHostKey = %q", d.StrictHostKey)
	}
}

// gpg-agent users set IdentityAgent because its socket lives at a fixed path
// rather than wherever SSH_AUTH_SOCK happens to point in a given shell.
func TestResolveReadsIdentityAgent(t *testing.T) {
	cfg := configFrom(t, "Host devbox\n  IdentityAgent ~/.gnupg/S.gpg-agent.ssh\n")
	d, err := Resolve("devbox", cfg, Overrides{User: "u"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.IdentityAgent != "~/.gnupg/S.gpg-agent.ssh" {
		t.Errorf("IdentityAgent = %q", d.IdentityAgent)
	}
	// The ~ is expanded when the agent is chosen, not when the value is read.
	home, _ := os.UserHomeDir()
	if got := resolveAgentPath("", d.IdentityAgent); got != filepath.Join(home, ".gnupg", "S.gpg-agent.ssh") {
		t.Errorf("resolved agent path = %q", got)
	}
}

func TestResolveRejectsBadDestination(t *testing.T) {
	if _, err := Resolve("", nil, Overrides{}); err == nil {
		t.Error("want an error for an empty destination")
	}
}

func TestDestinationString(t *testing.T) {
	tests := []struct {
		d    Destination
		want string
	}{
		{Destination{Host: "devbox", User: "jeff", Port: 22}, "jeff@devbox"},
		{Destination{Host: "devbox", User: "jeff", Port: 2222}, "jeff@devbox:2222"},
		{Destination{Host: "devbox", Port: 22}, "devbox"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestDestinationAddrBracketsIPv6(t *testing.T) {
	d := Destination{Host: "::1", Port: 2222}
	if got := d.Addr(); got != "[::1]:2222" {
		t.Errorf("Addr() = %q, want [::1]:2222", got)
	}
	// An already-bracketed host must not be double-bracketed.
	d = Destination{Host: "[::1]", Port: 22}
	if got := d.Addr(); got != "[::1]:22" {
		t.Errorf("Addr() = %q, want [::1]:22", got)
	}
}

func TestDestinationLabelFallsBackToHost(t *testing.T) {
	d := Destination{Alias: "devbox", Host: "10.0.0.7"}
	if got := d.Label(); got != "devbox" {
		t.Errorf("Label() = %q, want the alias", got)
	}
	d = Destination{Alias: "", Host: "10.0.0.1"}
	if got := d.Label(); got != "10.0.0.1" {
		t.Errorf("Label() = %q", got)
	}
}

// Two boxes behind one address on different ports must not share settings or
// policy, so a port the user typed is part of the identity.
func TestLabelKeepsATypedPort(t *testing.T) {
	d, err := Resolve("root@127.0.0.1:12222", nil, Overrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Label() != "127.0.0.1:12222" {
		t.Errorf("Label() = %q, want 127.0.0.1:12222", d.Label())
	}
	if d.User != "root" {
		t.Errorf("User = %q, want root", d.User)
	}
}

// A port from ssh_config already travels with the alias, so adding it to the
// label would only make the same box change identity when the file changes.
func TestLabelIgnoresAPortFromConfig(t *testing.T) {
	cfg := configFrom(t, "Host devbox\n  Port 2222\n")
	d, err := Resolve("devbox", cfg, Overrides{User: "u"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Label() != "devbox" {
		t.Errorf("Label() = %q, want devbox", d.Label())
	}
}

func TestExpandPath(t *testing.T) {
	home := isolatedHome(t)

	if got := ExpandPath("~/.ssh/id_ed25519"); got != filepath.Join(home, ".ssh", "id_ed25519") {
		t.Errorf("ExpandPath(~) = %q", got)
	}
	if got := ExpandPath("/absolute/path"); got != "/absolute/path" {
		t.Errorf("ExpandPath(absolute) = %q", got)
	}
	if got := ExpandPath(`"/quoted/path"`); got != "/quoted/path" {
		t.Errorf("ExpandPath(quoted) = %q", got)
	}
	t.Setenv("DEVTUN_TEST_DIR", "/expanded")
	if got := ExpandPath("$DEVTUN_TEST_DIR/key"); got != "/expanded/key" {
		t.Errorf("ExpandPath(env) = %q", got)
	}
}

// The chain must be consulted in order, with the first non-empty answer
// winning, so a user's config overrides the system one key by key.
func TestConfigFirstMatchWins(t *testing.T) {
	cfg := configFrom(t,
		"Host devbox\n  User first\n",
		"Host devbox\n  User second\n  Port 2222\n")

	if got := cfg.Get("devbox", "User"); got != "first" {
		t.Errorf("User = %q, want the user config's value", got)
	}
	if got := cfg.Get("devbox", "Port"); got != "2222" {
		t.Errorf("Port = %q, want the system config's value as a fallback", got)
	}
	if got := cfg.Get("devbox", "Nonexistent"); got != "" {
		t.Errorf("Nonexistent = %q, want empty", got)
	}
}

// A nil *Config is "no ssh_config at all", so every caller without one needs
// no special case.
func TestNilConfigAnswersEmpty(t *testing.T) {
	var cfg *Config
	if got := cfg.Get("devbox", "User"); got != "" {
		t.Errorf("Get on a nil Config = %q", got)
	}
	if got := cfg.GetAll("devbox", "IdentityFile"); got != nil {
		t.Errorf("GetAll on a nil Config = %v", got)
	}
}

func TestLoadConfigReadsTheUserFile(t *testing.T) {
	home := isolatedHome(t)
	content := "Host devbox\n  HostName 10.1.2.3\n  User jeff\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	d, err := Resolve("devbox", cfg, Overrides{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Host != "10.1.2.3" || d.User != "jeff" {
		t.Errorf("got %+v, want 10.1.2.3 / jeff", d)
	}
}

func TestLoadConfigToleratesAMissingFile(t *testing.T) {
	isolatedHome(t)
	if _, err := LoadConfig(); err != nil {
		t.Errorf("LoadConfig with no ~/.ssh/config = %v, want nil", err)
	}
}

func TestParseHostKeyMode(t *testing.T) {
	tests := map[string]HostKeyMode{
		"yes":        HostKeyStrict,
		"YES":        HostKeyStrict,
		"no":         HostKeyNone,
		"off":        HostKeyNone,
		"accept-new": HostKeyAcceptNew,
		"ask":        HostKeyAsk,
		"":           HostKeyAsk,
		"nonsense":   HostKeyAsk,
	}
	for in, want := range tests {
		if got := ParseHostKeyMode(in); got != want {
			t.Errorf("ParseHostKeyMode(%q) = %q, want %q", in, got, want)
		}
	}
}
