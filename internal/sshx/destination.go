// Package sshx is devtun's SSH transport: ssh_config resolution,
// authentication, host key verification, and the single connection everything
// else — the prober, the tunnels, the reverse-forwarded socket — is
// multiplexed over.
//
// devtun speaks SSH in-process rather than shelling out to ssh(1). The cost is
// this package: ssh_config, key loading, agent discovery, known_hosts and
// ProxyJump all re-implemented, none of which the ssh binary would have made
// us write. The benefit is a single static binary with no runtime
// dependencies, identical behaviour on macOS, Linux and Windows, structured
// errors instead of parsed stderr, and — the part that actually forced it —
// the ability to keep a listener in-process rather than negotiating with a
// child process's lifetime.
package sshx

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
)

// DefaultPort is used when neither the destination nor ssh_config says
// otherwise.
const DefaultPort = 22

// Destination is a fully resolved SSH destination.
type Destination struct {
	// Alias is the name as typed, before ssh_config rewrote it into an
	// address. It is what the user recognises, and what Label is built from.
	Alias string
	// Host and Port are where to connect.
	Host string
	Port int
	// User is the remote account.
	User string
	// IdentityFiles are candidate private keys, most specific first. They are
	// kept exactly as configured, whether or not they exist: a key named
	// explicitly and then missing deserves a complaint when it is loaded, not
	// a silent omission here.
	IdentityFiles []string
	// IdentitiesOnly suppresses the SSH agent, offering only the configured
	// keys. Passing -i explicitly implies it, matching ssh(1): otherwise a
	// well-stocked agent burns through the server's MaxAuthTries before the
	// key you actually named is ever tried.
	IdentitiesOnly bool
	// IdentityAgent is ssh_config's per-host agent socket. gpg-agent users
	// commonly set it, because its socket lives at a fixed path rather than
	// wherever SSH_AUTH_SOCK happens to point in a given shell.
	IdentityAgent string
	// ProxyJump is the raw ssh_config value, possibly a comma-separated chain.
	ProxyJump string
	// StrictHostKey is ssh_config's StrictHostKeyChecking, empty when unset.
	StrictHostKey string

	// portTyped records that the port came from the user rather than from
	// ssh_config, which is what makes it part of the identity. See Label.
	portTyped bool
}

// Label is the name devtun files everything persistent under: per-host
// settings, tunnel policy, approvals. It therefore has to survive the host's
// address, user and keys all changing, and it has to keep two boxes reached on
// different ports of one address apart. The ssh_config alias does the first,
// because it is what the user typed and what they recognise; a port joins it
// only when the user typed that too, since a port that came from ssh_config
// already travels with the alias.
func (d *Destination) Label() string {
	name := d.Alias
	if name == "" {
		name = d.Host
	}
	if d.portTyped {
		return joinHostPort(name, d.Port)
	}
	return name
}

// Addr renders host:port for dialling.
func (d *Destination) Addr() string { return joinHostPort(d.Host, d.Port) }

// String renders the destination the way a person would write it.
func (d *Destination) String() string {
	s := d.Host
	if d.User != "" {
		s = d.User + "@" + s
	}
	if d.Port != DefaultPort {
		s += ":" + strconv.Itoa(d.Port)
	}
	return s
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// Overrides are command-line values that win over ssh_config.
type Overrides struct {
	User          string
	Port          int
	IdentityFiles []string
	ProxyJump     string
}

// ParseTarget splits a destination as typed into its user, host and port
// parts. Accepted forms: "host", "user@host", "host:port", "user@host:port",
// "ssh://user@host:port", and bracketed IPv6 literals.
func ParseTarget(raw string) (user, host string, port int, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", 0, fmt.Errorf("empty destination")
	}
	s = strings.TrimPrefix(s, "ssh://")
	if u, rest, ok := strings.Cut(s, "@"); ok {
		if u == "" {
			return "", "", 0, fmt.Errorf("destination %q has an empty user", raw)
		}
		user, s = u, rest
	}
	if s == "" {
		return "", "", 0, fmt.Errorf("destination %q has an empty host", raw)
	}
	// Bracketed IPv6: [::1] or [::1]:2222
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", 0, fmt.Errorf("destination %q has an unterminated [", raw)
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", "", 0, fmt.Errorf("unexpected %q after address in %q", rest, raw)
			}
			port, err = parsePortStr(rest[1:], raw)
		}
		return user, host, port, err
	}
	// A bare IPv6 literal has several colons; only a single trailing colon is
	// a port separator, because guessing would break the address.
	if strings.Count(s, ":") == 1 {
		h, p, _ := strings.Cut(s, ":")
		port, err = parsePortStr(p, raw)
		return user, h, port, err
	}
	return user, s, 0, nil
}

func parsePortStr(s, raw string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("destination %q has an invalid port %q", raw, s)
	}
	return p, nil
}

// Resolve turns a typed destination into a Destination, layering ssh_config
// under the command-line overrides. A nil Config means "no ssh_config".
func Resolve(destination string, cfg *Config, o Overrides) (*Destination, error) {
	typedUser, alias, typedPort, err := ParseTarget(destination)
	if err != nil {
		return nil, err
	}

	d := &Destination{
		Alias:     alias,
		Host:      alias,
		User:      typedUser,
		Port:      typedPort,
		portTyped: typedPort != 0,
	}

	if v := cfg.Get(alias, "HostName"); v != "" {
		// OpenSSH expands %h in HostName to the alias.
		d.Host = strings.ReplaceAll(v, "%h", alias)
	}
	if d.User == "" {
		d.User = cfg.Get(alias, "User")
	}
	if d.Port == 0 {
		if p, err := strconv.Atoi(cfg.Get(alias, "Port")); err == nil {
			d.Port = p
		}
	}
	for _, v := range cfg.GetAll(alias, "IdentityFile") {
		d.IdentityFiles = append(d.IdentityFiles, ExpandPath(v))
	}
	if v := cfg.Get(alias, "ProxyJump"); v != "" && !strings.EqualFold(v, "none") {
		d.ProxyJump = v
	}
	d.IdentityAgent = cfg.Get(alias, "IdentityAgent")
	d.StrictHostKey = strings.ToLower(cfg.Get(alias, "StrictHostKeyChecking"))
	if strings.EqualFold(cfg.Get(alias, "IdentitiesOnly"), "yes") {
		d.IdentitiesOnly = true
	}

	if o.User != "" {
		d.User = o.User
	}
	if o.Port != 0 {
		d.Port = o.Port
		d.portTyped = true
	}
	if o.ProxyJump != "" {
		d.ProxyJump = o.ProxyJump
	}
	if len(o.IdentityFiles) > 0 {
		// An explicit -i replaces rather than augments, matching ssh(1), and
		// implies IdentitiesOnly.
		d.IdentityFiles = nil
		d.IdentitiesOnly = true
		for _, f := range o.IdentityFiles {
			d.IdentityFiles = append(d.IdentityFiles, ExpandPath(f))
		}
	}

	if d.Port == 0 {
		d.Port = DefaultPort
	}
	if d.User == "" {
		d.User = currentUsername()
	}
	if d.User == "" {
		return nil, fmt.Errorf("cannot determine a username for %q; pass --user", destination)
	}
	return d, nil
}

// Config is the user's ssh_config: one entry per file, consulted in order,
// first non-empty answer winning. A nil *Config answers everything with the
// zero value, so callers with no configuration need no special case.
type Config struct {
	files []*ssh_config.Config
}

// LoadConfig reads the user and system ssh_config files. A missing file is not
// an error; a malformed one is, because silently ignoring it would connect
// somewhere other than where the user said.
func LoadConfig() (*Config, error) {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".ssh", "config"))
	}
	paths = append(paths, "/etc/ssh/ssh_config")
	return LoadConfigFiles(paths...)
}

// LoadConfigFiles reads specific ssh_config files, for an explicit -F and for
// tests that must not see the developer's own configuration.
func LoadConfigFiles(paths ...string) (*Config, error) {
	cfg := &Config{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		parsed, err := ssh_config.Decode(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		cfg.files = append(cfg.files, parsed)
	}
	return cfg, nil
}

// Get returns the first non-empty value for key across the files. Unlike the
// ssh_config package's own defaults, an unset key stays empty: what to do
// about it is Resolve's decision, not this file's.
func (c *Config) Get(alias, key string) string {
	if c == nil {
		return ""
	}
	for _, f := range c.files {
		if v, err := f.Get(alias, key); err == nil && v != "" {
			return v
		}
	}
	return ""
}

// GetAll returns every value for key from the first file that has any, which
// is how IdentityFile accumulates several keys for one host.
func (c *Config) GetAll(alias, key string) []string {
	if c == nil {
		return nil
	}
	for _, f := range c.files {
		if v, err := f.GetAll(alias, key); err == nil && len(v) > 0 {
			return v
		}
	}
	return nil
}

// ExpandPath resolves ~ and environment variables in a path.
func ExpandPath(p string) string {
	p = strings.Trim(p, `"`)
	p = os.ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p[1:], string(filepath.Separator)))
		}
	}
	return p
}

// currentUsername is the fallback remote account, matching ssh's habit of
// assuming the local one.
func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		name := u.Username
		// Windows reports DOMAIN\user.
		if i := strings.LastIndexAny(name, `\/`); i >= 0 {
			name = name[i+1:]
		}
		return name
	}
	for _, k := range []string{"USER", "LOGNAME", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
