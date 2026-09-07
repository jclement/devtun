// Package hostcfg is devtun's configuration on disk.
//
// There are two layers and the split is deliberate. A global file holds the
// things that are true of you — the vault-to-account routing, deny rules that
// must hold everywhere, ports you never want forwarded on any box. A file per
// host holds the things that are true of that box, and there is one file per
// box rather than one big map because the per-host state *is* the interesting
// state: it is what you hand-edit, what you diff, and what you would copy to
// another laptop.
//
// Services do not see any of this. They are handed a service.Config — Get and
// Set of a document under a key, namespaced to (host, service) — so tunnels
// never has to teach this package about a port table and 1Password never has to
// teach it about rules. That seam is what keeps a fourth service from needing a
// change here at all.
package hostcfg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jclement/devtun/internal/service"
)

// Dir returns devtun's configuration directory.
//
// XDG on every unix, including macOS — deliberately not os.UserConfigDir, which
// would put this in ~/Library/Application Support/devtun. These files are meant
// to be opened in an editor, diffed, and copied to another laptop, and none of
// that happens to a directory with a space in its name that Finder hides. Every
// other tool the author keeps configuration for lives in ~/.config; devtun is
// not the one that should be different.
func Dir() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "devtun"), nil
	}
	if runtime.GOOS == "windows" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("locating the configuration directory: %w", err)
		}
		return filepath.Join(base, "devtun"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating the configuration directory: %w", err)
	}
	return filepath.Join(home, ".config", "devtun"), nil
}

// Global is the top-level configuration, shared by every host.
type Global struct {
	// Hide lists remote ports never to forward, on any host. Empty by
	// default: this is the one place to say "never a database, anywhere",
	// which is a policy the user holds, not something to bake into the binary.
	//
	// Ranges are allowed, and they are the point rather than a nicety. A box
	// that binds services to port 0 gets whatever the kernel hands out, so the
	// noisy ports are different every restart and cannot be hidden one at a
	// time — `32768-60999` says the thing a person actually means.
	Hide PortSpec `yaml:"hide,omitempty"`
	// Setup is the default answer to editing a remote shell rc: ask, auto or
	// never.
	Setup string `yaml:"setup,omitempty"`
	// Services gives per-service defaults applied to a host that has not said
	// otherwise — chiefly whether a service is enabled at all.
	Services map[string]ServiceState `yaml:"services,omitempty"`
	// Data holds each service's global section, in the same shape as a host
	// file's. 1Password's deny rules live here.
	Data map[string]map[string]yaml.Node `yaml:",inline"`
}

// PortSpec is a list of ports and ranges, in the same syntax as --exclude.
//
// It accepts what a person would naturally write: a bare number, a range, a
// comma-separated string, or a list mixing all three. Being fussy about which
// of those is "correct" would be a config file arguing with its reader.
type PortSpec []string

// UnmarshalYAML accepts a scalar or a sequence, of numbers or strings.
func (p *PortSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var value string
		if err := node.Decode(&value); err != nil {
			return err
		}
		*p = PortSpec{value}
		return nil
	case yaml.SequenceNode:
		out := make(PortSpec, 0, len(node.Content))
		for _, item := range node.Content {
			var value string
			if err := item.Decode(&value); err != nil {
				return fmt.Errorf("hide: %q is not a port or a range", item.Value)
			}
			out = append(out, value)
		}
		*p = out
		return nil
	}
	return fmt.Errorf("hide: expected a port, a range, or a list of them")
}

// Spec renders the list in --exclude syntax, for a parser that already knows
// how to read it.
func (p PortSpec) Spec() string { return strings.Join(p, ",") }

// ServiceState is whether a service runs on a host.
type ServiceState struct {
	// Enabled is a pointer because absent, true and false are three different
	// answers: absent means "inherit the global default", which is not the
	// same as an explicit false.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// Host is one box's configuration.
type Host struct {
	Services map[string]ServiceState         `yaml:"services,omitempty"`
	Data     map[string]map[string]yaml.Node `yaml:",inline"`
}

// Store holds the global file and every host file that has been opened, and
// writes back the ones that changed.
//
// A malformed or missing file degrades to an empty configuration rather than an
// error. Refusing to start because a settings file has a stray tab in it would
// be the wrong trade for a tool whose job is to get you connected.
type Store struct {
	dir string

	// loadErrs records files that would not parse. A malformed file reads as
	// empty so devtun still starts — but "empty" is a dangerous answer for a
	// file that may have contained deny rules, so the error is kept and Err()
	// lets a caller that is about to make a security decision refuse instead.
	loadErrs []error

	mu     sync.Mutex
	global Global
	hosts  map[string]*Host
	dirty  map[string]bool
	// memoryOnly is set when the config directory could not be located, so
	// everything still works for this run and nothing is written.
	memoryOnly bool
}

// Open loads the global file from dir. Host files are loaded lazily.
func Open(dir string) *Store {
	s := &Store{
		dir:        dir,
		hosts:      make(map[string]*Host),
		dirty:      make(map[string]bool),
		memoryOnly: dir == "",
	}
	if dir == "" {
		return s
	}
	path := filepath.Join(dir, "config.yaml")
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &s.global); err != nil {
			s.loadErrs = append(s.loadErrs, fmt.Errorf("%s: %w", path, err))
		}
	}
	return s
}

// OpenDefault loads from the standard location, falling back to a memory-only
// store when the directory cannot be determined.
func OpenDefault() *Store {
	dir, err := Dir()
	if err != nil {
		return Open("")
	}
	return Open(dir)
}

// Err reports any configuration file that would not parse.
//
// Reading a broken file as empty is the right default for presentation
// settings: refusing to start because a sort order has a stray tab in it would
// be absurd. It is the wrong default for policy. A file that was meant to say
// "never this vault from this box" and instead says nothing has failed open,
// and silence is exactly how nobody notices. Callers about to act on rules ask
// here first and refuse rather than proceed on a partial policy.
func (s *Store) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(s.loadErrs...)
}

// Global returns a copy of the global configuration.
func (s *Store) Global() Global {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.global
}

// Path returns the directory being used, empty for a memory-only store.
func (s *Store) Path() string {
	if s.memoryOnly {
		return ""
	}
	return s.dir
}

// host returns the loaded host document, reading it from disk on first use.
// The caller must hold s.mu.
func (s *Store) host(label string) *Host {
	if h, ok := s.hosts[label]; ok {
		return h
	}
	h := &Host{}
	if !s.memoryOnly {
		path := s.hostPath(label)
		if data, err := os.ReadFile(path); err == nil {
			if err := yaml.Unmarshal(data, h); err != nil {
				s.loadErrs = append(s.loadErrs, fmt.Errorf("%s: %w", path, err))
			}
		}
	}
	s.hosts[label] = h
	return h
}

// hostPath is where a host's file lives. The label is an ssh_config alias and
// so is normally a safe filename, but it can contain a slash or a colon when
// somebody passes user@host:port — replace anything that would escape the
// directory rather than trusting it.
func (s *Store) hostPath(label string) string {
	return filepath.Join(s.dir, "hosts", sanitize(label)+".yaml")
}

func sanitize(label string) string {
	replacer := strings.NewReplacer("/", "_", `\`, "_", ":", "_", "..", "_")
	out := replacer.Replace(label)
	if out == "" || out == "." {
		return "_"
	}
	return out
}

// Enabled reports whether a service should run on a host: the host's answer if
// it has one, then the global default, then the supplied fallback.
func (s *Store) Enabled(label, serviceID string, fallback bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, ok := s.host(label).Services[serviceID]; ok && state.Enabled != nil {
		return *state.Enabled
	}
	if state, ok := s.global.Services[serviceID]; ok && state.Enabled != nil {
		return *state.Enabled
	}
	return fallback
}

// SetEnabled records whether a service runs on a host.
func (s *Store) SetEnabled(label, serviceID string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := s.host(label)
	if h.Services == nil {
		h.Services = make(map[string]ServiceState)
	}
	h.Services[serviceID] = ServiceState{Enabled: &enabled}
	s.dirty[label] = true
}

// For returns the service.Config view for one service on one host. Reads fall
// through to the global file's section of the same name, so a rule written once
// globally is visible to every host without being copied into each file.
func (s *Store) For(label, serviceID string) *Section {
	return &Section{store: s, label: label, service: serviceID}
}

// Section is For, typed as the interface the session consumes. Go needs the
// exact return type to satisfy an interface, and services want the narrow
// contract rather than this package's concrete one.
func (s *Store) Section(label, serviceID string) service.Config {
	return s.For(label, serviceID)
}

// GlobalFor returns the global-only view of a service's section, for the parts
// of a service that are deliberately not per-host.
func (s *Store) GlobalFor(serviceID string) *Section {
	return &Section{store: s, service: serviceID}
}

// Section is one service's namespaced configuration on one host. It satisfies
// service.Config.
type Section struct {
	store   *Store
	label   string // empty for the global-only view
	service string
}

// GetLocal is Get without the fall-through to the global section.
//
// The fall-through is right for settings — a default you set once should apply
// everywhere — and wrong for anything the caller will write back. 1Password
// reads its global rules separately and then asks the host for the host's own;
// with fall-through it received the global ones twice, and the next "allow
// always" wrote that whole list into the host file. Removing a global rule then
// left a copy of it behind, still granting access from a file nobody thought to
// look in.
func (c *Section) GetLocal(key string, v any) (bool, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()

	if c.label == "" {
		return false, nil
	}
	node, ok := lookup(c.store.host(c.label).Data, c.service, key)
	if !ok {
		return false, nil
	}
	if err := node.Decode(v); err != nil {
		return false, fmt.Errorf("reading %s.%s for %s: %w", c.service, key, c.label, err)
	}
	return true, nil
}

// Get decodes the document stored under key into v, reporting whether one was
// found. A host document wins over a global one of the same name.
func (c *Section) Get(key string, v any) (bool, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()

	if c.label != "" {
		if node, ok := lookup(c.store.host(c.label).Data, c.service, key); ok {
			if err := node.Decode(v); err != nil {
				return false, fmt.Errorf("reading %s.%s for %s: %w", c.service, key, c.label, err)
			}
			return true, nil
		}
	}
	if node, ok := lookup(c.store.global.Data, c.service, key); ok {
		if err := node.Decode(v); err != nil {
			return false, fmt.Errorf("reading %s.%s from the global config: %w", c.service, key, err)
		}
		return true, nil
	}
	return false, nil
}

// Set stores v under key. It marks the file dirty but does not write; the
// session saves once, on exit, so a busy tunnel table is not rewriting a YAML
// file every two seconds.
func (c *Section) Set(key string, v any) error {
	node, err := toNode(v)
	if err != nil {
		return fmt.Errorf("encoding %s.%s: %w", c.service, key, err)
	}

	c.store.mu.Lock()
	defer c.store.mu.Unlock()

	if c.label == "" {
		store(&c.store.global.Data, c.service, key, node)
		c.store.dirty[globalKey] = true
		return nil
	}
	h := c.store.host(c.label)
	store(&h.Data, c.service, key, node)
	c.store.dirty[c.label] = true
	return nil
}

// globalKey is the dirty-map entry standing for the global file. A host may
// not use it, and cannot: sanitize never produces a leading slash.
const globalKey = "/global"

func lookup(data map[string]map[string]yaml.Node, service, key string) (yaml.Node, bool) {
	section, ok := data[service]
	if !ok {
		return yaml.Node{}, false
	}
	node, ok := section[key]
	return node, ok
}

func store(data *map[string]map[string]yaml.Node, service, key string, node yaml.Node) {
	if *data == nil {
		*data = make(map[string]map[string]yaml.Node)
	}
	if (*data)[service] == nil {
		(*data)[service] = make(map[string]yaml.Node)
	}
	(*data)[service][key] = node
}

// toNode round-trips a value through YAML to get a Node, which is the only way
// to build one that re-marshals identically.
func toNode(v any) (yaml.Node, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return yaml.Node{}, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return yaml.Node{}, err
	}
	// Unmarshal yields a document node wrapping the real one.
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		return *doc.Content[0], nil
	}
	return doc, nil
}

// Save writes every file that changed. It is safe to call when nothing has.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.memoryOnly || len(s.dirty) == 0 {
		return nil
	}

	var errs []error
	labels := make([]string, 0, len(s.dirty))
	for label := range s.dirty {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	for _, label := range labels {
		var err error
		if label == globalKey {
			err = writeYAML(filepath.Join(s.dir, "config.yaml"),
				"# devtun global settings. Safe to edit by hand.", s.global)
		} else {
			err = writeYAML(s.hostPath(label),
				"# devtun settings for "+label+". Safe to edit by hand.", s.hosts[label])
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		delete(s.dirty, label)
	}
	return errors.Join(errs...)
}

// writeYAML writes atomically: a temporary file in the same directory, then a
// rename. A settings file half-written because a laptop lid closed is worse
// than one that is out of date.
func writeYAML(path, header string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	body, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	content := append([]byte(header+"\n"), body...)

	temp, err := os.CreateTemp(filepath.Dir(path), ".devtun-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	name := temp.Name()
	// A no-op once the rename below has succeeded.
	defer func() { _ = os.Remove(name) }()

	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	// 0600 because a host file can carry policy that names vaults and hosts.
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}

// HostPath is where a host's settings file lives, for a command that wants to
// tell the user which file to edit.
func (s *Store) HostPath(label string) string {
	if s.memoryOnly {
		return ""
	}
	return s.hostPath(label)
}

// Hosts lists the hosts that have a file on disk, sorted.
func (s *Store) Hosts() []string {
	if s.memoryOnly {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "hosts"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".yaml"); ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
