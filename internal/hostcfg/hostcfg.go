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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// Prompt is how approvals are asked for: auto, tui, dialog or deny. It is
	// here because it is a property of the machine you sit at — a desktop with
	// zenity installed, a laptop where devtun always runs in a window behind
	// the browser — and re-typing --prompt dialog every time is how a setting
	// that matters gets left off.
	Prompt string `yaml:"prompt,omitempty"`
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
	Services map[string]ServiceState `yaml:"services,omitempty"`
	// Prompt overrides the global approval interface for this host. A box you
	// only ever touch from a terminal and one whose secrets you want a dialog
	// in front of are different situations, and this is where they differ.
	Prompt string                          `yaml:"prompt,omitempty"`
	Data   map[string]map[string]yaml.Node `yaml:",inline"`
}

// Store holds the global file and every host file that has been opened.
//
// A malformed or missing file degrades to an empty configuration rather than an
// error. Refusing to start because a settings file has a stray tab in it would
// be the wrong trade for a tool whose job is to get you connected.
//
// Two promises shape everything below, and both used to be broken.
//
// The first is that a file you edit by hand while devtun runs keeps your edit.
// The store used to hold the copy it read at startup and write *that* back,
// whole, the next time anything changed — so naming a port or answering a
// prompt "always" quietly erased a deny rule typed in five minutes earlier,
// comments and all, in the file whose header said it was safe to edit. Now
// every write is a transaction against the file as it is on disk: read it,
// change the one key being written, write it back. Everything else in the file,
// comments included, comes through untouched, and a second devtun writing the
// same file is serialised behind a lock file rather than racing it.
//
// The second is that an edit is noticed. Reads check the file's size and
// modification time and re-read it when either moved, so a rule added by hand
// takes effect on the next request rather than the next restart.
type Store struct {
	dir string

	mu     sync.Mutex
	global *file
	hosts  map[string]*file
	// revision counts changes to anything loaded, whether devtun wrote them or
	// noticed somebody else had. It is how a screen learns that what it is
	// showing is stale without diffing the whole configuration twice a second.
	revision uint64
	// memoryOnly is set when the config directory could not be located, so
	// everything still works for this run and nothing is written.
	memoryOnly bool
}

// file is one YAML file as last read or written.
type file struct {
	path string
	// doc is the parsed document. It is kept as a node tree, not a struct,
	// because a node tree remembers comments and layout and a struct does not —
	// and writing back a struct is precisely how hand edits were lost.
	doc *yaml.Node
	// stamp is the size and modification time doc was read at, so a read can
	// tell cheaply whether somebody else has changed the file since.
	stamp stamp
	// err is why the file on disk could not be used, nil when it could.
	//
	// A malformed file reads as its last good contents (empty, if there never
	// were any) so devtun still starts — but "empty" is a dangerous answer for
	// a file that may have contained deny rules, so the error is kept and Err()
	// lets a caller that is about to make a security decision refuse instead.
	err error
}

// stamp identifies one version of a file on disk well enough to notice an
// edit. It is not a content hash: an editor that rewrote identical bytes
// within the same second would go unnoticed, and nothing is lost if it does.
type stamp struct {
	exists bool
	size   int64
	mod    int64
}

func stampOf(info os.FileInfo) stamp {
	return stamp{exists: true, size: info.Size(), mod: info.ModTime().UnixNano()}
}

// Open loads the global file from dir. Host files are loaded lazily.
func Open(dir string) *Store {
	s := &Store{
		dir:        dir,
		hosts:      make(map[string]*file),
		memoryOnly: dir == "",
	}
	s.global = &file{doc: emptyDoc()}
	if dir != "" {
		s.global.path = filepath.Join(dir, "config.yaml")
		_ = s.refresh(s.global)
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

// LoadHost reads a host's file now rather than on first use.
//
// Host files load lazily, and Err() can only report what has been read — so a
// caller that checks Err() before touching a host is checking the global file
// and nothing else. A malformed hosts/bedev.yaml then reads as an empty one,
// its deny rules and hide ranges silently gone, and devtun carries on with
// wider access than the file asked for. That is precisely the failure Err()
// exists to prevent, arriving through the door Err() was not watching.
//
// Call this for the host you are about to act on, then Err().
func (s *Store) LoadHost(label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.host(label)
}

// Err reports any loaded configuration file that cannot be used as it stands
// on disk: one that will not parse, and one that cannot be read at all.
//
// Reading a broken file as empty is the right default for presentation
// settings: refusing to start because a sort order has a stray tab in it would
// be absurd. It is the wrong default for policy. A file that was meant to say
// "never this vault from this box" and instead says nothing has failed open,
// and silence is exactly how nobody notices. Callers about to act on rules ask
// here first and refuse rather than proceed on a partial policy.
//
// It reflects the files as they are now, not as they were at startup: a file
// broken by a hand edit while devtun runs is reported, and one that has been
// fixed stops being.
func (s *Store) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	errs := []error{s.refresh(s.global)}
	labels := make([]string, 0, len(s.hosts))
	for label := range s.hosts {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		errs = append(errs, s.refresh(s.hosts[label]))
	}
	return errors.Join(errs...)
}

// HostErr is Err for one host: its own file and the global one, which is
// everything a decision about that host reads.
func (s *Store) HostErr(label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(s.refresh(s.global), s.refresh(s.host(label)))
}

// Revision changes whenever anything this store has loaded changes, whether
// devtun wrote it or somebody edited the file. It only ever increases.
func (s *Store) Revision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refresh(s.global)
	for _, f := range s.hosts {
		_ = s.refresh(f)
	}
	return s.revision
}

// Global returns a copy of the global configuration.
func (s *Store) Global() Global {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.globalDoc()
}

// Path returns the directory being used, empty for a memory-only store.
func (s *Store) Path() string {
	if s.memoryOnly {
		return ""
	}
	return s.dir
}

// host returns the loaded host file, reading it from disk on first use and
// again whenever it has changed. The caller must hold s.mu.
func (s *Store) host(label string) *file {
	f, ok := s.hosts[label]
	if !ok {
		f = &file{doc: emptyDoc()}
		if !s.memoryOnly {
			f.path = s.hostPath(label)
		}
		s.hosts[label] = f
	}
	_ = s.refresh(f)
	return f
}

// globalDoc decodes the global file. The caller must hold s.mu.
func (s *Store) globalDoc() Global {
	_ = s.refresh(s.global)
	var g Global
	// The document parsed once already, so the only way this fails is a value
	// of the wrong shape — a `hide:` that is a map, say. That reads as unset
	// rather than taking the whole file down with it.
	_ = s.global.doc.Decode(&g)
	return g
}

// hostDoc decodes one host's file. The caller must hold s.mu.
func (s *Store) hostDoc(label string) Host {
	var h Host
	_ = s.host(label).doc.Decode(&h)
	return h
}

// refresh re-reads f if the file on disk is not the version it holds, and
// reports why the file on disk cannot be used, if it cannot. The caller must
// hold s.mu.
//
// Only a file that does not exist is an empty file. Anything else that stops
// it being read — a permission, an I/O error, a directory where the file
// should be — is an error, because "could not read the deny rules" and "there
// are no deny rules" are opposite answers and only one of them is safe to act
// on as if it were the other.
func (s *Store) refresh(f *file) error {
	if f.path == "" {
		return nil
	}
	info, err := os.Stat(f.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if f.stamp.exists || f.err != nil {
			f.doc, f.stamp, f.err = emptyDoc(), stamp{}, nil
			s.revision++
		}
		return nil
	case err != nil:
		return s.fail(f, stamp{}, fmt.Errorf("%s: %w", f.path, err))
	case info.IsDir():
		return s.fail(f, stampOf(info), fmt.Errorf("%s: is a directory, not a file", f.path))
	}
	now := stampOf(info)
	if now == f.stamp && f.err == nil {
		return nil
	}
	if now == f.stamp {
		return f.err
	}
	doc, err := readDoc(f.path)
	if err != nil {
		return s.fail(f, now, err)
	}
	f.doc, f.stamp, f.err = doc, now, nil
	s.revision++
	return nil
}

// fail records a file as unusable, keeping its last good contents for the
// readers that would rather have something than nothing. The caller holds s.mu.
func (s *Store) fail(f *file, at stamp, err error) error {
	if f.err == nil || f.err.Error() != err.Error() {
		s.revision++
	}
	f.stamp, f.err = at, err
	return err
}

// readDoc reads and parses one file. A missing file is an empty document.
func readDoc(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return emptyDoc(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind == 0 {
		return emptyDoc(), nil // an empty file, or one that is only comments
	}
	if root := docRoot(&doc); root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected a map of settings at the top level", path)
	}
	return &doc, nil
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

	if state, ok := s.hostDoc(label).Services[serviceID]; ok && state.Enabled != nil {
		return *state.Enabled
	}
	if state, ok := s.globalDoc().Services[serviceID]; ok && state.Enabled != nil {
		return *state.Enabled
	}
	return fallback
}

// Prompt is how approvals are asked for on a host: the host file wins, then
// the global file, then the fallback the caller was going to use anyway.
//
// An empty string at either level means "not configured", which is why this
// cannot be a bool or an enum with a zero value: unset and "auto" have to stay
// distinguishable so a host can be left alone by the global setting.
func (s *Store) Prompt(label, fallback string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if v := strings.TrimSpace(s.hostDoc(label).Prompt); v != "" {
		return v
	}
	if v := strings.TrimSpace(s.globalDoc().Prompt); v != "" {
		return v
	}
	return fallback
}

// SetEnabled records whether a service runs on a host.
//
// Durable now, for the same reason Section.Set is: a decision the interface
// says is remembered has to be remembered across a kill.
func (s *Store) SetEnabled(label, serviceID string, enabled bool) {
	_ = s.SetSetting(label, SectionServices, serviceID, strconv.FormatBool(enabled))
}

// Where the Config tab addresses a setting: a section and a key, read and
// written at exactly one level.
//
// An empty section is the top of the file, where the settings are named struct
// fields rather than free-form documents — hence the constants, since there is
// nothing to look them up in. SectionServices is the `services:` map both files
// carry. Anything else is a service's own section.
const (
	SectionServices = "services"

	KeyPrompt = "prompt"
	KeySetup  = "setup"
	KeyHide   = "hide"
)

// Setting reads one value at exactly one level: the host file when label names
// a host, the global file when it is empty. A service's on/off state reads back
// as "true" or "false" under SectionServices.
//
// Empty means that file does not set it, which is a third answer the resolving
// readers above deliberately collapse. An interface showing the settings cannot
// afford to: `auto` without saying whether that is this host's answer or the
// fall-through is a value nobody can act on.
func (s *Store) Setting(label, section, key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch section {
	case "":
		return s.topSetting(label, key)
	case SectionServices:
		states := s.globalDoc().Services
		if label != "" {
			states = s.hostDoc(label).Services
		}
		if state, ok := states[key]; ok && state.Enabled != nil {
			return strconv.FormatBool(*state.Enabled)
		}
		return ""
	}

	node := s.lookup(label, section, key)
	if node == nil {
		return ""
	}
	return scalarOf(*node)
}

// SetSetting records a value at one level, on disk, before it returns.
//
// An empty value removes the setting rather than writing a blank one: clearing
// a host's answer has to fall back to the global file, not pin whatever it
// happened to be showing at the time.
func (s *Store) SetSetting(label, section, key, value string) error {
	value = strings.TrimSpace(value)

	var path []string
	var node *yaml.Node
	switch section {
	case "":
		if label != "" && key != KeyPrompt {
			return fmt.Errorf("%s is a global setting, not a per-host one", key)
		}
		switch key {
		case KeyPrompt, KeySetup:
			node = scalarNode(value)
		case KeyHide:
			if value != "" {
				n, err := toNode(PortSpec{value})
				if err != nil {
					return err
				}
				node = &n
			}
		default:
			return fmt.Errorf("unknown setting %q", key)
		}
		path = []string{key}
	case SectionServices:
		if value != "" {
			enabled, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("%s: %q is not on or off", key, value)
			}
			node = mapNode("enabled", &yaml.Node{
				Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(enabled),
			})
		}
		path = []string{SectionServices, key}
	default:
		if value != "" {
			n, err := toNode(value)
			if err != nil {
				return fmt.Errorf("encoding %s.%s: %w", section, key, err)
			}
			node = &n
		}
		path = []string{section, key}
	}
	if value == "" {
		node = nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transact(s.fileFor(label), func(root *yaml.Node) error {
		setPath(root, path, node)
		return nil
	})
}

// topSetting reads a named field of one of the two documents. The host file has
// only one of them; asking it for a global-only setting is answered with "not
// set here" rather than an error, because the caller is a list of rows and the
// row is about to say which level it lives at anyway.
func (s *Store) topSetting(label, key string) string {
	if label != "" {
		if key == KeyPrompt {
			return strings.TrimSpace(s.hostDoc(label).Prompt)
		}
		return ""
	}
	g := s.globalDoc()
	switch key {
	case KeyPrompt:
		return strings.TrimSpace(g.Prompt)
	case KeySetup:
		return strings.TrimSpace(g.Setup)
	case KeyHide:
		return g.Hide.Spec()
	}
	return ""
}

// fileFor is the host's file, or the global one for an empty label. The caller
// holds s.mu.
func (s *Store) fileFor(label string) *file {
	if label == "" {
		_ = s.refresh(s.global)
		return s.global
	}
	return s.host(label)
}

// lookup finds section.key in one file, nil when it is not there. The caller
// holds s.mu.
func (s *Store) lookup(label, section, key string) *yaml.Node {
	return getPath(docRoot(s.fileFor(label).doc), section, key)
}

// scalarOf renders a stored document as the single line a settings screen can
// edit: a scalar as itself, a sequence joined with commas — which is the syntax
// the port lists already accept back, so a list somebody hand-wrote reads out
// as something they can edit and hand in again.
func scalarOf(node yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value
	case yaml.SequenceNode:
		parts := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			parts = append(parts, item.Value)
		}
		return strings.Join(parts, ",")
	}
	return ""
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
	return c.decode(c.store.lookup(c.label, c.service, key), key, "for "+c.label, v)
}

// GetGlobal reads only the global file's section, whichever view this is. It is
// the other half of GetLocal: a caller that keeps the two levels apart — the
// policy store, which labels every rule with where it came from — reads each
// with its own method rather than inferring the level from a fall-through.
func (c *Section) GetGlobal(key string, v any) (bool, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.decode(c.store.lookup("", c.service, key), key, "from the global config", v)
}

// Get decodes the document stored under key into v, reporting whether one was
// found. A host document wins over a global one of the same name.
func (c *Section) Get(key string, v any) (bool, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()

	if c.label != "" {
		if node := c.store.lookup(c.label, c.service, key); node != nil {
			return c.decode(node, key, "for "+c.label, v)
		}
	}
	return c.decode(c.store.lookup("", c.service, key), key, "from the global config", v)
}

func (c *Section) decode(node *yaml.Node, key, where string, v any) (bool, error) {
	if node == nil {
		return false, nil
	}
	if err := node.Decode(v); err != nil {
		return false, fmt.Errorf("reading %s.%s %s: %w", c.service, key, where, err)
	}
	return true, nil
}

// Err reports why either file this section reads — the host's, and the global
// one — cannot be used as it stands on disk. A caller deciding something on the
// strength of what it read checks this, because a broken file reads as its last
// good contents and those may be missing what the person just wrote.
func (c *Section) Err() error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.label == "" {
		return c.store.refresh(c.store.global)
	}
	return errors.Join(c.store.refresh(c.store.global), c.store.refresh(c.store.host(c.label)))
}

// Revision is the store's: it changes whenever anything loaded changes.
func (c *Section) Revision() uint64 { return c.store.Revision() }

// Set stores v under key, on disk, before it returns.
//
// This used to mark the file dirty and leave it, on the theory that a busy
// tunnel table would otherwise rewrite YAML every couple of seconds. That does
// not happen — every caller is a human action: hiding a port, naming one,
// answering a prompt, toggling a service. What did happen is that a `Never`
// written at 10am was still only in memory at 6pm, and a session killed rather
// than quit lost it. A deny rule the user believes is protecting them has to
// survive `kill -9`, a flat battery, and a laptop that never wakes up; "we
// would have written it on the way out" is not a promise worth making about a
// refusal.
func (c *Section) Set(key string, v any) error {
	node, err := toNode(v)
	if err != nil {
		return fmt.Errorf("encoding %s.%s: %w", c.service, key, err)
	}
	return c.EditNode(key, func(*yaml.Node) (*yaml.Node, error) { return &node, nil })
}

// EditNode changes one key as a transaction against the file on disk.
//
// edit is handed the key's current value as it is in the file right now — not
// as it was when devtun started, and not as this process last wrote it — or nil
// when the key is absent. It returns the replacement, or nil to remove the key.
// Nothing else in the file is touched, so a rule somebody typed into the same
// list a moment ago is still there for edit to see, and a comment beside it
// survives the write.
//
// If the file cannot be read or will not parse, nothing is written: a
// transaction against a file we cannot read would replace it with whatever we
// last understood, which is the clobbering this exists to prevent.
func (c *Section) EditNode(key string, edit func(current *yaml.Node) (*yaml.Node, error)) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.store.transact(c.store.fileFor(c.label), func(root *yaml.Node) error {
		current := getPath(root, c.service, key)
		if current != nil {
			copied := *current
			current = &copied
		}
		next, err := edit(current)
		if err != nil {
			return err
		}
		setPath(root, []string{c.service, key}, next)
		return nil
	})
}

// ErrUnreadable is what a write says when the file it would change cannot be
// read or parsed: nothing was written.
var ErrUnreadable = errors.New("the file cannot be read, so it was not changed")

// transact applies change to f's file as it is on disk and writes the result,
// all under the lock file. The caller holds s.mu.
func (s *Store) transact(f *file, change func(root *yaml.Node) error) error {
	if s.memoryOnly || f.path == "" {
		if err := change(docRoot(f.doc)); err != nil {
			return err
		}
		s.revision++
		return nil
	}

	unlock, err := lockDir(s.dir)
	if err != nil {
		return err
	}
	defer unlock()

	// The file as it is now, not as we last saw it. That is the whole fix.
	doc, err := readDoc(f.path)
	if err != nil {
		_ = s.fail(f, stamp{}, err)
		return fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if err := change(docRoot(doc)); err != nil {
		return err
	}
	if doc.HeadComment == "" && len(doc.Content) == 1 && doc.Content[0].HeadComment == "" {
		doc.HeadComment = s.header(f)
	}
	if err := writeDoc(f.path, doc); err != nil {
		return err
	}
	f.doc, f.err = doc, nil
	if info, err := os.Stat(f.path); err == nil {
		f.stamp = stampOf(info)
	}
	s.revision++
	return nil
}

// header is the comment a file devtun creates starts with.
func (s *Store) header(f *file) string {
	if f == s.global {
		return "# devtun global settings. Safe to edit by hand, even while devtun runs."
	}
	label := strings.TrimSuffix(filepath.Base(f.path), ".yaml")
	return "# devtun settings for " + label + ". Safe to edit by hand, even while devtun runs."
}

// Save is kept for callers written when writes were deferred. Every write now
// reaches disk before it returns, so there is never anything left to save.
func (s *Store) Save() error { return nil }

// lockDir takes the directory's lock file, so two devtun processes — two
// sessions for different hosts share the global file — apply their
// transactions one after the other rather than each writing back a file that
// is missing the other's change.
//
// It is a lock file created exclusively rather than flock, because devtun runs
// on Windows too and an exclusive create means the same thing everywhere. A
// process killed while holding it leaves the file behind, so one older than
// lockStale is taken to be abandoned: every holder keeps it for the length of
// one small write, and a write that has taken ten seconds is not still going.
func lockDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	path := filepath.Join(dir, ".devtun.lock")
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("locking %s: %w", dir, err)
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > lockStale {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another devtun has held %s for %s; not writing over it", path, lockWait)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

const (
	lockWait  = 5 * time.Second
	lockStale = 10 * time.Second
)

// emptyDoc is a document holding an empty map: what a missing file reads as.
func emptyDoc() *yaml.Node {
	return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
}

// docRoot is the top-level map of a document, made if it is not there.
func docRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind != yaml.DocumentNode {
		return doc
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	return doc.Content[0]
}

// getPath walks maps by key, nil when any step is missing.
func getPath(node *yaml.Node, keys ...string) *yaml.Node {
	for _, key := range keys {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
			}
		}
		node = next
	}
	return node
}

// setPath puts value at the end of a chain of map keys, making the maps on the
// way, or removes the last key when value is nil — and then any map that
// removing it left empty, so clearing a setting does not leave `services: {}`
// behind for somebody to wonder about. A key that already exists keeps its
// place in the file and the comments around it.
func setPath(node *yaml.Node, keys []string, value *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	key := keys[0]
	at := -1
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			at = i
		}
	}

	if len(keys) == 1 {
		switch {
		case value == nil && at >= 0:
			node.Content = append(node.Content[:at], node.Content[at+2:]...)
		case value != nil && at >= 0:
			value.HeadComment = firstNonEmpty(value.HeadComment, node.Content[at+1].HeadComment)
			value.LineComment = firstNonEmpty(value.LineComment, node.Content[at+1].LineComment)
			node.Content[at+1] = value
		case value != nil:
			node.Content = append(node.Content, scalarNode(key), value)
		}
		return
	}

	if at < 0 {
		if value == nil {
			return
		}
		node.Content = append(node.Content, scalarNode(key), &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
		at = len(node.Content) - 2
	}
	child := node.Content[at+1]
	if child.Kind != yaml.MappingNode {
		if value == nil {
			return
		}
		// A scalar where a section belongs — `1password: off` — is replaced
		// rather than written through, which would be impossible.
		child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		node.Content[at+1] = child
	}
	setPath(child, keys[1:], value)
	if value == nil && len(child.Content) == 0 {
		node.Content = append(node.Content[:at], node.Content[at+2:]...)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// mapNode builds a one-key map.
func mapNode(key string, value *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{scalarNode(key), value}}
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

// writeDoc writes atomically: a temporary file in the same directory, then a
// rename. A settings file half-written because a laptop lid closed is worse
// than one that is out of date.
func writeDoc(path string, doc *yaml.Node) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	content, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}

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
