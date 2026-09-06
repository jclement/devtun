package onepassword

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
)

// fakeHost is a host with no SSH connection behind it. Everything the
// authorisation pipeline uses — the label decisions are keyed to, the event
// sink, the config document — is real; everything that would touch a network
// refuses, so a test that starts using one fails loudly rather than hanging.
type fakeHost struct {
	label  string
	facts  service.Facts
	events *recorder
	config *fakeConfig
}

func newFakeHost(label string) *fakeHost {
	return &fakeHost{
		label:  label,
		facts:  service.Facts{User: "jsc", Hostname: label, OS: "linux", Arch: "amd64", Tools: map[string]string{}},
		events: &recorder{},
		config: newFakeConfig(),
	}
}

func (h *fakeHost) Label() string        { return h.label }
func (h *fakeHost) Facts() service.Facts { return h.facts }
func (h *fakeHost) Events() event.Sink   { return h.events }
func (h *fakeHost) Config() service.Config {
	return h.config
}

func (h *fakeHost) Run(context.Context, string, io.Writer) error { return errNoRemote }
func (h *fakeHost) Output(context.Context, string) (string, error) {
	return "", errNoRemote
}
func (h *fakeHost) Upload(context.Context, string, string, os.FileMode) error { return errNoRemote }
func (h *fakeHost) DialTCP(context.Context, string) (net.Conn, error)         { return nil, errNoRemote }
func (h *fakeHost) ShimPath() string                                          { return "/home/jsc/.devtun/bin/devtun-shim" }
func (h *fakeHost) SocketPath() string                                        { return "/run/user/1000/devtun.sock" }

// errNoRemote is what the fake host answers with. This service is meant to need
// nothing on the remote box, so reaching for it in a test is the bug.
var errNoRemote = errors.New("the 1Password service should not need anything from the remote box")

// fakeConfig is the service's slice of the host config file, kept as marshalled
// documents so a round trip through YAML is exercised the way the real one is.
type fakeConfig struct {
	mu      sync.Mutex
	docs    map[string][]byte
	getErr  error
	setErr  error
	written int
}

func newFakeConfig() *fakeConfig { return &fakeConfig{docs: make(map[string][]byte)} }

// GetLocal behaves as Get here: these fakes hold no shared layer for a local
// read to differ from.
func (c *fakeConfig) GetLocal(key string, v any) (bool, error) { return c.Get(key, v) }

func (c *fakeConfig) Get(key string, v any) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getErr != nil {
		return false, c.getErr
	}
	data, ok := c.docs[key]
	if !ok {
		return false, nil
	}
	return true, yaml.Unmarshal(data, v)
}

func (c *fakeConfig) Set(key string, v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.setErr != nil {
		return c.setErr
	}
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	c.docs[key] = data
	c.written++
	return nil
}

// seed puts a document in place as if a previous session had written it.
func (c *fakeConfig) seed(t testingT, key string, v any) {
	t.Helper()
	if err := c.Set(key, v); err != nil {
		t.Fatalf("seeding %s: %v", key, err)
	}
	c.mu.Lock()
	c.written = 0
	c.mu.Unlock()
}

func (c *fakeConfig) writes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

// testingT is the slice of *testing.T the helpers here use.
type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

// recorder keeps every event, because what was reported about a decision is
// part of the decision: the security record is the point.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Emit(e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// kinds returns the Kind of every event, in order.
func (r *recorder) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	for i, e := range r.events {
		out[i] = e.Kind
	}
	return out
}

// all returns a copy of the recorded events.
func (r *recorder) all() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event.Event, len(r.events))
	copy(out, r.events)
	return out
}
