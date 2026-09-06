package tunnels

import (
	"sync"

	"github.com/jclement/devtun/internal/service"
)

// Keys this service occupies in the host's config document. The service's
// slice is namespaced already, so these need only be unique among ourselves.
const (
	keyPorts = "ports"
	keyView  = "view"
)

// PortPrefs is what devtun remembers about one remote port between runs. It is
// deliberately a handful of scalars: the host file is meant to be readable and
// hand-editable, because it is the record of decisions you made in the UI.
type PortPrefs struct {
	// Label is a human-friendly name for the service, such as "frontend".
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// Scheme is "http" or "https"; empty means undetermined.
	Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	// Mode is auto, on or hidden; empty means auto.
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
	// Local is a preferred local port; zero means mirror the remote port.
	Local int `json:"local,omitempty" yaml:"local,omitempty"`
}

// IsZero reports whether the entry holds nothing worth persisting.
func (p PortPrefs) IsZero() bool {
	return p.Label == "" && p.Scheme == "" &&
		(p.Mode == "" || Mode(p.Mode) == ModeAuto) && p.Local == 0
}

// ViewPrefs is how a host's table is presented. These are display choices
// only: none of them forwards or stops forwarding anything.
type ViewPrefs struct {
	// ShowHidden lists the ports the user hid. Hiding is the only way to take
	// a row off the table, so this is the only way to put one back.
	ShowHidden bool
	// InactiveLast sinks rows with no tunnel below the ones that have them.
	InactiveLast bool
	// Sort names the ordering, e.g. "port" or "recent".
	Sort    string
	Reverse bool
}

// DefaultViewPrefs is how a host is presented before anyone changes anything.
func DefaultViewPrefs() ViewPrefs {
	return ViewPrefs{InactiveLast: true, Sort: "port"}
}

// viewDoc is the persisted shape of ViewPrefs. InactiveLast defaults to true,
// so it is a pointer: absent means "not configured", which is a different
// thing from "explicitly off" and only a pointer can tell them apart in a
// hand-edited file.
type viewDoc struct {
	ShowHidden   bool   `json:"show_hidden,omitempty" yaml:"show_hidden,omitempty"`
	Sort         string `json:"sort,omitempty" yaml:"sort,omitempty"`
	Reverse      bool   `json:"reverse,omitempty" yaml:"reverse,omitempty"`
	InactiveLast *bool  `json:"inactive_last,omitempty" yaml:"inactive_last,omitempty"`
}

// Store is the service's slice of the host's config file, read once on attach
// and written back through the Config seam as decisions are made.
//
// It is deliberately forgiving: an unreadable document is treated as empty
// rather than as a startup failure, because losing the memory of which port
// serves HTTPS should never stop you connecting.
type Store struct {
	cfg service.Config

	mu    sync.Mutex
	ports map[int]PortPrefs
	view  ViewPrefs
}

// NewStore loads what was remembered about this host. A nil Config yields a
// memory-only store, which is what the tests and a --no-config run want.
func NewStore(cfg service.Config) *Store {
	s := &Store{cfg: cfg, ports: map[int]PortPrefs{}, view: DefaultViewPrefs()}
	if cfg == nil {
		return s
	}

	ports := map[int]PortPrefs{}
	if ok, err := cfg.Get(keyPorts, &ports); ok && err == nil {
		s.ports = ports
	}

	var doc viewDoc
	if ok, err := cfg.Get(keyView, &doc); ok && err == nil {
		s.view.ShowHidden = doc.ShowHidden
		s.view.Reverse = doc.Reverse
		if doc.Sort != "" {
			s.view.Sort = doc.Sort
		}
		if doc.InactiveLast != nil {
			s.view.InactiveLast = *doc.InactiveLast
		}
	}
	return s
}

// Port returns the remembered settings for a remote port.
func (s *Store) Port(port int) PortPrefs {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ports[port]
}

// SetPort records settings for a remote port. An entry holding nothing is
// removed rather than persisted as clutter.
func (s *Store) SetPort(port int, p PortPrefs) {
	s.mu.Lock()
	if p.IsZero() {
		if _, existed := s.ports[port]; !existed {
			s.mu.Unlock()
			return
		}
		delete(s.ports, port)
	} else {
		if s.ports[port] == p {
			s.mu.Unlock()
			return
		}
		s.ports[port] = p
	}
	// Copy under the lock; Set may marshal on the caller's goroutine.
	snapshot := make(map[int]PortPrefs, len(s.ports))
	for k, v := range s.ports {
		snapshot[k] = v
	}
	cfg := s.cfg
	s.mu.Unlock()

	if cfg != nil {
		_ = cfg.Set(keyPorts, snapshot)
	}
}

// View returns the host's presentation settings.
func (s *Store) View() ViewPrefs {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view
}

// SetView records the host's presentation settings.
func (s *Store) SetView(p ViewPrefs) {
	s.mu.Lock()
	if s.view == p {
		s.mu.Unlock()
		return
	}
	s.view = p
	doc := viewDoc{ShowHidden: p.ShowHidden, Reverse: p.Reverse}
	if p.Sort != DefaultViewPrefs().Sort {
		doc.Sort = p.Sort
	}
	if !p.InactiveLast {
		off := false
		doc.InactiveLast = &off
	}
	cfg := s.cfg
	s.mu.Unlock()

	if cfg != nil {
		_ = cfg.Set(keyView, doc)
	}
}
