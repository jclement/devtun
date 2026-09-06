package tunnels

import (
	"fmt"

	"github.com/jclement/devtun/internal/tunnels/probe"
)

// RemoteBind selects which remote bind addresses are interesting.
type RemoteBind string

const (
	// BindAny forwards a service regardless of what it is bound to.
	BindAny RemoteBind = "any"
	// BindLoopback forwards only services bound exclusively to loopback:
	// exactly the ones no firewall change could make reachable.
	BindLoopback RemoteBind = "loopback"
)

// ParseRemoteBind validates a --remote-bind value.
func ParseRemoteBind(s string) (RemoteBind, error) {
	switch RemoteBind(s) {
	case BindAny:
		return BindAny, nil
	case BindLoopback:
		return BindLoopback, nil
	}
	return "", fmt.Errorf("invalid --remote-bind %q (want \"any\" or \"loopback\")", s)
}

// Mode is the user's standing decision for one remote port, and the only
// per-port decision there is. It is remembered per host between runs.
type Mode string

const (
	// ModeAuto follows the policy: forward anything that clears the port
	// window and the bind filter. It is the zero value, so a port nobody has
	// touched behaves the same as one set to auto explicitly.
	ModeAuto Mode = "auto"
	// ModeOn forwards even when a filter would leave the service out.
	ModeOn Mode = "on"
	// ModeHidden never forwards, and takes the row off the table too. It is
	// how the user says "yes, postgres is running, stop telling me".
	ModeHidden Mode = "hidden"
)

// ParseMode validates a stored mode, defaulting to auto.
func ParseMode(s string) Mode {
	switch Mode(s) {
	case ModeOn:
		return ModeOn
	case ModeHidden:
		return ModeHidden
	default:
		return ModeAuto
	}
}

// Next cycles auto → on → hidden → auto.
func (m Mode) Next() Mode {
	switch ParseMode(string(m)) {
	case ModeOn:
		return ModeHidden
	case ModeHidden:
		return ModeAuto
	default:
		return ModeOn
	}
}

// Policy decides which remote services devtun forwards.
//
// Unlike autotun, which snapshotted what was already listening at connect time
// and refused to forward it, everything at or above MinPort is fair game. A
// one-shot session can reasonably call whatever was up before it arrived
// "furniture"; devtun reattaches to the same box every day, so that rule makes
// a service invisible for no reason other than that it started five minutes
// before you did, and shows you a different board every time you reconnect.
// The user hides what they do not want — see Mode — and that is remembered.
type Policy struct {
	MinPort    int
	MaxPort    int
	Include    PortSet
	Exclude    PortSet
	RemoteBind RemoteBind
	// Paused suspends automatic forwarding without discarding state.
	Paused bool
}

// DefaultPolicy is the policy applied when no flags are given. The 1024 floor
// is the line above which a port can be bound without root, which is a good
// proxy for "something a person started" versus "something the box runs".
func DefaultPolicy() Policy {
	return Policy{
		MinPort:    1024,
		MaxPort:    65535,
		RemoteBind: BindAny,
	}
}

// Skip explains why a service is not forwarded. An empty Skip means "forward".
type Skip string

const (
	SkipNone       Skip = ""
	SkipBelowMin   Skip = "below --min-port"
	SkipAboveMax   Skip = "above --max-port"
	SkipExcluded   Skip = "excluded"
	SkipNotInclude Skip = "not in --include"
	SkipNotLoop    Skip = "not loopback-only"
	SkipPaused     Skip = "paused"
	// SkipHidden is a standing user decision, not a policy outcome.
	SkipHidden Skip = "hidden"
)

// Filtered reports whether a skip reason means the service was ruled out by
// explicit configuration, rather than by a rule the user might want to
// override from the table.
//
// Filtered services are not shown at all: if you set --min-port 1024, sshd on
// 22 is not something you were deciding about, it is something you already
// excluded, and listing it is noise. A paused service stays visible, because
// pausing is temporary and the row is what you unpause.
//
// Hiding is deliberately not in here. It filters the row too, but through the
// "show hidden" view preference rather than unconditionally — otherwise there
// would be no way to unhide anything.
func (s Skip) Filtered() bool {
	switch s {
	case SkipBelowMin, SkipAboveMax, SkipExcluded, SkipNotInclude, SkipNotLoop:
		return true
	}
	return false
}

// Eval decides whether svc should be forwarded.
//
// An explicit --include entry overrides the min/max window and the bind
// filter: naming a port is an unambiguous request for it. --exclude beats
// --include, because otherwise there is no way to punch a hole in a range.
func (p Policy) Eval(svc probe.Service) Skip {
	if p.Exclude.Contains(svc.Port) {
		return SkipExcluded
	}
	explicit := p.Include.Contains(svc.Port)
	if !explicit {
		if !p.Include.Empty() {
			return SkipNotInclude
		}
		if svc.Port < p.MinPort {
			return SkipBelowMin
		}
		if svc.Port > p.MaxPort {
			return SkipAboveMax
		}
		if p.RemoteBind == BindLoopback && !svc.LoopbackOnly() {
			return SkipNotLoop
		}
	}
	if p.Paused {
		return SkipPaused
	}
	return SkipNone
}
