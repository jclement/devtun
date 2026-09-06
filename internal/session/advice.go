package session

import (
	"context"
	"strings"

	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// reportSetup works out whether the remote shell is missing anything, and
// either says so, offers to fix it, or fixes it — depending on --setup.
//
// The governing rule comes from opproxy: print nothing when nothing is wrong.
// A block of setup instructions on every single connection is one people stop
// reading, which is exactly when it matters that they read it.
func (s *Session) reportSetup(
	ctx context.Context, conn Conn, facts service.Facts,
	paths shim.RemotePaths, label string, advisors []service.Advisor, h service.Host,
) {
	plan := planRC(facts, paths.Bin)

	// Anything a service needs beyond the PATH line goes in the same block, so
	// a user ever sees one devtun block in their rc rather than one per
	// service. The SSH agent service is the first to use this: `ssh` finds its
	// agent through SSH_AUTH_SOCK and there is no binary to shadow, so it is
	// the one capability that cannot be delivered by PATH alone.
	for _, advisor := range advisors {
		for _, line := range advisor.SetupLines(h) {
			if !alreadySet(facts, line) {
				plan.Lines = append(plan.Lines, line)
			}
		}
	}

	// Nothing missing: say so once and stop. Printing a block of instructions
	// to somebody who has already followed them is how instructions stop being
	// read, which is exactly when it matters that they are.
	if onPath(facts.LoginPath, paths.Bin) {
		plan.Lines = plan.Lines[1:] // drop the PATH line, which is satisfied
	}
	if len(plan.Lines) == 0 {
		s.events.Emit(event.Event{
			Kind: "remote-ready", Class: event.Lifecycle, Level: event.Info,
			Text: label + " is ready",
		})
		return
	}
	plan = rebuildBlock(plan)

	switch s.opts.Setup {
	case SetupNever:
		s.adviseOnly(plan, label)
		return
	case SetupAuto:
		s.applyOrAdvise(ctx, conn, plan, label)
		return
	}

	// SetupAsk. A refusal is remembered: being asked the same question on
	// every reconnect is how a helpful offer becomes an irritation.
	state := s.setupState(label)
	if state.Asked && !state.Accepted {
		s.adviseOnly(plan, label)
		return
	}
	if s.opts.AskSetup == nil {
		s.adviseOnly(plan, label)
		return
	}

	plan = checkWritable(ctx, conn, plan)
	if !plan.Writable {
		s.adviseOnly(plan, label)
		return
	}

	accepted, err := s.opts.AskSetup(ctx, plan)
	if err != nil {
		// Only a refusal a human actually gave is worth remembering. Piping
		// devtun once — `devtun bedev | tee log` — puts the question to nobody,
		// and recording that as "asked and declined" would suppress the offer
		// permanently, including in the TUI where it could have been answered.
		s.adviseOnly(plan, label)
		return
	}
	if !accepted {
		s.saveSetupState(label, SetupState{Asked: true})
		s.adviseOnly(plan, label)
		return
	}
	s.saveSetupState(label, SetupState{Asked: true, Accepted: true})
	s.applyOrAdvise(ctx, conn, plan, label)
}

// SetupState remembers what the user said about editing this host's shell rc.
type SetupState struct {
	// Asked records that the question has been put; Accepted records the
	// answer. Both are needed: "not asked" and "asked and declined" call for
	// different behaviour on the next connection.
	Asked    bool `yaml:"asked,omitempty"`
	Accepted bool `yaml:"accepted,omitempty"`
}

func (s *Session) setupState(label string) SetupState {
	var state SetupState
	if _, err := s.opts.Config.Section(label, sessionSection).Get("setup", &state); err != nil {
		return SetupState{}
	}
	return state
}

func (s *Session) saveSetupState(label string, state SetupState) {
	// A failure here costs a repeated question, not correctness.
	_ = s.opts.Config.Section(label, sessionSection).Set("setup", state)
}

// applyOrAdvise makes the edit, falling back to advice when it cannot.
func (s *Session) applyOrAdvise(ctx context.Context, conn Conn, plan RCPlan, label string) {
	plan = checkWritable(ctx, conn, plan)
	if !plan.Writable {
		s.adviseOnly(plan, label)
		return
	}
	if err := applyRC(ctx, conn, plan); err != nil {
		s.events.Emit(event.Event{
			Kind: "setup-failed", Class: event.Lifecycle, Level: event.Warn,
			Text: err.Error(),
		})
		s.adviseOnly(plan, label)
		return
	}
	// Verify rather than assume. We already re-probe under the user's own
	// shells, so claiming success we have not seen would be a guess.
	s.events.Emit(event.Event{
		Kind: "setup-applied", Class: event.Lifecycle, Level: event.Info,
		Text:   "added devtun to " + plan.File + " — open a new shell on " + label + " for it to take effect",
		Fields: []any{"file", plan.File},
	})
}

// adviseOnly prints what is missing and why devtun is not doing it.
func (s *Session) adviseOnly(plan RCPlan, label string) {
	text := "add this to your shell on " + label + ": " + strings.Join(plan.Lines, "  ")
	if plan.Why != "" {
		text += " (" + plan.Why + ")"
	}
	s.events.Emit(event.Event{
		Kind: "setup-needed", Class: event.Lifecycle, Level: event.Warn,
		Text:   text,
		Fields: []any{"file", plan.File},
	})
}

// rebuildBlock refreshes the managed block after lines have been added, so the
// markers still wrap everything that is meant to be inside them.
func rebuildBlock(plan RCPlan) RCPlan {
	if plan.File == "" {
		return plan
	}
	plan.Block = strings.Join(append(
		[]string{setupMarkerStart},
		append(append([]string{}, plan.Lines...), setupMarkerEnd)...,
	), "\n")
	return plan
}

// alreadySet reports whether an advisor's export line is redundant because the
// user's shell already exports that variable with that value.
//
// The comparison is deliberately exact. A different value is not "already set"
// — it is somebody else's agent, or a stale path from a previous devtun — and
// silently accepting it would leave the user with a service that cannot work
// and no line saying why.
func alreadySet(facts service.Facts, line string) bool {
	name, value, ok := parseExport(line)
	if !ok {
		return false
	}
	return facts.EnvValue(name) == value
}

// parseExport pulls NAME and VALUE out of `export NAME="VALUE"`. It understands
// only the form devtun itself generates; anything else is treated as unknown
// and therefore still worth printing.
func parseExport(line string) (name, value string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(line), "export ")
	if !found {
		return "", "", false
	}
	name, value, found = strings.Cut(rest, "=")
	if !found {
		return "", "", false
	}
	value = strings.Trim(value, `"'`)
	if strings.Contains(value, "$") {
		// A value with a variable in it cannot be compared against what the
		// shell reported without expanding it, so do not pretend to.
		return "", "", false
	}
	return name, value, true
}

// onPath reports whether dir is already on the shell's PATH. This is why the
// facts probe asks the user's own login and interactive shells rather than the
// bare one `ssh host command` gets: a box configured perfectly for the person
// who logs into it otherwise looks unconfigured.
func onPath(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}
	for _, entry := range strings.Split(path, ":") {
		if strings.TrimRight(entry, "/") == strings.TrimRight(dir, "/") {
			return true
		}
	}
	return false
}
