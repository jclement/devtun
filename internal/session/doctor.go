package session

import (
	"context"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/jclement/devtun/internal/doctor"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/service"
	"github.com/jclement/devtun/internal/shim"
)

// Diagnose connects once and reports what is and is not in order, changing
// nothing.
//
// It is deliberately the same path a real session takes — the same connector,
// the same one-shot probe, the same Probe call on each service — up to the
// point where anything would be written. A doctor that asked its own questions
// would drift from the thing it is meant to be checking, and the failure it
// missed would be exactly the one that only happens on a real connection.
//
// Nothing here uploads, edits a shell rc, or downloads a helper. "Could this be
// installed?" is answered by looking at where a helper would come from, because
// a diagnostic command that changes the machine is one people stop running on
// the machine that matters.
func (s *Session) Diagnose(ctx context.Context) *doctor.Section {
	label := s.opts.Connector.Label()
	out := &doctor.Section{Title: label}

	conn, err := s.opts.Connector.Connect(ctx)
	if err != nil {
		out.Fail("ssh", "cannot connect: "+err.Error(),
			"check `ssh "+label+"` works first — devtun reads the same ssh_config")
		return out
	}
	defer func() { _ = conn.Close() }()

	facts, err := probeFacts(ctx, conn)
	if err != nil {
		out.Fail("probe", "connected, but the box would not answer: "+err.Error(),
			"devtun needs a POSIX shell there; check the account's login shell")
		return out
	}
	out.OK("ssh", fmt.Sprintf("connected to %s@%s (%s/%s)", facts.User, facts.Hostname, facts.OS, facts.Arch))

	paths := shim.PathsFor(facts.Home, facts.RuntimeDir)
	s.diagnoseShell(out, facts)
	s.diagnoseHelper(ctx, out, conn, facts, paths)
	s.diagnoseServices(ctx, out, conn, facts, paths, label)
	s.diagnoseSetup(ctx, out, conn, facts, paths)
	return out
}

// diagnoseShell reports the login shell, because every other answer depends on
// it: the PATH devtun reads, the rc file it would edit, and whether the probe
// meant anything at all.
func (s *Session) diagnoseShell(out *doctor.Section, facts service.Facts) {
	if facts.Shell == "" {
		out.Warn("shell", "the account has no $SHELL",
			"devtun will fall back to /bin/sh and cannot offer to edit an rc file")
		return
	}
	// An empty bin directory: only the rc file's location is wanted here, and
	// planRC works that out from the shell alone.
	plan := planRC(facts, "")
	if plan.File == "" {
		out.Warn("shell", facts.Shell+" — not one devtun knows how to edit",
			"the setup lines below have to go in by hand")
		return
	}
	out.OK("shell", facts.Shell+" · "+plan.File)
}

// diagnoseHelper answers the two questions about the remote binary: is one
// there, and if not, is there a way to get one for that platform.
//
// The second question is the one worth asking in advance. A helper that cannot
// be obtained fails quietly at the worst moment — tunnels keep working, so
// devtun looks fine, while 1Password and the agent never start.
func (s *Session) diagnoseHelper(
	ctx context.Context, out *doctor.Section, conn Conn, facts service.Facts, paths shim.RemotePaths,
) {
	syncer := &shimSyncer{Binary: s.opts.ShimBinary, Version: s.opts.Version, Fetch: s.opts.FetchShim}
	want := s.opts.Version

	if current, ok := syncer.remoteVersion(ctx, conn, paths.Binary); ok {
		if current == want {
			out.OK("helper", fmt.Sprintf("%s installed at %s", current, paths.Binary))
			return
		}
		out.Warn("helper", fmt.Sprintf("%s installed, this devtun is %s", current, want),
			"it is replaced automatically on the next connection")
		return
	}

	source, err := s.helperSource(facts)
	if err != nil {
		out.Fail("helper", "not installed, and there is no binary for "+facts.OS+"/"+facts.Arch,
			err.Error())
		return
	}
	out.Warn("helper", "not installed yet", "it is installed automatically on the next connection, from "+source)
}

// helperSource says where a helper for the remote's platform would come from,
// without fetching one. The order mirrors localBinary exactly, because a doctor
// that reasons differently from the thing it checks is worse than no doctor.
func (s *Session) helperSource(facts service.Facts) (string, error) {
	if s.opts.ShimBinary != "" {
		return "--shim-binary " + s.opts.ShimBinary, nil
	}
	if candidate := path.Join("dist", fmt.Sprintf("devtun-%s-%s", facts.OS, facts.Arch)); fileExists(candidate) {
		return candidate, nil
	}
	if facts.OS == runtime.GOOS && facts.Arch == runtime.GOARCH {
		return "this devtun binary — the box is the same platform", nil
	}
	if s.opts.FetchShim == nil {
		return "", fmt.Errorf("build one with `mise run build:all`, or pass --shim-binary")
	}
	return "the " + s.opts.Version + " release", nil
}

// diagnoseServices asks every service the same question a session asks it, and
// reports the answer instead of acting on it.
func (s *Session) diagnoseServices(
	ctx context.Context, out *doctor.Section, conn Conn,
	facts service.Facts, paths shim.RemotePaths, label string,
) {
	for _, svc := range s.opts.Services {
		meta := svc.Meta()
		if !s.opts.Config.Enabled(label, meta.ID, true) {
			out.Off(meta.ID, "switched off for "+label)
			continue
		}
		h := &host{
			label: label,
			facts: facts,
			paths: paths,
			// event.Discard: doctor reports what it found in its own words,
			// and a service's running commentary interleaved with a checklist
			// would belong to neither.
			events: event.Discard,
			config: s.opts.Config.Section(label, meta.ID),
			client: conn,
		}
		if support := svc.Probe(ctx, h); !support.OK {
			out.Warn(meta.ID, support.Reason, "devtun will start without it")
			continue
		}
		out.OK(meta.ID, meta.Short)
	}
}

// diagnoseSetup reports the shell lines the remote still needs, which is the
// other half of "will this actually work" — a helper that is installed but not
// on PATH is a helper nothing will ever call.
func (s *Session) diagnoseSetup(
	ctx context.Context, out *doctor.Section, conn Conn, facts service.Facts, paths shim.RemotePaths,
) {
	plan := planRC(facts, paths.Bin)
	if onPath(facts.LoginPath, paths.Bin) {
		plan.Lines = plan.Lines[1:]
	}
	// The advisors are asked the same way attachAll asks them, so a service
	// that needs a second line is not forgotten here.
	h := &host{label: s.opts.Connector.Label(), facts: facts, paths: paths, events: event.Discard, client: conn}
	for _, svc := range s.opts.Services {
		advisor, ok := svc.(service.Advisor)
		if !ok || !s.opts.Config.Enabled(h.label, svc.Meta().ID, true) {
			continue
		}
		for _, line := range advisor.SetupLines(h) {
			if !alreadySet(facts, line) {
				plan.Lines = append(plan.Lines, line)
			}
		}
	}

	if len(plan.Lines) == 0 {
		out.OK("shell setup", "the login shell already has everything devtun needs")
		return
	}

	where := plan.File
	if where == "" {
		where = "your shell's rc file"
	}
	plan = checkWritable(ctx, conn, plan)
	fix := "add to " + where + ":\n" + strings.Join(plan.Lines, "\n")
	if plan.Writable {
		fix += "\ndevtun offers to do this for you on connect (--setup auto does it without asking)"
	} else if plan.Why != "" {
		fix += "\ndevtun will not edit it itself: " + plan.Why
	}
	out.Warn("shell setup", fmt.Sprintf("%d line(s) missing from the login shell", len(plan.Lines)), fix)
}

// fileExists is the "is there a cross-built helper in dist/" test, kept next to
// the reasoning that uses it rather than duplicating os.Stat at the call site.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
