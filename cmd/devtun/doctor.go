package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jclement/devtun/internal/buildinfo"
	"github.com/jclement/devtun/internal/doctor"
	"github.com/jclement/devtun/internal/event"
	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/prompt"
	"github.com/jclement/devtun/internal/release"
	"github.com/jclement/devtun/internal/session"
	"github.com/jclement/devtun/internal/sshx"
	"github.com/jclement/devtun/internal/ui"
)

// newDoctorCommand answers "why is this not working" without making anyone
// start a session and read a log.
//
// Two halves, because there are two machines. `devtun doctor` looks at this
// workstation: the tools devtun drives here — the 1Password CLI, your agent, a
// browser, something to draw an approval dialog with — and the config it will
// read. `devtun doctor <host>` adds the other end: it connects, probes, asks
// every service the same question a session asks it, and reports whether the
// helper is installed and whether the remote shell has what it needs.
//
// It changes nothing. Not the remote shell, not the helper, not a config file.
// A diagnostic that edits the machine is one people stop running on the machine
// where it matters.
func newDoctorCommand(shared *upFlags) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "doctor [destination]",
		Short: "Check that devtun has what it needs, here and on a host",
		Long: `With no arguments, checks this machine: the config devtun reads, the 1Password
CLI, the SSH agent, a browser to open URLs in, and whether an approval can be
put in front of you.

Given a host, it also connects and checks that end — the helper, the login
shell's PATH, and whether each service can actually run there — and changes
nothing while it does.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := *shared
			report := &doctor.Report{}
			localChecks(cmd.Context(), report, flags)

			if len(args) == 1 {
				flags.destination = args[0]
				if err := remoteChecks(cmd.Context(), report, flags); err != nil {
					return err
				}
			}

			out := cmd.OutOrStdout()
			if asJSON || !ui.IsTTY() {
				if err := report.WriteJSON(out); err != nil {
					return err
				}
			} else {
				report.Render(out)
			}
			if report.Failed() {
				// Quietly, because the report has already said everything there
				// is to say and a second summary line would only repeat it.
				return errSilent
			}
			return nil
		},
	}
	shared.registerConnection(cmd.Flags())
	cmd.Flags().BoolVar(&asJSON, "json", false, "one JSON object instead of a report")
	return cmd
}

// localChecks looks at this workstation.
func localChecks(ctx context.Context, report *doctor.Report, flags upFlags) {
	out := report.Section("this machine")
	out.OK("devtun", buildinfo.Short())

	store := hostcfg.OpenDefault()
	dir, dirErr := hostcfg.Dir()
	switch {
	case dirErr != nil:
		out.Warn("config", "no config directory: "+dirErr.Error(),
			"devtun runs, but nothing you decide will be remembered")
	case store.Err() != nil:
		out.Fail("config", store.Err().Error(),
			"devtun refuses to start on a config it cannot read, because a file that was\n"+
				"meant to deny something and instead says nothing has failed open")
	default:
		out.OK("config", fmt.Sprintf("%s · %d host(s)", dir, len(store.Hosts())))
	}

	doctorApprovals(out, store, flags)
	doctorOnePassword(ctx, out, flags)
	doctorAgent(out, flags)
	doctorBrowser(out)
}

// doctorApprovals reports where an approval would appear, which is the check
// people most often want after configuring `prompt:`.
func doctorApprovals(out *doctor.Section, store *hostcfg.Store, flags upFlags) {
	backend := promptBackend(flags, store, "")
	dialog := prompt.DialogBackend()

	switch backend {
	case prompt.BackendDeny:
		out.Warn("approvals", "deny — nothing outside your rules will be allowed",
			"remove `prompt: deny` to be asked instead")
	case prompt.BackendDialog:
		if dialog == "" {
			out.Fail("approvals", "dialog, but this machine has no program to draw one",
				"install one of "+strings.Join(prompt.ChooserNames(), ", ")+", or set `prompt: auto`")
			return
		}
		out.OK("approvals", "a desktop dialog, drawn with "+dialog)
	default:
		if dialog != "" {
			out.OK("approvals", "auto — a desktop dialog, drawn with "+dialog)
			return
		}
		if !ui.IsInteractive() {
			out.Warn("approvals", "auto — and there is no terminal and no dialog program here",
				"a prompt nobody can answer is a refusal; run devtun from a terminal")
			return
		}
		out.OK("approvals", "auto — in the interface, or in the terminal under --log")
	}
}

// doctorOnePassword checks the CLI devtun drives on *this* side. The remote box
// does not need op; this machine does, and that is the part people get the
// wrong way round.
func doctorOnePassword(ctx context.Context, out *doctor.Section, flags upFlags) {
	name := flags.opPath
	if name == "" {
		name = "op"
	}
	path, err := exec.LookPath(name)
	if err != nil {
		out.Warn("1password", "no `op` on this machine",
			"install it with `brew install 1password-cli` — without it the remote's op calls are refused")
		return
	}

	version, err := runBriefly(ctx, path, "--version")
	if err != nil {
		out.Warn("1password", path+" would not run: "+err.Error(), "check the install")
		return
	}
	// Whether an account is configured is the difference between "op is
	// installed" and "op will answer", and only the second one matters.
	if _, err := runBriefly(ctx, path, "account", "list"); err != nil {
		out.Warn("1password", "op "+version+" at "+path+", but no account answered",
			"run `op account add`, or sign in to the 1Password app and enable the CLI integration")
		return
	}
	out.OK("1password", "op "+version+" at "+path)
}

// doctorAgent reports which agent devtun would forward, and what it holds.
func doctorAgent(out *doctor.Section, flags upFlags) {
	if flags.noAgent {
		out.Off("ssh-agent", "--no-agent")
		return
	}
	socket, keys, err := sshx.AgentKeys(flags.authSock, "")
	switch {
	case socket == "":
		out.Warn("ssh-agent", "no agent: SSH_AUTH_SOCK is not set",
			"start one (`ssh-add -l` will tell you), or devtun has no keys to offer the remote")
	case err != nil:
		out.Fail("ssh-agent", err.Error(),
			"the socket is named but nothing is listening — a stale SSH_AUTH_SOCK in this shell?")
	case len(keys) == 0:
		out.Warn("ssh-agent", "the agent at "+socket+" is holding no keys",
			"`ssh-add ~/.ssh/id_ed25519`, or unlock the agent that has them")
	default:
		out.OK("ssh-agent", fmt.Sprintf("%d key(s) via %s", len(keys), socket))
	}
}

// doctorBrowser checks that a URL the remote asks for can actually be opened.
func doctorBrowser(out *doctor.Section) {
	opener := ui.OpenerName()
	if opener == "" {
		out.Warn("browser", "nothing here can open a URL",
			"install xdg-open (or gio, sensible-browser) — until then the browser service just logs the URL")
		return
	}
	out.OK("browser", "URLs open with "+opener)
}

// runBriefly runs a local tool for its one line of output. The timeout is
// short: doctor is answering "is this here and does it work", and a tool that
// takes ten seconds to say its own version has already answered no.
func runBriefly(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// remoteChecks connects to the host and asks the session itself.
func remoteChecks(ctx context.Context, report *doctor.Report, flags upFlags) error {
	dest, connectOpts, err := resolveDestination(flags)
	if err != nil {
		return err
	}
	store := hostcfg.OpenDefault()
	backend := promptBackend(flags, store, dest.Label())

	// The registry is built exactly as a session builds it, so that what is
	// probed is what would actually run — including the services switched off
	// for this host, which doctor reports rather than hides.
	services, _, err := buildServices(flags, store, backend, false)
	if err != nil {
		return err
	}

	sess := session.New(session.Options{
		Connector: session.NewSSHConnector(dest, connectOpts),
		// A real bus, small: Diagnose emits nothing, but a session built
		// around a nil one is a panic waiting for the first line of code that
		// forgets that.
		Bus:        event.NewBus(1),
		Services:   services,
		Config:     store,
		ShimBinary: flags.shimBinary,
		FetchShim: (&release.Fetcher{
			Slug:    repoSlug,
			Version: buildinfo.Version(),
		}).Binary,
		Version: buildinfo.Version(),
	})

	report.Sections = append(report.Sections, sess.Diagnose(ctx))
	return nil
}

// errSilent ends the command with a failing status and no extra message: the
// report is the message.
var errSilent = silentError{}

type silentError struct{}

func (silentError) Error() string { return "" }

// exitQuietly lets main tell a silent failure from a real one.
func exitQuietly(err error) bool {
	_, ok := err.(silentError)
	return ok
}
