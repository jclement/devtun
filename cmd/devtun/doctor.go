package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
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
	doctorAlert(out)
	doctorEveryGateCanAsk(out, store, flags)
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

// doctorAlert reports whether a waiting approval will actually be heard.
//
// devtun runs in a window you are not looking at, which is the whole premise —
// so a request that makes no sound is one that times out unheard, and a timeout
// reads as a refusal nobody made. That makes "this machine will be silent" a
// thing to know now rather than after the fact.
func doctorAlert(out *doctor.Section) {
	player := ui.AlertPlayer()
	if player == "" {
		out.Warn("alert", "no way to play a sound here — only the terminal bell",
			"install a player (afplay, canberra-gtk-play, paplay), or make sure your terminal's bell is on\n"+
				"a request you do not hear is one that times out, and a timeout is a refusal you did not make")
		return
	}
	out.OK("alert", "an approval plays a sound with "+filepath.Base(player))
}

// doctorEveryGateCanAsk reports whether each gated service would have anywhere
// to put a question at all.
//
// Distinct from doctorApprovals above, which reports WHERE an approval would
// appear if one were asked for. This is the cruder question underneath it —
// whether the service was wired to ask anybody — and it is the one that has
// been wrong.
//
// This is the failure that has now shipped twice, and both times it was silent:
// a service whose prompter was never installed refuses everything, and the
// refusal is worded exactly like one somebody meant. The second time, `--web`
// was open in front of the person the whole time — a surface perfectly able to
// answer, never asked.
func doctorEveryGateCanAsk(out *doctor.Section, store *hostcfg.Store, flags upFlags) {
	services, _, err := buildServices(flags, store, promptBackendOf(flags), false, nil)
	if err != nil {
		out.Warn("gates", "could not assemble the services to check: "+err.Error(), "")
		return
	}
	var mute []string
	for _, svc := range services {
		if asker, ok := svc.(interface{ CanAsk() bool }); ok && !asker.CanAsk() {
			mute = append(mute, svc.Meta().ID)
		}
	}
	if len(mute) > 0 {
		out.Fail("gates", strings.Join(mute, ", ")+" would refuse everything without asking",
			"this is a bug in devtun, not in your setup — please report it")
		return
	}
	out.OK("gates", "every gated service has somewhere to put a question")
}

// promptBackendOf is what doctor assumes about a run it is not making. The
// config files are not consulted: this check is about the wiring, and the
// wiring is the same whichever backend the files name.
func promptBackendOf(flags upFlags) prompt.Backend {
	if v := strings.TrimSpace(flags.promptBackend); v != "" {
		return prompt.Backend(v)
	}
	return prompt.BackendAuto
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
	// `op whoami`, not `op account list`.
	//
	// This check used to run `account list` and claim, in a comment, that it
	// told "op is installed" from "op will answer". It does not: `account list`
	// reads a config file on disk and succeeds with no session at all. So
	// doctor reported a cheerful tick on a machine where every request from the
	// remote box came back "account is not signed in" — which is exactly the
	// failure this check exists to find, passed over by the check itself.
	//
	// `whoami` needs a live session, which is the thing being claimed. It may
	// raise a biometric prompt; that is the right trade for a diagnostic
	// somebody ran on purpose, and a prompt appearing is itself the answer.
	who, err := runBriefly(ctx, path, "whoami")
	if err != nil {
		if accounts, listErr := runBriefly(ctx, path, "account", "list"); listErr != nil || strings.TrimSpace(accounts) == "" {
			out.Warn("1password", "op "+version+" has no account configured",
				"run `op account add` — until then every op call from the remote box is refused")
			return
		}
		out.Warn("1password", "op "+version+" knows your accounts but is not signed in",
			"turn on 1Password → Settings → Developer → \"Integrate with 1Password CLI\", or run `eval $(op signin)`;\n"+
				"devtun will forward the request and op will refuse it until then")
		return
	}
	out.OK("1password", "op "+version+" · "+firstField(who, "signed in"))
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

// firstField pulls the account's email out of `op whoami`, which prints a
// labelled block. A fallback rather than a parser: the shape of that output is
// 1Password's to change, and a doctor line is not worth breaking over it.
func firstField(out, fallback string) string {
	for _, line := range strings.Split(out, "\n") {
		if _, rest, found := strings.Cut(line, "Email:"); found {
			if email := strings.TrimSpace(rest); email != "" {
				return email
			}
		}
	}
	return fallback
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
	// Same reason as runUp: Err() can only report files that have been read.
	store.LoadHost(dest.Label())
	backend := promptBackend(flags, store, dest.Label())

	// The registry is built exactly as a session builds it, so that what is
	// probed is what would actually run — including the services switched off
	// for this host, which doctor reports rather than hides.
	services, _, err := buildServices(flags, store, backend, false, nil)
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
