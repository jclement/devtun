// Command devtun makes a remote development box feel local: every port it
// opens appears on your machine, its `op` calls reach your own 1Password vault
// one approval at a time, and the URLs it wants opened open here.
//
// The same binary is also the shim that runs on the remote box, dispatched on
// argv[0] before cobra sees anything — as `op`, every argument belongs to the
// 1Password command line, including ones that would otherwise collide with
// devtun's own flags.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jclement/devtun/internal/buildinfo"
	"github.com/jclement/devtun/internal/ui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if code, handled := runShim(ctx, os.Args); handled {
		os.Exit(code)
	}

	ui.Init()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		// Cobra has already printed usage errors; anything else is ours to
		// report, and a cancelled context is a Ctrl-C rather than a fault.
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, ui.Error.Render("devtun: "+err.Error()))
		}
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var flags upFlags

	root := &cobra.Command{
		Use:   "devtun [flags] <destination>",
		Short: "Make a remote dev box feel local",
		Long: `devtun keeps one SSH connection to a development box and layers services on it:

  tunnels     every port the box opens appears on your localhost
  1password   the box's ` + "`op`" + ` calls reach your vault, one approval at a time
  browser     URLs the box wants opened open here

<destination> is an ssh_config alias or [user@]host[:port]. The alias is also
the name settings and approvals are recorded against, so they keep working when
a machine changes address.

` + completionHint(),
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       buildinfo.Version(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			flags.destination = args[0]
			return runUp(cmd.Context(), flags)
		},
	}

	root.SetVersionTemplate(buildinfo.Short() + "\n")
	flags.register(root)

	root.AddCommand(
		newVersionCommand(),
		newUpdateCommand(),
		newInstallCommand(&flags),
		newHostsCommand(),
	)
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit, build date and toolchain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), buildinfo.Long())
			return nil
		},
	}
}

// shimName reports the base name devtun was invoked as, for argv[0] dispatch.
func shimName(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return filepath.Base(argv[0])
}
