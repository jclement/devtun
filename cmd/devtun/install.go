package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jclement/devtun/internal/hostcfg"
	"github.com/jclement/devtun/internal/ui"
)

// newInstallCommand primes a box without starting a session.
//
// devtun installs the helper automatically on connect, so this exists for the
// case where you want that to have happened already — baking an image, or
// proving the cross-built binary runs there before you rely on it.
func newInstallCommand(shared *upFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "install <destination>",
		Short: "Put the devtun helper on a remote host and stop",
		Long: `Uploads the helper, creates its symlinks, and reports what the remote shell
still needs. devtun does this automatically on every connection; running it by
hand is for priming a box in advance, or for checking that the binary built for
that platform actually runs there.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := *shared
			flags.destination = args[0]
			// An install is exactly a session that stops once the remote is in
			// order, so it is the ordinary path with the services turned off.
			flags.only = []string{}
			flags.installOnly = true
			flags.tui = false
			return runUp(cmd.Context(), flags)
		},
	}
}

// newHostsCommand lists what devtun remembers.
func newHostsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hosts",
		Short: "List the hosts devtun has settings for",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := hostcfg.OpenDefault()
			hosts := store.Hosts()
			if len(hosts) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), ui.Muted.Render("no hosts yet — devtun <host> makes one"))
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, ui.Header.Render("HOST\tSETTINGS"))
			for _, host := range hosts {
				fmt.Fprintf(w, "%s\t%s\n", ui.Host.Render(host), ui.Muted.Render(store.HostPath(host)))
			}
			return w.Flush()
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print where devtun keeps its configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := hostcfg.Dir()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), dir)
			return nil
		},
	})
	return cmd
}
