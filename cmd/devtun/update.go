package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jclement/devtun/internal/buildinfo"
	"github.com/jclement/devtun/internal/selfupdate"
	"github.com/jclement/devtun/internal/ui"
)

// repoSlug is where releases come from.
const repoSlug = "jclement/devtun"

// newUpdateCommand replaces this binary with the latest release.
//
// It refuses to clobber a Homebrew-managed install and says to run `brew
// upgrade` instead, because overwriting a file a package manager believes it
// owns is how you end up with a version number that is a work of fiction.
func newUpdateCommand() *cobra.Command {
	var check bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Replace this binary with the latest release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			source, err := selfupdate.NewGitHubSource(repoSlug)
			if err != nil {
				return err
			}
			return selfupdate.Run(cmd.Context(), selfupdate.Options{
				Source:    source,
				Current:   buildinfo.Version(),
				CheckOnly: check,
				Out:       cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "report whether an update exists, and change nothing")
	return cmd
}

// newCompletionNote is a small courtesy: cobra generates the completion
// command, but nobody discovers it, so the root's help says it is there.
func completionHint() string {
	return ui.Muted.Render(fmt.Sprintf("shell completions: %s completion zsh (or bash, fish)", "devtun"))
}
