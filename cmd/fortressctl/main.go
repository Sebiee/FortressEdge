package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "fortressctl:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fortressctl",
		Short: "Operate a FortressEdge and build its images",
		Long: `An edge's config has three owners:

  fortress.yml    fortressctl bake puts it into a copy of the release ISO
  fqdn, address   the machine's NoCloud drive: user-data and network-config
  policy.yml      fortressctl apply puts it on the running edge

fortressctl ca makes the client CA fortress.yml names, and the operator,
log-reader, and dark-node certificates it signs.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newCA(), newInitramfs(), newISO(), newBake(), newApply(), newDiff())
	return cmd
}
