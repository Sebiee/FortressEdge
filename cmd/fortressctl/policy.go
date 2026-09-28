package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Sebiee/fortressedge/internal/operator"
)

// edgeFlags are how apply and diff reach an edge.
func edgeFlags(cmd *cobra.Command, e *operator.Edge, file *string) {
	cmd.Flags().StringVarP(file, "file", "f", "policy.yml", "policy.yml")
	cmd.Flags().StringVar(&e.Cert, "cert", "", "operator client certificate (ops/<name>)")
	cmd.Flags().StringVar(&e.Key, "key", "", "its private key")
	cmd.Flags().StringVar(&e.CACert, "cacert", "", "PEM roots for the edge's certificate, such as the ACME server's CA; default: the system roots")
	cmd.Flags().StringVar(&e.Connect, "connect", "", "host:port to dial instead of <fqdn>:443")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
}

func newApply() *cobra.Command {
	var e operator.Edge
	var file string
	cmd := &cobra.Command{
		Use:   "apply <fqdn>",
		Short: "Put a policy.yml on a running edge",
		Long: `Replaces the edge's policy (block, exempt, limits) with policy.yml, over
the ops API with an operator certificate. The same file again changes
nothing, so a pipeline can apply on every merge. block, exempt, and most
limits apply at once; max_connections, max_header_size,
max_http2_streams, and response_header_timeout reboot the edge.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e.Name = args[0]
			return operator.Apply(e, file, cmd.OutOrStdout())
		},
	}
	edgeFlags(cmd, &e, &file)
	return cmd
}

func newDiff() *cobra.Command {
	var e operator.Edge
	var file string
	cmd := &cobra.Command{
		Use:   "diff <fqdn>",
		Short: "Show how an edge's policy differs from policy.yml",
		Long: `Prints a unified diff from the edge's policy to policy.yml: what
fortressctl apply would change. Exits 0 when they are the same, 1 when
they differ, and 2 when the edge could not be compared, as diff does.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e.Name = args[0]
			err := operator.Diff(e, file, cmd.OutOrStdout())
			if errors.Is(err, operator.ErrDrift) {
				os.Exit(1)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "fortressctl:", err)
				os.Exit(2)
			}
			return nil
		},
	}
	edgeFlags(cmd, &e, &file)
	return cmd
}
