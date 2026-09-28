package main

import (
	"github.com/spf13/cobra"

	"github.com/Sebiee/fortressedge/internal/ca"
)

func newCA() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Create a client CA and mint certificates offline",
	}
	initCmd := &cobra.Command{
		Use:   "init <dir>",
		Short: "Write ca.key and ca.crt: the client CA fortress.yml names as client_ca",
		Long: `Writes a client CA into <dir>. ca.crt goes into fortress.yml as client_ca;
ca.key stays with whoever signs certificates, never on an edge or in an ISO.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return ca.Init(args[0], nil)
		},
	}
	client := &cobra.Command{
		Use:   "client <dir> <spiffe-id>",
		Short: "Sign a client cert into <dir>/clients/<role>/<name>",
		Long: `Signs a client certificate with the CA in <dir>. The SPIFFE ID says what
it may do on the edge whose fqdn it names:

  spiffe://<fqdn>/node/<name>   a dark node: the tunnel only
  spiffe://<fqdn>/ops/<name>    an operator: the whole ops API
  spiffe://<fqdn>/logs/<name>   a log shipper or monitor: logs and status`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return ca.Client(args[0], args[1])
		},
	}
	cmd.AddCommand(initCmd, client)
	return cmd
}
