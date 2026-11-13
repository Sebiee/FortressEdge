// Package operator is what fortressctl does on the operator's side: bake
// a release ISO with fortress.yml, and put a policy on a running edge.
package operator

import (
	"fmt"
	"os"
	"time"

	"github.com/Sebiee/fortressedge/internal/bootimg"
	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
)

// Bake writes out: the release ISO at iso with the fortress.yml at
// edgePath in its initramfs, as it is. It must be a valid fortress.yml.
// Two bakes of the same files differ in the ISO's timestamps only.
func Bake(out, iso, edgePath string) error {
	edge, err := ReadEdge(edgePath)
	if err != nil {
		return err
	}
	if err := bootimg.Bake(out, iso, edge); err != nil {
		return err
	}
	if cas := config.EdgeClientCAs(edge); len(cas) > 1 {
		// Each is a full trust anchor: say which, so that a CA nobody meant
		// to bake is seen.
		fmt.Fprintf(os.Stderr, "fortressctl: %s trusts %d client CAs, and each can name any node, operator, and log reader:\n", out, len(cas))
		for _, c := range cas {
			fmt.Fprintf(os.Stderr, "  %s  sha256 %s  until %s\n", c.Subject, ca.Fingerprint(c), c.NotAfter.UTC().Format(time.DateOnly))
		}
	}
	if config.EdgeHoldsSecret(edge) {
		fmt.Fprintf(os.Stderr, "fortressctl: %s holds this edge's Vault secret ID, readable by you alone (0600): "+
			"it is a credential for one edge. Keep it as you keep the keys, never publish it, and bind the secret ID to the edge's address.\n", out)
	}
	return nil
}

// ReadEdge reads and checks a fortress.yml.
func ReadEdge(path string) ([]byte, error) {
	edge, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := config.CheckEdge(edge); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return edge, nil
}
