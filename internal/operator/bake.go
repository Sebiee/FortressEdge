// Package operator is what fortressctl does on the operator's side: bake
// a release ISO with fortress.yml, and put a policy on a running edge.
package operator

import (
	"fmt"
	"os"

	"github.com/Sebiee/fortressedge/internal/bootimg"
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
	return bootimg.Bake(out, iso, edge)
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
