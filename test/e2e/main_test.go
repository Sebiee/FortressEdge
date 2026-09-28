//go:build e2e

package e2e

import (
	"os"
	"testing"

	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

func TestMain(m *testing.M) { os.Exit(lab.Main(m)) }

// step runs fn, and skips it when an earlier step already failed, so one
// failure does not turn into a pile of follow-on failures.
func step(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	if t.Failed() {
		t.Run(name, func(t *testing.T) { t.Skip("earlier step failed") })
		return
	}
	t.Run(name, fn)
}
