//go:build e2e

package lab

import (
	"cmp"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
)

// EdgeOptions is how NewEdge makes an edge. The zero value is one vCPU on
// QEMU's user-mode network, booted from the suite's -iso baked with
// testdata/fortress.yml, named Tunnel, with no policy.
type EdgeOptions struct {
	CPUs, MemMiB int
	Tap          bool
	ISO          string // the release ISO to bake; empty is the suite's -iso
	Config       string // fortress.yml lines after testdata's
	Policy       string // applied with fortressctl apply once the edge is up
	Pebble       PebbleOptions
	FQDN         string // user-data's fqdn; empty is Tunnel
	NoDrive      bool   // boot without the NoCloud drive
}

// Edge is an edge VM as an operator deploys one: a release ISO baked with
// fortress.yml, a NoCloud drive with its fqdn and address, and a blank
// data disk. Its certificates come from its own Pebble.
type Edge struct {
	VM     *VM
	Pebble *Pebble
	Dir    string // the test's files: the ISO, the drive, the disk
	PKI    string // the client CA and a certificate per role (see PKI)
	// Roots is what the edge's certificates chain to: Pebble's root. A
	// visitor, a dark node, and fortressctl trust it.
	Roots string
	Web   *http.Client // a visitor
	Ops   *http.Client // the operator ops/alice
}

// NewEdge makes an edge without starting it: VM.Restart does.
func NewEdge(t *testing.T, o EdgeOptions) *Edge {
	t.Helper()
	e := &Edge{Dir: t.TempDir()}
	e.PKI = PKI(t, e.Dir)
	drive := filepath.Join(e.Dir, "cidata.iso")
	if o.NoDrive {
		drive = ""
	}
	e.VM = New(t, BlankDisk(t, e.Dir), drive, "")
	e.VM.CPUs, e.VM.MemMiB = o.CPUs, o.MemMiB
	if o.Tap {
		e.VM.UseTap(t)
	}
	e.Pebble = StartPebble(t, e.VM, o.Pebble)
	e.Roots = e.Pebble.Roots
	edge := []byte(string(Read(t, "fortress.yml")) + o.Config +
		"acme: " + e.Pebble.URL + "\n" +
		"acme_ca: |\n" + Indent(e.Pebble.TLSCA) +
		"ntp: " + e.VM.NTP() + "\n" +
		"client_ca: |\n" + Indent(readFile(t, filepath.Join(e.PKI, "ca.crt"))))
	e.VM.ISO = Bake(t, e.Dir, cmp.Or(o.ISO, *iso), edge)
	if drive != "" {
		Drive(t, drive, UserData(cmp.Or(o.FQDN, Tunnel)), e.VM.NetworkConfig())
	}
	opsCrt, opsKey := e.Cert(ca.RoleOps, "alice")
	e.Web = e.VM.Client(t, e.Roots, "", "")
	e.Ops = e.VM.Client(t, e.Roots, opsCrt, opsKey)
	return e
}

// BootEdge starts NewEdge's edge, waits until its ops API answers, and
// applies o.Policy.
func BootEdge(t *testing.T, o EdgeOptions) *Edge {
	t.Helper()
	e := NewEdge(t, o)
	e.VM.Restart(t)
	e.WaitUp(t)
	if o.Policy != "" {
		e.Apply(t, o.Policy)
	}
	return e
}

// WaitUp waits until the ops API answers the operator.
func (e *Edge) WaitUp(t *testing.T) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) { BootID(c, e.Ops) }, Until(t), Tick)
}

// Cert is the certificate and key for role/name in the edge's PKI.
func (e *Edge) Cert(role ca.Role, name string) (crt, key string) {
	return Cert(e.PKI, role, name)
}

// Apply puts policy on the edge with fortressctl apply, as ops/alice, and
// returns what it printed.
func (e *Edge) Apply(t *testing.T, policy string) string {
	t.Helper()
	return CtlOut(t, append([]string{"apply", Tunnel, "-f", Write(t, t.TempDir(), "policy.yml", []byte(policy))}, e.ctlFlags()...)...)
}

// Diff runs fortressctl diff against policy and returns what it printed
// and whether the edge has that policy: exit status 0, where 1 is a
// difference and anything else fails the test.
func (e *Edge) Diff(t *testing.T, policy string) (string, bool) {
	t.Helper()
	out, code := ctl(t, append([]string{"diff", Tunnel, "-f", Write(t, t.TempDir(), "policy.yml", []byte(policy))}, e.ctlFlags()...)...)
	require.Contains(t, []int{0, 1}, code, "fortressctl diff\n%s", out)
	return out, code == 0
}

// ctlFlags reach the edge as the operator: through the forward to the
// guest's 443, trusting Pebble's root.
func (e *Edge) ctlFlags() []string {
	crt, key := e.Cert(ca.RoleOps, "alice")
	return []string{"--cert", crt, "--key", key, "--cacert", e.Roots,
		"--connect", net.JoinHostPort(e.VM.Addr, strconv.Itoa(e.VM.HTTPS))}
}

// Indent makes PEM a YAML block scalar body.
func Indent(pem []byte) string {
	return "  " + strings.ReplaceAll(strings.TrimSpace(string(pem)), "\n", "\n  ") + "\n"
}
