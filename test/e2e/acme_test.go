//go:build e2e

package e2e

import (
	"crypto/rand"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// Boot against a private ACME directory (Pebble) that the edge trusts
// through acme_ca, and check where certificates come from.
func TestCertificatesFromAnACMEServer(t *testing.T) {
	t.Parallel()
	// The renewal timer runs every 250ms, so an ARI window the lab moves
	// is seen at once.
	a := bootACME(t, lab.PebbleOptions{}, "250ms")
	vm, pebble, web, ops, nodeCrt, nodeKey := a.vm, a.pebble, a.web, a.ops, a.nodeCrt, a.nodeKey

	var tunnelSerial string
	step(t, "the tunnel certificate comes from the ACME server, issued once", func(t *testing.T) {
		resp, _, err := lab.Get(ops, lab.OpsURL+"status")
		require.NoError(t, err)
		leaf := resp.TLS.PeerCertificates[0]
		assert.Equal(t, []string{lab.Tunnel}, leaf.DNSNames)
		assert.Equal(t, []string{lab.Tunnel}, pebble.Issued(), "TCP 443 and QUIC share one certificate")
		tunnelSerial = leaf.SerialNumber.String()
	})

	step(t, "a site is issued when a dark node publishes it, before anyone visits", func(t *testing.T) {
		body := rand.Text()
		vm.Publish(t, "wss", pebble.Roots, nodeCrt, nodeKey, lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, body)
		})), "app.example.com")
		require.Eventually(t, func() bool { return slices.Contains(pebble.Issued(), "app.example.com") }, lab.Until(t), lab.Tick)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			resp, got, err := lab.Get(web, "https://app.example.com/")
			require.NoError(c, err)
			assert.Equal(c, body, got)
			assert.Equal(c, []string{"app.example.com"}, resp.TLS.PeerCertificates[0].DNSNames)
		}, lab.Until(t), lab.Tick)
	})

	step(t, "a name no dark node published gets no certificate", func(t *testing.T) {
		_, _, err := lab.Get(web, "https://nobody.example.com/")
		assert.Error(t, err, "TLS handshake for an unpublished name")
		assert.NotContains(t, pebble.Issued(), "nobody.example.com")
	})

	step(t, "a dark node on QUIC trusts the ACME tunnel certificate", func(t *testing.T) {
		vm.Tunnel(t, web, "quic", "quic.example.com", pebble.Roots, nodeCrt, nodeKey)
	})

	step(t, "after a reboot, certificates come from the disk", func(t *testing.T) {
		before := pebble.Issued()
		vm.PowerDown(t)
		vm.Restart(t)
		require.EventuallyWithT(t, func(c *assert.CollectT) { lab.BootID(c, ops) }, lab.Until(t), lab.Tick)
		resp, _, err := lab.Get(ops, lab.OpsURL+"status")
		require.NoError(t, err)
		assert.Equal(t, tunnelSerial, resp.TLS.PeerCertificates[0].SerialNumber.String(), "tunnel certificate")
		vm.Tunnel(t, web, "wss", "app.example.com", pebble.Roots, nodeCrt, nodeKey)
		assert.Equal(t, before, pebble.Issued(), "nothing issued after the reboot")
	})

	step(t, "a name whose dark node left is not answered, though its certificate is on disk", func(t *testing.T) {
		stop := vm.Tunnel(t, web, "wss", "gone.example.com", pebble.Roots, nodeCrt, nodeKey)
		stop()
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, _, err := lab.Get(web, "https://gone.example.com/")
			assert.Error(c, err, "TLS handshake for a name no node publishes")
		}, lab.Until(t), lab.Tick)
	})

	step(t, "when the ACME server asks for early renewal (ARI), the next check renews, once", func(t *testing.T) {
		vm.Tunnel(t, web, "wss", "app.example.com", pebble.Roots, nodeCrt, nodeKey)
		oldTunnel := pebble.RenewNow(t, lab.Tunnel)
		oldApp := pebble.RenewNow(t, "app.example.com")
		pebble.RenewNow(t, "gone.example.com")
		var newTunnel string
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			newTunnel = lab.Serial(c, ops, lab.OpsURL+"status")
			assert.NotEqual(c, oldTunnel, newTunnel, "tunnel")
			assert.NotEqual(c, oldApp, lab.Serial(c, web, "https://app.example.com/"), "app.example.com")
		}, lab.Until(t), lab.Tick)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Equal(c, newTunnel, vm.QUICSerial(c, pebble.Roots, nodeCrt, nodeKey), "QUIC reloads the renewed certificate")
		}, lab.Until(t), lab.Tick)
		// Once each, or twice: certmagic's ARI check fetches the old
		// certificate's window, and when a renewal lands before it stores
		// that window, the new certificate takes the old one's past window
		// and renews once more. That is certmagic's race, not the edge's.
		issued := pebble.Issued()
		assert.Contains(t, []int{2, 3}, count(issued, lab.Tunnel), "TCP 443 and QUIC renewed the tunnel certificate between them")
		assert.Contains(t, []int{2, 3}, count(issued, "app.example.com"))
		assert.Equal(t, 1, count(issued, "gone.example.com"), "a name no node publishes is not renewed")
	})
}

// acmeLab is an edge booted against its own Pebble, which it trusts
// through acme_ca, with QUIC on.
type acmeLab struct {
	vm               *lab.VM
	pebble           *lab.Pebble
	web, ops         *http.Client // ops carries the ops certificate
	nodeCrt, nodeKey string       // a dark node's client certificate
}

func bootACME(t *testing.T, opts lab.PebbleOptions, renewInterval string) acmeLab {
	t.Helper()
	e := lab.BootEdge(t, lab.EdgeOptions{Pebble: opts, Config: "renew_interval: " + renewInterval + "\n"})
	a := acmeLab{vm: e.VM, pebble: e.Pebble, web: e.Web, ops: e.Ops}
	a.nodeCrt, a.nodeKey = e.Cert(ca.RoleNode, "node1")
	return a
}
