//go:build e2e

package e2e

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// Certificates that live 24 seconds, checked every 250ms, as Traefik's
// suite does with 120-second ones: each is replaced in the last third of
// its life, twice, so a renewed certificate is renewed again; none is
// served expired; and a name no node publishes is not renewed. ARI is off,
// so the lifetime alone decides. certmagic renews at once when fewer than
// five checks are left, so the lifetime is well over fifteen checks; and
// it renews one certificate at a time, so the last third (8s) must hold
// two back-to-back ACME orders: a second each under -race, and several
// when the host is busy and the 1-vCPU guest waits for it.
func TestCertificatesRenewBeforeTheyExpire(t *testing.T) {
	t.Parallel()
	const life = 24 * time.Second
	a := bootACME(t, lab.PebbleOptions{Validity: life, NoARI: true}, "250ms")
	stop := a.vm.Tunnel(t, a.web, "wss", "gone.example.com", a.pebble.Roots, a.nodeCrt, a.nodeKey)
	stop()
	a.vm.Tunnel(t, a.web, "wss", "app.example.com", a.pebble.Roots, a.nodeCrt, a.nodeKey)

	sites := map[string]func(c *assert.CollectT) *x509.Certificate{
		lab.Tunnel:        func(c *assert.CollectT) *x509.Certificate { return lab.Leaf(c, a.ops, lab.OpsURL+"status") },
		"app.example.com": func(c *assert.CollectT) *x509.Certificate { return lab.Leaf(c, a.web, "https://app.example.com/") },
	}
	served := map[string]map[string]bool{lab.Tunnel: {}, "app.example.com": {}} // serials clients saw
	var expired []string
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		for name, leaf := range sites {
			cert := leaf(c)
			if !time.Now().Before(cert.NotAfter) {
				expired = append(expired, name+" "+cert.SerialNumber.String())
			}
			served[name][cert.SerialNumber.String()] = true
		}
		for name := range sites {
			assert.GreaterOrEqual(c, len(served[name]), 3, "%s: clients saw two renewals", name)
		}
	}, lab.Until(t), lab.Tick)

	assert.Empty(t, expired, "served after it expired")
	// When each renewal happened comes from what Pebble issued, not from
	// sampling: a slow sample can miss a whole generation.
	for name := range sites {
		for prev, next := range pairs(a.pebble.Certificates(name)) {
			// A certificate is issued when it is renewed. Certificate times
			// are whole seconds, and the ACME order takes a moment.
			assert.True(t, next.NotBefore.After(prev.NotBefore.Add(life*2/3-2*time.Second)),
				"%s renewed at %v into a %v life: before its last third", name, next.NotBefore.Sub(prev.NotBefore), life)
			assert.True(t, next.NotBefore.Before(prev.NotAfter), "%s renewed after it expired", name)
		}
	}
	assert.Equal(t, 1, count(a.pebble.Issued(), "gone.example.com"), "a name no node publishes is not renewed")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, lab.Serial(c, a.ops, lab.OpsURL+"status"), a.vm.QUICSerial(c, a.pebble.Roots, a.nodeCrt, a.nodeKey),
			"QUIC serves the current tunnel certificate")
	}, lab.Until(t), lab.Tick)
}

// pairs yields each certificate with the one that replaced it.
func pairs(certs []*x509.Certificate) func(yield func(prev, next *x509.Certificate) bool) {
	return func(yield func(prev, next *x509.Certificate) bool) {
		for i := 1; i < len(certs); i++ {
			if !yield(certs[i-1], certs[i]) {
				return
			}
		}
	}
}

// count is how many times name appears in names.
func count(names []string, name string) int {
	return len(slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n != name }))
}
