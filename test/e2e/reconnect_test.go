//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// An edge restarting: it powers off at once on the power button, even
// with a request hanging, and closes its tunnels. A dark node's tunnel
// comes back by itself once the edge listens again, graceful restart or
// hard reset, and in between the site answers 503 with Retry-After,
// never a closed connection.
func TestTunnelComesBack(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{Tap: lab.HasTap()})
	vm, web, ops := e.VM, e.Web, e.Ops
	crt, key := e.Cert(ca.RoleNode, "node1")
	vm.Publish(t, "wss", e.Roots, crt, key, lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "back")
	})), "back.example.com")
	up := func(c *assert.CollectT) {
		_, body, err := lab.Get(web, "https://back.example.com/")
		require.NoError(c, err)
		assert.Equal(c, "back", body)
	}
	require.EventuallyWithT(t, up, lab.Until(t), lab.Tick)

	// back measures from the edge answering its ops API again to the site
	// answering through its tunnel, and checks every site request between
	// got an answer: 503 with Retry-After.
	back := func(t *testing.T, within time.Duration) {
		var ready time.Time
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, _, err := lab.Get(ops, lab.OpsURL+"status")
			require.NoError(c, err)
			ready = time.Now()
		}, lab.Until(t), 20*time.Millisecond)
		quick := &http.Client{Transport: web.Transport, Timeout: 2 * time.Second}
		gap := 0
		for {
			resp, body, err := lab.Get(quick, "https://back.example.com/")
			require.NoError(t, err, "the edge listens: the site must answer")
			if resp.StatusCode == http.StatusOK && body == "back" {
				break
			}
			require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, body)
			require.Equal(t, "1", resp.Header.Get("Retry-After"))
			gap++
			require.Less(t, time.Since(ready), lab.Until(t), "the tunnel never came back")
			time.Sleep(20 * time.Millisecond)
		}
		took := time.Since(ready)
		t.Logf("tunnel back %s after the edge listened; %d requests answered 503 meanwhile", took.Round(time.Millisecond), gap)
		assert.Less(t, took, within)
	}

	step(t, "the power button powers off within seconds, a hanging request and all", func(t *testing.T) {
		go lab.Get(&http.Client{Transport: web.Transport, Timeout: 30 * time.Second}, "https://back.example.com/hang")
		time.Sleep(300 * time.Millisecond)
		start := time.Now()
		vm.PowerDown(t)
		took := time.Since(start)
		t.Logf("powered off in %s", took.Round(time.Millisecond))
		assert.Less(t, took, 5*time.Second)
	})
	step(t, "after a restart the tunnel is back within a second of the edge listening", func(t *testing.T) {
		vm.Restart(t)
		back(t, 1500*time.Millisecond)
	})
	step(t, "after a hard reset the tunnel comes back too", func(t *testing.T) {
		// On QEMU's user-mode network, the tunnel ends at QEMU's socket on
		// this host, which stays open and acknowledges everything while the
		// machine behind it resets: frpc cannot tell, until QEMU gives up.
		// On a tap, as on a real network, the edge's kernel is the peer.
		within := 5 * time.Second
		if !lab.HasTap() {
			within = lab.Until(t)
		}
		vm.Reset(t)
		// The edge takes a moment to go away: wait until it has.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, _, err := lab.Get(&http.Client{Transport: ops.Transport, Timeout: 200 * time.Millisecond}, lab.OpsURL+"status")
			assert.Error(c, err)
		}, lab.Until(t), 20*time.Millisecond)
		back(t, within)
	})
}
