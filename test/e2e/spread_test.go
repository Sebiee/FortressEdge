//go:build e2e

package e2e

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/fatedier/frp/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// An edge behind a balancer, as a dark node's frpc sees it. The edge
// counts the node's tunnels in its login answer, whichever of a WebSocket
// and QUIC each came on, and answers a tunnel that asks to leave for
// another edge: yes while it has more tunnels that serve than the other
// edge would, never its last one, and never for a second login that
// reached this same edge. fortresskube's looks stand on these answers.
func TestEdgeCountsANodesTunnelsAndLetsOneLeave(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{Tap: lab.HasTap()})
	vm, web, ops := e.VM, e.Web, e.Ops
	const site = "spread.example.com"
	origin := lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "spread") }))
	crt, key := e.Cert(ca.RoleNode, "node1")
	proxy := lab.HTTPProxy(origin, site)
	a, _ := vm.DarkNode(t, lab.Member{User: "a"}, "wss", e.Roots, crt, key, proxy)
	b, _ := vm.DarkNode(t, lab.Member{User: "b"}, "quic", e.Roots, crt, key, proxy)
	served := func(c *assert.CollectT) {
		resp, body, err := lab.Get(web, "https://"+site+"/")
		require.NoError(c, err)
		assert.Equal(c, http.StatusOK, resp.StatusCode)
		assert.Equal(c, "spread", body)
	}
	// login waits for a frpc's login, and returns what the edge answered.
	login := func(t *testing.T, svc *client.Service) (runID string, peers int) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var ok bool
			runID, peers, ok = svc.Login()
			assert.True(c, ok)
		}, lab.Until(t), lab.Tick)
		return runID, peers
	}
	ctx, cancel := context.WithTimeout(t.Context(), lab.Until(t))
	defer cancel()
	leave := func(t *testing.T, svc *client.Service, runID string, peers int) (granted bool, serving int) {
		granted, serving, err := svc.Leave(ctx, runID, peers)
		require.NoError(t, err)
		return granted, serving
	}

	step(t, "a login is told how many tunnels of its node the edge has", func(t *testing.T) {
		require.EventuallyWithT(t, served, lab.Until(t), lab.Tick)
		_, n := login(t, a)
		assert.Positive(t, n, "an edge that counts says so at every login")
		// Both serve by now: the edge sent the site through one of them.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, body, err := lab.Get(ops, lab.OpsURL+"metrics")
			require.NoError(c, err)
			assert.Equal(c, 2.0, metric(body, "fortressedge_tunnel_proxies"))
		}, lab.Until(t), lab.Tick)

		look, stop := vm.DarkNode(t, lab.Member{User: "look"}, "wss", e.Roots, crt, key)
		runID, n := login(t, look)
		assert.Equal(t, 3, n, "two that serve, and the new login")

		granted, serving := leave(t, a, runID, n)
		assert.False(t, granted, "its second login is at this same edge")
		assert.Equal(t, 2, serving)
		stop()

		lab.Ctl(t, "ca", "client", e.PKI, ca.ID(lab.Tunnel, ca.RoleNode, "node2"))
		crt2, key2 := e.Cert(ca.RoleNode, "node2")
		other, _ := vm.DarkNode(t, lab.Member{User: "c"}, "quic", e.Roots, crt2, key2)
		_, n = login(t, other)
		assert.Equal(t, 1, n, "another node has its own count")
	})

	step(t, "a tunnel may leave for an edge with fewer, but not the last one", func(t *testing.T) {
		granted, serving := leave(t, a, "elsewhere", 1)
		assert.True(t, granted, "2 here, 1 there with it")
		assert.Equal(t, 2, serving)
		granted, serving = leave(t, b, "elsewhere", 1)
		assert.False(t, granted, "the last tunnel that serves")
		assert.Equal(t, 1, serving)
		resp, body, err := lab.Get(web, "https://"+site+"/")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, body)

		// The tunnel stays after all: the edge counts it again, so the
		// other one, on QUIC, may leave.
		require.NoError(t, a.Stay(ctx))
		granted, serving = leave(t, b, "elsewhere", 1)
		assert.True(t, granted)
		assert.Equal(t, 2, serving)
		require.NoError(t, b.Stay(ctx))

		_, metrics, err := lab.Get(ops, lab.OpsURL+"metrics")
		require.NoError(t, err)
		assert.Equal(t, 2.0, metric(metrics, `fortressedge_tunnel_leaves_total{result="granted"}`))
		assert.Equal(t, 2.0, metric(metrics, `fortressedge_tunnel_leaves_total{result="refused"}`))
		assert.Equal(t, 2.0, metric(metrics, `fortressedge_tunnel_group_members{group="node1"}`), "a leave closes no tunnel")
	})
}
