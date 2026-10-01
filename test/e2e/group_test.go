//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// A dark node runs several frpc with one node certificate, as
// fortresskube's replicas do: they share its names, and the edge spreads
// requests across them. Another node cannot join them. One that goes
// silent, with no FIN or RST (a node lost, a network cut), leaves the
// group within seconds, and the others carry its share; when it comes
// back, it rejoins. On a tap, so the edge's TCP talks to the members'
// TCP, not to slirp's.
func TestGroupSharesNamesAndDropsADeadMember(t *testing.T) {
	if !lab.HasTap() {
		t.Skip("needs -tap: run in os/netns.sh")
	}
	// Member b dials from an address of its own, so nft can cut it alone.
	const bAddr = "10.77.0.9"
	out, err := exec.Command("ip", "addr", "add", bAddr+"/32", "dev", lab.TapDevice()).CombinedOutput()
	require.NoError(t, err, "ip addr: %s", out)
	t.Cleanup(func() { exec.Command("ip", "addr", "del", bAddr+"/32", "dev", lab.TapDevice()).Run() })

	e := lab.BootEdge(t, lab.EdgeOptions{Tap: true})
	vm, web, ops := e.VM, e.Web, e.Ops
	const site = "group.example.com"
	origin := func(name string) int {
		return lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, name) }))
	}
	crt, key := e.Cert(ca.RoleNode, "node1")
	vm.PublishAs(t, lab.Member{User: "a"}, "wss", e.Roots, crt, key, origin("a"), site)
	vm.PublishAs(t, lab.Member{User: "b", LocalIP: bAddr}, "wss", e.Roots, crt, key, origin("b"), site)

	quick := &http.Client{Transport: web.Transport, Timeout: 10 * time.Second}
	// answers sends n requests and counts the bodies; a failed request
	// counts under its error or status.
	answers := func(n int) map[string]int {
		got := map[string]int{}
		for range n {
			resp, body, err := lab.Get(quick, "https://"+site+"/")
			switch {
			case err != nil:
				got["error"]++
			case resp.StatusCode != http.StatusOK:
				got[resp.Status]++
			default:
				got[body]++
			}
		}
		return got
	}
	members := func(c require.TestingT) (map[string]int, bool) {
		ops.CloseIdleConnections()
		_, body, err := lab.Get(ops, lab.OpsURL+"status")
		require.NoError(c, err)
		var st struct {
			Ready  bool           `json:"ready"`
			Groups map[string]int `json:"tunnel_groups"`
		}
		require.NoError(c, json.Unmarshal([]byte(body), &st), body)
		return st.Groups, st.Ready
	}

	step(t, "both members get requests", func(t *testing.T) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			g, ready := members(c)
			assert.Equal(c, map[string]int{"node1": 2}, g)
			assert.True(c, ready)
		}, lab.Until(t), lab.Tick)
		// The site's certificate comes after the logins.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			resp, _, err := lab.Get(quick, "https://"+site+"/")
			require.NoError(c, err)
			assert.Equal(c, http.StatusOK, resp.StatusCode)
		}, lab.Until(t), lab.Tick)
		got := answers(20)
		assert.Equal(t, map[string]int{"a": 10, "b": 10}, got, "round robin")
		_, body, err := lab.Get(ops, lab.OpsURL+"metrics")
		require.NoError(t, err)
		assert.Equal(t, 2.0, metric(body, `fortressedge_tunnel_group_members{group="node1"}`))
		assert.Equal(t, 1.0, metric(body, "fortressedge_ready"))
	})

	step(t, "another node cannot join the group", func(t *testing.T) {
		lab.Ctl(t, "ca", "client", e.PKI, ca.ID(lab.Tunnel, ca.RoleNode, "node2"))
		crt2, key2 := e.Cert(ca.RoleNode, "node2")
		vm.PublishAs(t, lab.Member{User: "c"}, "wss", e.Roots, crt2, key2, origin("c"), site)
		// It logs in; its proxy for the name is refused.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			g, _ := members(c)
			assert.Equal(c, map[string]int{"node1": 2, "node2": 1}, g)
		}, lab.Until(t), lab.Tick)
		time.Sleep(time.Second)
		got := answers(20)
		assert.Equal(t, map[string]int{"a": 10, "b": 10}, got)
	})

	// nft drops every packet to and from b: to the edge, b goes silent.
	cut := `table inet lab_group {
	chain in { type filter hook input priority 0; policy accept; ip daddr ` + bAddr + ` counter drop; }
	chain out { type filter hook output priority 0; policy accept; ip saddr ` + bAddr + ` counter drop; }
}`
	heal := func() { exec.Command("/usr/sbin/nft", "delete", "table", "inet", "lab_group").Run() }
	t.Cleanup(heal)

	step(t, "a silent member leaves within seconds, and the other carries the site", func(t *testing.T) {
		cmd := exec.Command("/usr/sbin/nft", "-f", "-")
		cmd.Stdin = strings.NewReader(cut)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "nft: %s", out)
		start := time.Now()
		failed := 0
		var left time.Duration
		for time.Since(start) < 15*time.Second {
			got := answers(1)
			failed += len(got) - got["a"] - got["b"]
			if g, _ := members(t); g["node1"] == 1 && left == 0 {
				left = time.Since(start)
			}
			if left > 0 && time.Since(start) > left+time.Second {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		require.NotZero(t, left, "the silent member never left")
		t.Logf("silent member left after %s; %d requests failed meanwhile", left.Round(time.Millisecond), failed)
		assert.Less(t, left, 6*time.Second)
		got := answers(20)
		assert.Equal(t, map[string]int{"a": 20}, got, "after it left, every request goes to the live member")
	})

	step(t, "it rejoins once it can reach the edge again", func(t *testing.T) {
		heal()
		start := time.Now()
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			g, _ := members(c)
			assert.Equal(c, 2, g["node1"])
			// Logged in first, then its proxy: wait for its answers.
			assert.Positive(c, answers(2)["b"])
		}, lab.Until(t), 50*time.Millisecond)
		t.Logf("member back %s after the cut healed", time.Since(start).Round(time.Millisecond))
		got := answers(20)
		assert.Equal(t, map[string]int{"a": 10, "b": 10}, got)
	})
}
