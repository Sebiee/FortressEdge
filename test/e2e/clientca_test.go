//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// An edge that trusts two client CAs, as while the edges change CA. A
// certificate is its SPIFFE name, whichever CA signed it: node1 from the
// old CA and node1 from the new one are one node, in one group, with the
// same names, and requests reach both. An operator from either CA sets the
// policy. A third CA's certificates are refused, and an edge baked with
// the new CA alone refuses the old one's.
func TestTwoClientCAs(t *testing.T) {
	t.Parallel()
	old := lab.PKI(t, t.TempDir())
	e := lab.BootEdge(t, lab.EdgeOptions{MoreClientCAs: []string{old}})
	vm, web, ops := e.VM, e.Web, e.Ops
	const site = "ca.example.com"
	origin := func(name string) int {
		return lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, name) }))
	}
	newCrt, newKey := e.Cert(ca.RoleNode, "node1")
	oldCrt, oldKey := lab.Cert(old, ca.RoleNode, "node1")

	step(t, "node1 from either CA is one node: one group, one name, requests to both", func(t *testing.T) {
		vm.PublishAs(t, lab.Member{User: "new"}, "wss", e.Roots, newCrt, newKey, origin("new"), site)
		// The old CA's over QUIC, so both of the edge's checks see a second CA.
		vm.PublishAs(t, lab.Member{User: "old"}, "quic", e.Roots, oldCrt, oldKey, origin("old"), site)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, body, err := lab.Get(ops, lab.OpsURL+"status")
			require.NoError(c, err)
			var st struct {
				Groups map[string]int `json:"tunnel_groups"`
			}
			require.NoError(c, json.Unmarshal([]byte(body), &st), body)
			assert.Equal(c, map[string]int{"node1": 2}, st.Groups)
		}, lab.Until(t), lab.Tick)
		quick := &http.Client{Transport: web.Transport, Timeout: 10 * time.Second}
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			resp, _, err := lab.Get(quick, "https://"+site+"/")
			require.NoError(c, err)
			assert.Equal(c, http.StatusOK, resp.StatusCode)
		}, lab.Until(t), lab.Tick)
		got := map[string]int{}
		for range 20 {
			_, body, err := lab.Get(quick, "https://"+site+"/")
			require.NoError(t, err)
			got[body]++
		}
		assert.Positive(t, got["new"], "no request reached the new CA's tunnel: %v", got)
		assert.Positive(t, got["old"], "no request reached the old CA's tunnel: %v", got)
	})

	step(t, "the status and the metrics list both CAs", func(t *testing.T) {
		_, body, err := lab.Get(ops, lab.OpsURL+"status")
		require.NoError(t, err)
		var st struct {
			CAs []struct {
				SHA256 string `json:"sha256"`
			} `json:"client_cas"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &st), body)
		want := []string{fingerprint(t, e.PKI), fingerprint(t, old)}
		var got []string
		for _, c := range st.CAs {
			got = append(got, c.SHA256)
		}
		assert.Equal(t, want, got)
		_, metrics, err := lab.Get(ops, lab.OpsURL+"metrics")
		require.NoError(t, err)
		for _, fp := range want {
			assert.Contains(t, metrics, `fortressedge_client_ca_not_after_seconds{sha256="`+fp+`"`)
		}
	})

	step(t, "an operator from either CA sets the policy", func(t *testing.T) {
		oldOps, oldOpsKey := lab.Cert(old, ca.RoleOps, "alice")
		e.ApplyAs(t, oldOps, oldOpsKey, "sites:\n  "+site+":\n    access_log: true\n")
		e.Apply(t, "sites:\n  "+site+":\n    access_log: false\n")
	})

	step(t, "a third CA's certificates are refused", func(t *testing.T) {
		third := lab.PKI(t, t.TempDir())
		crt, key := lab.Cert(third, ca.RoleNode, "node1")
		for _, proto := range []string{"wss", "quic"} {
			assert.Error(t, vm.Login(t, proto, e.Roots, crt, key), proto)
		}
		opsCrt, opsKey := lab.Cert(third, ca.RoleOps, "alice")
		_, _, err := lab.Get(vm.Client(t, e.Roots, opsCrt, opsKey), lab.OpsURL+"status")
		assert.Error(t, err, "ops API")
	})

	step(t, "an edge baked with the new CA alone refuses the old one's", func(t *testing.T) {
		e2 := lab.BootEdge(t, lab.EdgeOptions{PKI: e.PKI})
		for _, proto := range []string{"wss", "quic"} {
			assert.Error(t, e2.VM.Login(t, proto, e2.Roots, oldCrt, oldKey), "old CA, %s", proto)
			assert.NoError(t, e2.VM.Login(t, proto, e2.Roots, newCrt, newKey), "new CA, %s", proto)
		}
		oldOps, oldOpsKey := lab.Cert(old, ca.RoleOps, "alice")
		_, _, err := lab.Get(e2.VM.Client(t, e2.Roots, oldOps, oldOpsKey), lab.OpsURL+"status")
		assert.Error(t, err, "the old CA's operator")
	})
}

// fingerprint is the SHA-256 of the CA in pki.
func fingerprint(t *testing.T, pki string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	require.NoError(t, err)
	cas, err := ca.ParseCAs(b)
	require.NoError(t, err)
	return ca.Fingerprint(cas[0])
}
