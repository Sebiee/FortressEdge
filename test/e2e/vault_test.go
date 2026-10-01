//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/certstore"
	"github.com/Sebiee/fortressedge/internal/certstore/vaulttest"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// Two edges for the same names share their certificates through Vault's
// KV v2 (fortress.yml's vault). The second edge starts with the first's
// certificate instead of ordering its own. When an edge does order, the
// CA's TLS-ALPN validation may reach the other edge, which answers it
// from the shared store: here Pebble validates against the first edge
// only. With Vault down, an edge boots and serves from its own disk.
func TestEdgesShareCertificatesThroughVault(t *testing.T) {
	t.Parallel()
	vault, err := vaulttest.Start("127.0.0.1:0", "edge-certs", "test/private")
	require.NoError(t, err)
	t.Cleanup(vault.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(vault.URL, "https://"))
	// On QEMU's user-mode network, the guest reaches this host at 10.0.2.2.
	conf := "vault: https://10.0.2.2:" + port + "\n" +
		"vault_mount: edge-certs\nvault_path: test/private\n" +
		"vault_role_id: " + vault.RoleID + "\nvault_secret_id: " + vault.SecretID + "\n" +
		"vault_ca: |\n" + lab.Indent(vault.CA)
	tunnelCert := func() bool {
		return slices.ContainsFunc(vault.Keys(), func(k string) bool {
			return strings.HasSuffix(k, "/"+lab.Tunnel+"/"+lab.Tunnel+".crt")
		})
	}

	a := lab.BootEdge(t, lab.EdgeOptions{Config: conf})
	require.True(t, tunnelCert(), "the tunnel certificate is not in Vault: %v", vault.Keys())
	first := lab.Serial(t, a.Ops, lab.OpsURL+"status")

	// The parent test owns it: a subtest's cleanup would stop it.
	b := lab.BootEdge(t, lab.EdgeOptions{Config: conf, SharePebble: a.Pebble})
	step(t, "a second edge starts with the first's certificate", func(t *testing.T) {
		assert.Equal(t, first, lab.Serial(t, b.Ops, lab.OpsURL+"status"))
		assert.Equal(t, []string{lab.Tunnel}, a.Pebble.Issued(), "ordered again")
		st := certStore(t, b)
		assert.Equal(t, true, st["reachable"])
	})

	step(t, "an edge that orders is validated through the other", func(t *testing.T) {
		b.VM.PowerDown(t)
		v, err := certstore.NewVault(certstore.VaultConfig{URL: vault.URL, CA: vault.CA, Mount: vault.Mount, Path: vault.Path,
			RoleID: vault.RoleID, SecretID: vault.SecretID})
		require.NoError(t, err)
		require.NoError(t, v.Delete(context.Background(), "certificates"))
		require.False(t, tunnelCert())
		blank(t, filepath.Join(b.Dir, "data.img"))
		b.VM.Restart(t)
		b.WaitUp(t)
		second := lab.Serial(t, b.Ops, lab.OpsURL+"status")
		assert.NotEqual(t, first, second)
		assert.Equal(t, []string{lab.Tunnel, lab.Tunnel}, a.Pebble.Issued())
		assert.Zero(t, a.Pebble.Invalid(), "a validation failed: the first edge did not answer the second's challenge")
		assert.True(t, tunnelCert())
	})

	step(t, "with Vault down, an edge boots from its disk", func(t *testing.T) {
		serial := lab.Serial(t, b.Ops, lab.OpsURL+"status")
		restart := func() time.Duration {
			b.VM.PowerDown(t)
			start := time.Now()
			b.VM.Restart(t)
			b.WaitUp(t)
			return time.Since(start)
		}
		up := restart()
		vault.SetDown(true)
		down := restart()
		t.Logf("up %s after a restart with Vault up, %s with it down", up.Round(time.Millisecond), down.Round(time.Millisecond))
		assert.Less(t, down, up+2*time.Second, "Vault being down held the boot")
		assert.Equal(t, serial, lab.Serial(t, b.Ops, lab.OpsURL+"status"))
		st := certStore(t, b)
		assert.Equal(t, false, st["reachable"])
		assert.NotEmpty(t, st["last_error"])
		_, body, err := lab.Get(b.Ops, lab.OpsURL+"metrics")
		require.NoError(t, err)
		assert.Contains(t, body, "fortressedge_cert_store_errors_total{op=")

		vault.SetDown(false)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Equal(c, true, certStore(c, b)["reachable"])
		}, 2*time.Minute, time.Second)
	})
}

func certStore(t require.TestingT, e *lab.Edge) map[string]any {
	e.Ops.CloseIdleConnections()
	_, body, err := lab.Get(e.Ops, lab.OpsURL+"status")
	require.NoError(t, err)
	var st struct {
		CertStore map[string]any `json:"cert_store"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &st), body)
	require.NotNil(t, st.CertStore, "no cert_store in the status")
	return st.CertStore
}

// blank empties a powered-off VM's data disk: the edge formats it.
func blank(t *testing.T, disk string) {
	t.Helper()
	require.NoError(t, os.Truncate(disk, 0))
	require.NoError(t, os.Truncate(disk, 64<<20))
}
