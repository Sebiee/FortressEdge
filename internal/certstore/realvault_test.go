package certstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// realVault runs `vault server -dev` from $VAULT_ITEST_BIN, set up as the
// platform does: a KV v2 mount, and an AppRole whose policy allows its
// path and nothing else. The tests that check what Vault itself does run
// against it too; without the variable, they use vaulttest alone.
type realVault struct {
	url, mount, path, roleID, secretID string
	ca                                 []byte
	root                               *vault.Client
}

func startRealVault(t *testing.T) *realVault {
	t.Helper()
	bin := os.Getenv("VAULT_ITEST_BIN")
	if bin == "" {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	addr := ln.Addr().String()
	ln.Close()
	dir := t.TempDir()
	cmd := exec.Command(bin, "server", "-dev", "-dev-root-token-id=root", "-dev-listen-address="+addr,
		"-dev-tls", "-dev-tls-cert-dir="+dir)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	rv := &realVault{url: "https://" + addr, mount: "edge-certs", path: "test/private"}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "vault-ca.pem")); err == nil && len(b) > 0 {
			rv.ca = b
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("vault -dev did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	cfg := vault.DefaultConfig()
	cfg.Address = rv.url
	must(t, cfg.ConfigureTLS(&vault.TLSConfig{CACertBytes: rv.ca}))
	root, err := vault.NewClient(cfg)
	must(t, err)
	root.SetToken("root")
	rv.root = root
	ctx := context.Background()
	must(t, root.Sys().MountWithContext(ctx, rv.mount, &vault.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}))
	must(t, root.Sys().EnableAuthWithOptionsWithContext(ctx, "approle", &vault.EnableAuthOptions{Type: "approle"}))
	policy := fmt.Sprintf(`
path "%[1]s/data/%[2]s/*"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "%[1]s/metadata/%[2]s/*" { capabilities = ["create", "read", "update", "delete", "list"] }
`, rv.mount, rv.path)
	must(t, root.Sys().PutPolicyWithContext(ctx, "edge", policy))
	_, err = root.Logical().WriteWithContext(ctx, "auth/approle/role/edge", map[string]any{
		"token_policies": "edge", "token_ttl": "1h", "token_max_ttl": "24h", "secret_id_num_uses": 0,
	})
	must(t, err)
	s, err := root.Logical().ReadWithContext(ctx, "auth/approle/role/edge/role-id")
	must(t, err)
	rv.roleID = s.Data["role_id"].(string)
	s, err = root.Logical().WriteWithContext(ctx, "auth/approle/role/edge/secret-id", nil)
	must(t, err)
	rv.secretID = s.Data["secret_id"].(string)
	return rv
}

func (rv *realVault) client(t *testing.T) *Vault {
	t.Helper()
	v, err := NewVault(VaultConfig{URL: rv.url, CA: rv.ca, Mount: rv.mount, Path: rv.path, RoleID: rv.roleID, SecretID: rv.secretID})
	must(t, err)
	return v
}

// keys lists every secret under the mount, as root sees it.
func (rv *realVault) keys(t *testing.T, dir string) []string {
	t.Helper()
	s, err := rv.root.Logical().List(rv.mount + "/metadata/" + dir)
	must(t, err)
	if s == nil {
		return nil
	}
	var out []string
	for _, k := range s.Data["keys"].([]any) {
		n := k.(string)
		if strings.HasSuffix(n, "/") {
			out = append(out, rv.keys(t, dir+n)...)
		} else {
			out = append(out, dir+n)
		}
	}
	slices.Sort(out)
	return out
}

// The same storage, locks, and sharing against a real Vault: what the
// fake answers is what Vault answers.
func TestAgainstRealVault(t *testing.T) {
	rv := startRealVault(t)
	if rv == nil {
		t.Skip("set VAULT_ITEST_BIN to a vault binary")
	}
	ctx := context.Background()
	v := rv.client(t)
	crt := []byte("-----BEGIN CERTIFICATE-----\n\x00\xff binary too\n")
	must(t, v.Store(ctx, "certificates/ca/a.example.com/a.example.com.crt", crt))
	must(t, v.Store(ctx, "certificates/ca/a.example.com/a.example.com.key", []byte("key")))
	must(t, v.Store(ctx, "acme/ca/users/default/default.key", []byte("account")))
	got, err := v.Load(ctx, "certificates/ca/a.example.com/a.example.com.crt")
	if err != nil || !bytes.Equal(got, crt) {
		t.Fatalf("load: %q %v", got, err)
	}
	if _, err := v.Load(ctx, "certificates/none"); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
	keys, err := v.List(ctx, "certificates", true)
	must(t, err)
	want := []string{"certificates/ca", "certificates/ca/a.example.com",
		"certificates/ca/a.example.com/a.example.com.crt", "certificates/ca/a.example.com/a.example.com.key"}
	if !slices.Equal(keys, want) {
		t.Fatalf("recursive list: %v", keys)
	}
	if info, err := v.Stat(ctx, "certificates/ca/a.example.com/a.example.com.key"); err != nil || !info.IsTerminal || time.Since(info.Modified) > time.Minute {
		t.Fatalf("stat: %+v %v", info, err)
	}
	if info, err := v.Stat(ctx, "certificates/ca"); err != nil || info.IsTerminal {
		t.Fatalf("stat of a directory: %+v %v", info, err)
	}
	must(t, v.Delete(ctx, "certificates/ca/a.example.com"))
	if k := rv.keys(t, rv.path+"/"); !slices.Equal(k, []string{rv.path + "/acme/ca/users/default/default.key"}) {
		t.Fatalf("after delete: %v", k)
	}

	// Outside the path: the policy refuses, as it must.
	if _, err := v.kv.Put(ctx, "other/x", map[string]any{"value": "x"}); err == nil {
		t.Fatal("wrote outside its path")
	}

	// Locks: check-and-set as Vault does it.
	a, b := rv.client(t), rv.client(t)
	must(t, a.Lock(ctx, "issue_cert_x"))
	short, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	if err := b.Lock(short, "issue_cert_x"); err == nil {
		t.Fatal("b took a's lock")
	}
	cancel()
	must(t, a.Unlock(ctx, "issue_cert_x"))
	must(t, b.Lock(ctx, "issue_cert_x"))
	b.locksMu.Lock()
	held := b.locks["issue_cert_x"]
	b.locksMu.Unlock()
	held.cancel()
	<-held.done
	p := b.lockPath("issue_cert_x")
	cur, err := b.kv.Get(ctx, p)
	must(t, err)
	_, err = b.kv.Put(ctx, p, map[string]any{"expires": time.Now().Add(-time.Second).Unix()}, vault.WithCheckAndSet(cur.VersionMetadata.Version))
	must(t, err)
	must(t, a.Lock(ctx, "issue_cert_x"))
	must(t, b.Unlock(ctx, "issue_cert_x"))
	if !slices.Contains(rv.keys(t, rv.path+"/"), rv.path+"/_locks/issue_cert_x") {
		t.Fatal("b's unlock released a's lock")
	}
	must(t, a.Unlock(ctx, "issue_cert_x"))
	if slices.Contains(rv.keys(t, rv.path+"/"), rv.path+"/_locks/issue_cert_x") {
		t.Fatal("unlock left the lock")
	}

	// A token Vault no longer knows: the client logs in again.
	_, err = rv.root.Logical().WriteWithContext(ctx, "sys/leases/revoke-prefix/auth/approle/login", nil)
	must(t, err)
	if _, err := v.Load(ctx, "acme/ca/users/default/default.key"); err != nil {
		t.Fatalf("after its token was revoked: %v", err)
	}

	// Two edges sharing it.
	ea := NewShared(newDisk(t), rv.client(t))
	eb := NewShared(newDisk(t), rv.client(t))
	ea.Seed(ctx)
	eb.Seed(ctx)
	must(t, ea.Store(ctx, "certificates/ca/s/s.crt", []byte("v1")))
	if got, err := eb.Load(ctx, "certificates/ca/s/s.crt"); err != nil || string(got) != "v1" {
		t.Fatalf("b: %q %v", got, err)
	}
	must(t, ea.Delete(ctx, "certificates/ca/s/s.crt"))
	if _, err := eb.Load(ctx, "certificates/ca/s/s.crt"); !os.IsNotExist(err) {
		t.Fatalf("b after a's delete: %v", err)
	}
}
