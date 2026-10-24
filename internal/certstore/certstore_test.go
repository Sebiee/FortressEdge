package certstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	vault "github.com/hashicorp/vault/api"

	"github.com/Sebiee/fortressedge/internal/certstore/vaulttest"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

func fakeVault(t *testing.T) *vaulttest.Server {
	t.Helper()
	srv, err := vaulttest.Start("127.0.0.1:0", "edge-certs", "test/private")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func client(t *testing.T, srv *vaulttest.Server) *Vault {
	t.Helper()
	v, err := NewVault(VaultConfig{URL: srv.URL, CA: srv.CA, Mount: srv.Mount, Path: srv.Path, RoleID: srv.RoleID, SecretID: srv.SecretID})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestVaultStorage(t *testing.T) {
	ctx := context.Background()
	srv := fakeVault(t)
	v := client(t, srv)
	crt := []byte("-----BEGIN CERTIFICATE-----\n\x00\xff binary too\n")
	must(t, v.Store(ctx, "certificates/ca/a.example.com/a.example.com.crt", crt))
	must(t, v.Store(ctx, "certificates/ca/a.example.com/a.example.com.key", []byte("key")))
	must(t, v.Store(ctx, "acme/ca/users/default/default.key", []byte("account")))

	got, err := v.Load(ctx, "certificates/ca/a.example.com/a.example.com.crt")
	must(t, err)
	if !bytes.Equal(got, crt) {
		t.Fatalf("load: %q", got)
	}
	if _, err := v.Load(ctx, "certificates/ca/b.example.com/b.example.com.crt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if keys := srv.Keys(); !slices.Contains(keys, "test/private/certificates/ca/a.example.com/a.example.com.crt") {
		t.Fatalf("not under the path: %v", keys)
	}

	keys, err := v.List(ctx, "certificates", false)
	must(t, err)
	if !slices.Equal(keys, []string{"certificates/ca"}) {
		t.Fatalf("list: %v", keys)
	}
	keys, err = v.List(ctx, "certificates", true)
	must(t, err)
	want := []string{"certificates/ca", "certificates/ca/a.example.com",
		"certificates/ca/a.example.com/a.example.com.crt", "certificates/ca/a.example.com/a.example.com.key"}
	if !slices.Equal(keys, want) {
		t.Fatalf("recursive list: %v", keys)
	}

	info, err := v.Stat(ctx, "certificates/ca/a.example.com/a.example.com.key")
	must(t, err)
	if !info.IsTerminal || time.Since(info.Modified) > time.Minute {
		t.Fatalf("stat: %+v", info)
	}
	info, err = v.Stat(ctx, "certificates/ca")
	if err != nil || info.IsTerminal {
		t.Fatalf("a directory: %+v %v", info, err)
	}
	if v.Exists(ctx, "certificates/nothing") {
		t.Fatal("exists")
	}

	must(t, v.Delete(ctx, "certificates/ca/a.example.com"))
	if keys := srv.Keys(); len(keys) != 1 || !strings.HasSuffix(keys[0], "default.key") {
		t.Fatalf("after deleting a directory: %v", keys)
	}
	for _, bad := range []string{"", "../x", "a/../../x", "_locks/x"} {
		if err := v.Store(ctx, bad, nil); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
}

func TestVaultLogsInAgain(t *testing.T) {
	ctx := context.Background()
	srv := fakeVault(t)
	v := client(t, srv)
	must(t, v.Store(ctx, "a", []byte("1")))
	srv.RevokeTokens()
	_, err := v.Load(ctx, "a")
	must(t, err)
	if n := srv.Logins.Load(); n != 2 {
		t.Fatalf("%d logins, want 2", n)
	}
}

func TestVaultRefusesAnotherCA(t *testing.T) {
	srv := fakeVault(t)
	other := fakeVault(t)
	v, err := NewVault(VaultConfig{URL: srv.URL, CA: other.CA, Mount: srv.Mount, Path: srv.Path, RoleID: srv.RoleID, SecretID: srv.SecretID})
	must(t, err)
	if err := v.Store(context.Background(), "a", nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a server the CA did not sign: %v", err)
	}
	if srv.Logins.Load() != 0 {
		t.Fatal("logged in")
	}
}

func TestVaultLocks(t *testing.T) {
	ctx := context.Background()
	srv := fakeVault(t)
	a, b := client(t, srv), client(t, srv)
	must(t, a.Lock(ctx, "issue_cert_a.example.com"))

	short, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	if err := b.Lock(short, "issue_cert_a.example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("b took a's lock: %v", err)
	}
	must(t, b.Lock(ctx, "other"))
	must(t, a.Unlock(ctx, "issue_cert_a.example.com"))
	must(t, b.Lock(ctx, "issue_cert_a.example.com"))

	// b dies holding it: once it expires, a takes it over, and b's
	// unlock does not release a's.
	b.locksMu.Lock()
	held := b.locks["issue_cert_a.example.com"]
	b.locksMu.Unlock()
	held.cancel()
	<-held.done
	p := b.lockPath("issue_cert_a.example.com")
	cur, err := b.kv.Get(ctx, p)
	must(t, err)
	_, err = b.kv.Put(ctx, p, map[string]any{"expires": time.Now().Add(-time.Second).Unix()}, vault.WithCheckAndSet(cur.VersionMetadata.Version))
	must(t, err)
	must(t, a.Lock(ctx, "issue_cert_a.example.com"))
	must(t, b.Unlock(ctx, "issue_cert_a.example.com"))
	if !slices.Contains(srv.Keys(), "test/private/_locks/issue_cert_a.example.com") {
		t.Fatal("b's unlock released a's lock")
	}
	must(t, a.Unlock(ctx, "issue_cert_a.example.com"))
	if slices.Contains(srv.Keys(), "test/private/_locks/issue_cert_a.example.com") {
		t.Fatal("a's unlock left the lock")
	}
	if keys, _ := a.List(ctx, "", false); slices.Contains(keys, "_locks") {
		t.Fatalf("locks listed: %v", keys)
	}
}

// meta is a certificate's metadata, whose value only has to be JSON.
const meta = "certificates/ca/x.example.com/x.example.com.json"

var v1, v2 = []byte(`{"v":1}`), []byte(`{"v":2}`)

func newDisk(t *testing.T) *certmagic.FileStorage {
	return &certmagic.FileStorage{Path: t.TempDir()}
}

func shared(t *testing.T, srv *vaulttest.Server) (*Shared, *certmagic.FileStorage) {
	t.Helper()
	disk := newDisk(t)
	s := NewShared(disk, client(t, srv))
	s.Seed(context.Background())
	return s, disk
}

func TestSharedReadsTheStoreFirst(t *testing.T) {
	ctx := context.Background()
	srv := fakeVault(t)
	a, diskA := shared(t, srv)
	b, diskB := shared(t, srv)

	must(t, a.Store(ctx, meta, v1))
	if v, err := diskA.Load(ctx, meta); err != nil || !bytes.Equal(v, v1) {
		t.Fatalf("a's disk: %q %v", v, err)
	}
	// b gets a's certificate, and keeps a copy.
	if v, err := b.Load(ctx, meta); err != nil || !bytes.Equal(v, v1) {
		t.Fatalf("b: %q %v", v, err)
	}
	if v, err := diskB.Load(ctx, meta); err != nil || !bytes.Equal(v, v1) {
		t.Fatalf("b's disk: %q %v", v, err)
	}
	// a renews it: b reads the new one, not its copy.
	must(t, a.Store(ctx, meta, v2))
	if v, _ := b.Load(ctx, meta); !bytes.Equal(v, v2) {
		t.Fatalf("b after a's renewal: %q", v)
	}
	// a deletes it: b's copy does not bring it back.
	must(t, a.Delete(ctx, meta))
	if _, err := b.Load(ctx, meta); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("b after a's delete: %v", err)
	}
	if keys, _ := b.List(ctx, "certificates", true); len(keys) != 0 {
		t.Fatalf("b lists %v", keys)
	}
}

func TestSharedServesFromDiskWhileTheStoreIsDown(t *testing.T) {
	old := downFor
	downFor = 300 * time.Millisecond
	t.Cleanup(func() { downFor = old })
	ctx := context.Background()
	srv := fakeVault(t)
	a, _ := shared(t, srv)
	b, _ := shared(t, srv)
	must(t, a.Store(ctx, meta, v1))
	if _, err := b.Load(ctx, meta); err != nil {
		t.Fatal(err)
	}

	srv.SetDown(true)
	start := time.Now()
	if v, err := b.Load(ctx, meta); err != nil || !bytes.Equal(v, v1) {
		t.Fatalf("down: %q %v", v, err)
	}
	calls := srv.Calls.Load()
	for range 5 {
		if _, err := b.Load(ctx, meta); err != nil {
			t.Fatal(err)
		}
	}
	if srv.Calls.Load() != calls || time.Since(start) > 5*time.Second {
		t.Fatal("asked the store again while it was down")
	}
	// b renews by itself, under the disk's lock.
	must(t, b.Lock(ctx, "issue_cert_x"))
	must(t, b.Store(ctx, meta, v2))
	must(t, b.Unlock(ctx, "issue_cert_x"))
	if v, _ := b.Load(ctx, meta); !bytes.Equal(v, v2) {
		t.Fatalf("its own renewal: %q", v)
	}
	st := b.Status()
	if st["reachable"] != false || st["pending"] != 1 || st["errors"].(map[string]int64)["load"] != 1 {
		t.Fatalf("status: %v", st)
	}

	srv.SetDown(false)
	time.Sleep(downFor)
	b.flush(ctx)
	if v, err := a.Load(ctx, meta); err != nil || !bytes.Equal(v, v2) {
		t.Fatalf("a after b's renewal was written: %q %v", v, err)
	}
	if b.Status()["pending"] != 0 {
		t.Fatal("still pending")
	}
	var buf bytes.Buffer
	w := metrics.NewWriter(&buf)
	b.WriteMetrics(w)
	must(t, w.Flush())
	for _, want := range []string{`fortressedge_cert_store_errors_total{op="load"} 1`, "fortressedge_cert_store_pending 0",
		"fortressedge_cert_store_last_success_timestamp_seconds "} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, buf.String())
		}
	}
}

// pair is a certificate for name, valid from from to until, and its key,
// as certmagic stores them.
func pair(t *testing.T, name string, from, until time.Time) (crt, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: from, NotAfter: until}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	must(t, err)
	kd, err := x509.MarshalECPrivateKey(k)
	must(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// What Vault holds is checked before an edge copies it to its disk or
// uses it, since every edge on the path trusts it: a value too large to
// be a certificate, a key that is not the certificate's, a certificate for
// another name or outside its dates, or metadata that is not JSON. The
// edge keeps its disk's copy instead, and without one, the load fails.
func TestSharedRefusesWhatItCannotUse(t *testing.T) {
	ctx := context.Background()
	srv := fakeVault(t)
	other := client(t, srv) // anyone with the AppRole
	s, disk := shared(t, srv)
	const site = "certificates/ca/app.example.com/app.example.com"
	now := time.Now()
	crt, key := pair(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	good := map[string][]byte{".crt": crt, ".key": key, ".json": []byte(`{"sans":["app.example.com"]}`)}
	for ext, v := range good {
		must(t, s.Store(ctx, site+ext, v))
	}

	_, strayKey := pair(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	otherCrt, otherKey := pair(t, "other.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	oldCrt, oldKey := pair(t, "app.example.com", now.Add(-2*time.Hour), now.Add(-time.Hour))
	newCrt, newKey := pair(t, "app.example.com", now.Add(time.Hour), now.Add(2*time.Hour))
	for _, tc := range []struct {
		name string
		bad  map[string][]byte
	}{
		{"too large", map[string][]byte{".json": []byte(`"` + strings.Repeat("A", 1<<20) + `"`)}},
		{"another key", map[string][]byte{".key": strayKey}},
		{"another name", map[string][]byte{".crt": otherCrt, ".key": otherKey}},
		{"expired", map[string][]byte{".crt": oldCrt, ".key": oldKey}},
		{"not yet valid", map[string][]byte{".crt": newCrt, ".key": newKey}},
		{"not a certificate", map[string][]byte{".crt": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")}},
		{"metadata", map[string][]byte{".json": []byte("{")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for ext, v := range good {
				must(t, other.Store(ctx, site+ext, v))
			}
			for ext, v := range tc.bad {
				must(t, other.Store(ctx, site+ext, v))
			}
			for ext, want := range good {
				if got, err := s.Load(ctx, site+ext); err != nil || !bytes.Equal(got, want) {
					t.Errorf("load %s: %v", ext, err)
				}
				if got, err := disk.Load(ctx, site+ext); err != nil || !bytes.Equal(got, want) {
					t.Errorf("disk %s: %v", ext, err)
				}
			}
			fresh, freshDisk := shared(t, srv)
			for ext := range tc.bad {
				if v, err := fresh.Load(ctx, site+ext); err == nil {
					t.Errorf("an edge without a copy loads %s: %.40q", ext, v)
				}
				if freshDisk.Exists(ctx, site+ext) {
					t.Errorf("%s written to the disk", ext)
				}
			}
		})
	}

	// A certificate another edge renewed is taken, with its key, even from
	// a CA whose clock is a little ahead.
	crt2, key2 := pair(t, "app.example.com", now.Add(time.Minute), now.Add(time.Hour))
	must(t, other.Store(ctx, site+".key", key2))
	must(t, other.Store(ctx, site+".crt", crt2))
	if got, err := s.Load(ctx, site+".crt"); err != nil || !bytes.Equal(got, crt2) {
		t.Fatalf("renewed: %v", err)
	}
	if got, _ := disk.Load(ctx, site+".key"); !bytes.Equal(got, key2) {
		t.Fatal("the renewed certificate's key is not on the disk with it")
	}
}

// A Vault that hangs answers no TLS handshake: the edge serves from its
// disk after two seconds, not after a whole request timeout.
func TestSharedGivesUpOnASilentVaultFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer ln.Close()
	// It never accepts: the kernel completes the TCP handshake, and then
	// nothing answers.
	v, err := NewVault(VaultConfig{URL: "https://" + ln.Addr().String(), Mount: "m", Path: "p", RoleID: "r", SecretID: "s"})
	must(t, err)
	disk := newDisk(t)
	ctx := context.Background()
	must(t, disk.Store(ctx, "certificates/ca/x/x.crt", []byte("mine")))
	s := NewShared(disk, v)
	start := time.Now()
	s.Seed(ctx)
	got, err := s.Load(ctx, "certificates/ca/x/x.crt")
	if err != nil || string(got) != "mine" {
		t.Fatalf("%q %v", got, err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("took %s", took)
	}
}

// An edge that kept its certificates on disk shares them when it starts
// using the store, rather than order them again; what it lacks, it gets.
func TestSharedSeedsTheStore(t *testing.T) {
	ctx := context.Background()
	srv := fakeVault(t)
	disk := &certmagic.FileStorage{Path: t.TempDir()}
	must(t, disk.Store(ctx, "certificates/ca/old/old.crt", []byte("mine")))
	s := NewShared(disk, client(t, srv))
	if v, err := s.Load(ctx, "certificates/ca/old/old.crt"); err != nil || string(v) != "mine" {
		t.Fatalf("before seeding: %q %v", v, err)
	}
	s.Seed(ctx)
	if v, ok := srv.Value("test/private/certificates/ca/old/old.crt"); !ok || v == nil {
		t.Fatalf("not shared: %v", srv.Keys())
	}
	if s.Status()["pending"] != 0 {
		t.Fatal("pending")
	}
}
