package httpsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/fatedier/frp/pkg/util/vhost"
)

// certPEM is a self-signed certificate for name valid until notAfter, and
// its key, as certmagic stores them.
func certPEM(t *testing.T, name string, notAfter time.Time) (crt, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{name},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// A certificate still valid on the disk makes its name answerable after a
// boot, before any dark node publishes it; an expired one, the tunnel's,
// and names with no certificate stay silent.
func TestLoadHeld(t *testing.T) {
	ctx := context.Background()
	store := &certmagic.FileStorage{Path: t.TempDir()}
	magic := certmagic.New(certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, nil },
	}), certmagic.Config{Storage: store})
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{CA: "https://acme.example/dir"})
	magic.Issuers = []certmagic.Issuer{issuer}
	put := func(name string, until time.Time) {
		crt, key := certPEM(t, name, until)
		k := issuer.IssuerKey()
		if err := store.Store(ctx, certmagic.StorageKeys.SiteCert(k, name), crt); err != nil {
			t.Fatal(err)
		}
		if err := store.Store(ctx, certmagic.StorageKeys.SitePrivateKey(k, name), key); err != nil {
			t.Fatal(err)
		}
	}
	put("app.example.com", time.Now().Add(24*time.Hour))
	put("old.example.com", time.Now().Add(-time.Hour))
	put("tunnel.example.com", time.Now().Add(24*time.Hour))

	d := NewDomains("tunnel.example.com")
	d.SetTunnelGrace(10 * time.Minute)
	d.loadHeld(ctx, magic)
	if len(d.held) != 1 || d.held["app.example.com"].cert == nil {
		t.Fatalf("held %v", d.held)
	}
	if name, ok := d.Route("App.Example.com."); !ok || name != "app.example.com" || !d.Known("app.example.com") {
		t.Fatalf("app: route %q %v", name, ok)
	}
	for _, name := range []string{"old.example.com", "other.example.com"} {
		if d.Known(name) {
			t.Errorf("%s is known", name)
		}
	}
	if d.Allowed("app.example.com") {
		t.Fatal("a held name may have a certificate issued")
	}
	d.magic = magic
	c, err := d.certificate(&tls.ClientHelloInfo{ServerName: "app.example.com"})
	if err != nil || c != d.held["app.example.com"].cert {
		t.Fatalf("certificate: %v", err)
	}
	if _, err := d.certificate(&tls.ClientHelloInfo{ServerName: "old.example.com"}); err == nil {
		t.Fatal("an expired name got a certificate")
	}

	// Once tunnel_grace is up, or with none, the name is silent again.
	h := d.held["app.example.com"]
	h.since = time.Now().Add(-11 * time.Minute)
	d.held["app.example.com"] = h
	if d.Known("app.example.com") {
		t.Fatal("known past its grace")
	}
	h.since = time.Now()
	d.held["app.example.com"] = h
	d.SetTunnelGrace(0)
	if d.Known("app.example.com") {
		t.Fatal("known with tunnel_grace 0")
	}
}

// A site no tunnel carries is answered 503 with Retry-After, counted as
// no_tunnel, and its access line says so.
func TestNoTunnelIs503(t *testing.T) {
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ProxyError(r, &vhost.ProxyError{Stage: vhost.StageRoute, Err: vhost.ErrNoRouteFound})
		w.WriteHeader(http.StatusNotFound) // frps's answer for no route
	})
	st := &httpStats{}
	h, err := Handler("tunnel.example.com", frps, nil, nil, st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("status %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	s := st.site("app.example.com")
	if s.proxyErrors[reasonNoTunnel].Load() != 1 || s.status[5].Load() != 1 {
		t.Fatalf("no_tunnel %d, 5xx %d", s.proxyErrors[reasonNoTunnel].Load(), s.status[5].Load())
	}
}
