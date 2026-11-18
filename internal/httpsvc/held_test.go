package httpsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/fatedier/frp/pkg/util/vhost"

	"github.com/Sebiee/fortressedge/internal/config"
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
	if name, held, ok := d.Route("App.Example.com."); !ok || !held || name != "app.example.com" || !d.Known("app.example.com") {
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

// While a name's tunnel is away, its held name stays its own under
// another node's wildcard. The edge answers it 503 itself: frps would
// hand it to the wildcard's node, and the absent node's visitors with it,
// under the absent node's certificate.
func TestHeldNameIsNoWildcards(t *testing.T) {
	crt, key := certPEM(t, "app.example.com", time.Now().Add(24*time.Hour))
	c, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDomains("tunnel.example.com")
	d.SetTunnelGrace(10 * time.Minute)
	d.held = map[string]heldCert{"app.example.com": {&c, time.Now()}}
	d.Domain("*.example.com", true)
	var reached []string
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = append(reached, r.Host) })
	st := &httpStats{}
	h, err := Handler("tunnel.example.com", frps, nil, nil, st, d.Route, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]int{"app.example.com": http.StatusServiceUnavailable, "other.example.com": http.StatusOK} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", host, rec.Code, want)
		}
	}
	if len(reached) != 1 || reached[0] != "other.example.com" {
		t.Fatalf("frps got %v", reached)
	}
	if s := st.site("app.example.com"); s.proxyErrors[reasonNoTunnel].Load() != 1 {
		t.Fatalf("no_tunnel %d", s.proxyErrors[reasonNoTunnel].Load())
	}

	// Once the grace is up, or with none, the name is silent, not the
	// wildcard's: a connection still open for it, or a TLS session
	// resumed without a new certificate, would reach the wildcard's node.
	for _, grace := range []time.Duration{time.Nanosecond, 0} {
		d.SetTunnelGrace(grace)
		if d.Known("app.example.com") || !aborts(func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))
		}) {
			t.Errorf("tunnel_grace %v: the name is not silent", grace)
		}
	}
	if len(reached) != 1 {
		t.Fatalf("frps got %v", reached)
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
	h, err := Handler("tunnel.example.com", frps, nil, nil, st, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("status %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if c := rec.Header().Get("Connection"); c != "" {
		t.Fatalf("Connection %q from an edge no balancer checks, want none", c)
	}
	s := st.site("app.example.com")
	if s.proxyErrors[reasonNoTunnel].Load() != 1 || s.status[5].Load() != 1 {
		t.Fatalf("no_tunnel %d, 5xx %d", s.proxyErrors[reasonNoTunnel].Load(), s.status[5].Load())
	}
}

// balancedHandler is an edge behind a load balancer, by its policy's health
// check site: dark.example.com is held, with no tunnel to carry it, frps
// has no route for gone.example.com, and it answers every other site.
func balancedHandler(t *testing.T) http.Handler {
	t.Helper()
	p, err := config.ParsePolicy([]byte("sites:\n  check.example.com:\n    health_check: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostname(r.Host) == "gone.example.com" {
			ProxyError(r, &vhost.ProxyError{Stage: vhost.StageRoute, Err: vhost.ErrNoRouteFound})
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, "ok")
	})
	route := func(host string) (string, bool, bool) { return host, host == "dark.example.com", true }
	h, err := Handler("tunnel.example.com", frps, nil, nil, &httpStats{}, route, newLivePolicy(p), nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Behind a load balancer, the 503 for a site no tunnel carries closes the
// visitor's connection; a site that is carried keeps it, and an upgrade is
// left to its own Connection header.
func TestNoTunnelClosesTheConnectionBehindABalancer(t *testing.T) {
	h := balancedHandler(t)
	for _, tc := range []struct {
		host     string
		upgrade  bool
		status   int
		wantConn string
	}{
		{"dark.example.com", false, http.StatusServiceUnavailable, "close"},
		{"dark.example.com", true, http.StatusServiceUnavailable, ""},
		{"gone.example.com", false, http.StatusServiceUnavailable, "close"},
		{"app.example.com", false, http.StatusOK, ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
		if tc.upgrade {
			req.Header.Set("Connection", "keep-alive, Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if c := rec.Header().Get("Connection"); rec.Code != tc.status || c != tc.wantConn {
			t.Errorf("%s (upgrade %v): %d, Connection %q; want %d, %q", tc.host, tc.upgrade, rec.Code, c, tc.status, tc.wantConn)
		}
	}
}

// On a real listener: a visitor's connection is kept from one request to
// the next, until a request on it finds no tunnel. The request after that
// one arrives on a new connection, which a balancer gives to another edge.
// HTTP/2 says so with GOAWAY, which the client may read a moment after the
// response.
func TestNoTunnelSendsTheVisitorToANewConnection(t *testing.T) {
	overHTTP1And2(t, balancedHandler(t), func(t *testing.T, url string, c *http.Client) {
		get := func(host string) (status int, reused bool) {
			t.Helper()
			ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
			})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = host
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return resp.StatusCode, reused
		}
		if status, _ := get("app.example.com"); status != http.StatusOK {
			t.Fatalf("a site: %d", status)
		}
		if status, reused := get("app.example.com"); status != http.StatusOK || !reused {
			t.Fatalf("a site again: %d, connection reused %v; want it kept", status, reused)
		}
		if status, reused := get("dark.example.com"); status != http.StatusServiceUnavailable || !reused {
			t.Fatalf("a site without a tunnel: %d, connection reused %v; want 503 on the open connection", status, reused)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			status, reused := get("app.example.com")
			if status != http.StatusOK {
				t.Fatalf("a site, after the 503: %d", status)
			}
			if !reused {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("the visitor's connection stayed open after the 503")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}
