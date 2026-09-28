package httpsvc

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/Sebiee/fortressedge/internal/config"
)

func TestHostForwardedToVhost(t *testing.T) {
	var gotHost, gotXFF, gotReal, gotProto, gotFwdHost string
	vhost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotReal = r.Header.Get("X-Real-IP")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotFwdHost = r.Header.Get("X-Forwarded-Host")
		io.WriteString(w, "ok")
	}))
	t.Cleanup(vhost.Close)

	h, err := Handler("tunnel.example.com", vhost.Config.Handler, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTestServer(t, h)
	req, _ := http.NewRequest(http.MethodGet, "http://app.example.com/x", nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.Header.Set("X-Real-IP", "9.9.9.9")
	res, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
	if gotHost != "app.example.com" {
		t.Fatalf("upstream Host = %q", gotHost)
	}
	if gotXFF == "" || gotXFF == "9.9.9.9" {
		t.Fatalf("X-Forwarded-For=%q (spoof should be replaced)", gotXFF)
	}
	if gotReal == "" || gotReal == "9.9.9.9" {
		t.Fatalf("X-Real-IP=%q", gotReal)
	}
	if gotProto != "http" {
		t.Fatalf("X-Forwarded-Proto=%q", gotProto)
	}
	if gotFwdHost != "app.example.com" {
		t.Fatalf("X-Forwarded-Host=%q", gotFwdHost)
	}
}

func TestUnroutedHostGetsNoResponse(t *testing.T) {
	var hits atomic.Int32
	vhost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(vhost.Close)
	routed := func(host string) bool { return host == "app.example.com" }
	h, err := Handler("tunnel.example.com", vhost.Config.Handler, nil, nil, nil, routed, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr := serving(t, h)
	for _, host := range []string{"new.example.com", "192.0.2.1", ""} {
		if b := rawHTTP(t, addr, host); len(b) != 0 {
			t.Fatalf("host %q got %q, want a silent close", host, b)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("an unrouted host reached vhost")
	}
	if b := rawHTTP(t, addr, "App.Example.com."); !strings.HasPrefix(string(b), "HTTP/1.0 200") {
		t.Fatalf("routed host got %q", b)
	}
	if hits.Load() != 1 {
		t.Fatal("a routed host did not reach vhost")
	}
}

// rawHTTP sends one HTTP/1.0 GET with host as the Host header and returns
// every byte the server sent back before closing.
func rawHTTP(t *testing.T, addr, host string) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("host %q: %v", host, err)
	}
	return b
}

// aborts reports whether fn panics with http.ErrAbortHandler, which is how
// a handler closes the connection without a response.
func aborts(fn func()) (ok bool) {
	defer func() { ok = recover() == http.ErrAbortHandler }()
	fn()
	return false
}

func TestTunnelWebsocketPath(t *testing.T) {
	vhostHit := false
	vhost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vhostHit = true
	}))
	t.Cleanup(vhost.Close)
	var gotPath string
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.WriteString(w, "frp")
	}))
	t.Cleanup(control.Close)

	h, err := Handler("tunnel.example.com", vhost.Config.Handler, control.Config.Handler, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTestServer(t, h)
	client := front.Client()

	req, _ := http.NewRequest(http.MethodGet, "http://tunnel.example.com"+config.FrpWebsocketPath, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "frp" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
	if gotPath != config.FrpWebsocketPath {
		t.Fatalf("path %q", gotPath)
	}
	if vhostHit {
		t.Fatal("tunnel request hit vhost")
	}

	req, _ = http.NewRequest(http.MethodGet, "http://tunnel.example.com/", nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("tunnel / status=%d", res.StatusCode)
	}
}

func TestOpsPathStaysOnTunnelHost(t *testing.T) {
	vhost := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(vhost.Close)
	opsHit := false
	opsH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opsHit = true
		io.WriteString(w, "ops")
	})
	h, err := Handler("tunnel.example.com", vhost.Config.Handler, nil, opsH, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTestServer(t, h)
	client := front.Client()

	req, _ := http.NewRequest(http.MethodGet, "http://tunnel.example.com"+config.OpsLogsPath, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !opsHit || res.StatusCode != 200 {
		t.Fatalf("ops on tunnel host: hit=%v status=%d", opsHit, res.StatusCode)
	}

	// Site hosts never see the ops API; their /~!ops/* goes to the vhost.
	opsHit = false
	req, _ = http.NewRequest(http.MethodGet, "http://app.example.com"+config.OpsLogsPath, nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if opsHit || res.StatusCode != 404 {
		t.Fatalf("ops on site host: hit=%v status=%d", opsHit, res.StatusCode)
	}
}

func TestDrainCompletesInFlightHTTP(t *testing.T) {
	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, "ok")
	})
	s, track, addr := serving(t, h)

	got := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		res, err := http.Get("http://" + addr + "/")
		if err != nil {
			errc <- err
			return
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			errc <- err
			return
		}
		got <- string(body)
	}()
	<-started
	drain([]*http.Server{s}, track, 2*time.Second)
	select {
	case err := <-errc:
		t.Fatal(err)
	case body := <-got:
		if body != "ok" {
			t.Fatalf("body=%q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	_, err := http.Get("http://" + addr + "/")
	if err == nil {
		t.Fatal("accepted after drain")
	}
}

func TestDrainClosesHijacked(t *testing.T) {
	ready := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		_, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()
		close(ready)
	})
	s, track, addr := serving(t, h)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 101 {
		t.Fatalf("status=%d", res.StatusCode)
	}
	<-ready
	drain([]*http.Server{s}, track, time.Second)
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("hijacked conn still open")
	}
}

// A closed connection leaves the count, hijacked or not. net/http never
// reports a hijacked connection as closed.
func TestConnsForgetClosed(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			io.WriteString(w, "ok")
			return
		}
		c, bufrw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		bufrw.Flush()
		_, _ = io.Copy(io.Discard, bufrw)
	})
	s, track, addr := serving(t, h)
	t.Cleanup(func() { _ = s.Close() })

	ws, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(ws, "GET / HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(ws), nil)
	if err != nil || res.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", res, err)
	}
	client := &http.Client{Transport: &http.Transport{}}
	res, err = client.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if n := track.Len(); n != 2 {
		t.Fatalf("open: %d, want 2", n)
	}
	ws.Close()
	client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for track.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("still counted: %d", track.Len())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDrainTimeoutCutsSlowHTTP(t *testing.T) {
	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(5 * time.Second)
		io.WriteString(w, "late")
	})
	s, track, addr := serving(t, h)

	errc := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		_, err := client.Get("http://" + addr + "/")
		errc <- err
	}()
	<-started
	start := time.Now()
	drain([]*http.Server{s}, track, 100*time.Millisecond)
	if time.Since(start) > time.Second {
		t.Fatal("drain hung past timeout")
	}
	if err := <-errc; err == nil {
		t.Fatal("slow request survived drain timeout")
	}
}

func TestServeDrainsOnCancel(t *testing.T) {
	started := make(chan struct{})
	track := newConns()
	s := newServer("127.0.0.1:0", http.NotFoundHandler(), nil)
	s.BaseContext = func(net.Listener) context.Context {
		close(started)
		return context.Background()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, []*http.Server{s}, track, nil, time.Second) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not return")
	}
}

// blockingIssuer never issues. Issue returns once the obtain is cancelled.
type blockingIssuer struct{ started, done chan struct{} }

func (blockingIssuer) IssuerKey() string { return "blocking" }

func (b blockingIssuer) Issue(ctx context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	close(b.started)
	<-ctx.Done()
	close(b.done)
	return nil, ctx.Err()
}

func TestDomainsObtainInTheBackground(t *testing.T) {
	d := NewDomains("Tunnel.Example.com.")
	iss := blockingIssuer{started: make(chan struct{}), done: make(chan struct{})}
	d.setMagic(testMagic(t, iss, time.Hour))
	if !d.Allowed("tunnel.example.com") || d.Allowed("app.example.com") {
		t.Fatal("Allowed")
	}
	// Routed but never issued: a wildcard, a catch-all, an address.
	d.Domain("*.example.com", true)
	d.Domain("*", true)
	d.Domain("192.0.2.10", true)
	if d.Allowed("*.example.com") || d.Allowed("192.0.2.10") {
		t.Fatal("a name that cannot be issued is allowed")
	}
	// frps holds its router lock across this call; the obtain must not.
	returned := make(chan struct{})
	go func() {
		d.Domain("App.Example.com:443", true)
		close(returned)
	}()
	within(t, returned, "Domain blocked on the obtain")
	within(t, iss.started, "no obtain for a new name")
	if !d.Allowed("app.example.com.") {
		t.Fatal("registered name")
	}
	d.Domain("app.example.com", false)
	within(t, iss.done, "removing the name did not cancel its obtain")
	if d.Allowed("app.example.com") {
		t.Fatal("removed name")
	}
	if _, err := d.certificate(helloFor("app.example.com")); err == nil {
		t.Fatal("expected no certificate")
	}
}

func TestDomainsStopRenewingANameThatLeft(t *testing.T) {
	iss := &testIssuer{lifetime: func(int) (time.Duration, time.Duration) { return 0, time.Hour }}
	magic, cache := testMagic(t, iss, time.Hour)
	d := NewDomains("tunnel.example.com")
	d.setMagic(magic, cache)
	d.Domain("app.example.com", true)
	eventually(t, func() bool { return servedSerial(d, "app.example.com") != "" }, "no certificate for a registered name")
	d.Domain("app.example.com", false)
	if len(cache.AllMatchingCertificates("app.example.com")) != 0 {
		t.Fatal("a name that left is still in the cache, where the timer renews it")
	}
	d.Domain("app.example.com", true)
	eventually(t, func() bool { return servedSerial(d, "app.example.com") != "" }, "no certificate after the name came back")
	if n := iss.count(); n != 1 {
		t.Fatalf("issued %d times; a returning name reuses the certificate on disk", n)
	}
}

// TestRenewalTimer: certmagic's timer, at the configured interval, renews a
// certificate in the last third of its life, well before it expires.
func TestRenewalTimer(t *testing.T) {
	const life = 3 * time.Second
	iss := &testIssuer{lifetime: func(int) (time.Duration, time.Duration) { return 0, life }}
	magic, cache := testMagic(t, iss, 100*time.Millisecond)
	d := NewDomains("tunnel.example.com")
	if err := manage(t.Context(), magic, cache, "tunnel.example.com"); err != nil {
		t.Fatal(err)
	}
	d.setMagic(magic, cache)
	first := servedSerial(d, "tunnel.example.com")
	start := time.Now()
	eventually(t, func() bool { return servedSerial(d, "tunnel.example.com") != first }, "not renewed")
	if took := time.Since(start); took < life/2 || took > life {
		t.Fatalf("renewed after %v of a %v lifetime; want in its last third", took, life)
	}
}

// TestExpiredCertificateIsRenewedBeforeUse: after the edge was off past a
// certificate's end, manage replaces it before anything is served.
func TestExpiredCertificateIsRenewedBeforeUse(t *testing.T) {
	iss := &testIssuer{lifetime: func(n int) (time.Duration, time.Duration) {
		if n == 0 {
			return -2 * time.Hour, -time.Hour // expired an hour ago
		}
		return 0, time.Hour
	}}
	magic, cache := testMagic(t, iss, time.Hour)
	d := NewDomains("tunnel.example.com")
	for range 2 { // obtain, then boot again with the expired one on disk
		cache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: "tunnel.example.com"}})
		if err := manage(t.Context(), magic, cache, "tunnel.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	d.setMagic(magic, cache)
	c, err := d.certificate(helloFor("tunnel.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !time.Now().Before(c.Leaf.NotAfter) || iss.count() != 2 || len(cache.AllMatchingCertificates("tunnel.example.com")) != 1 {
		t.Fatalf("served until %v after %d issuances", c.Leaf.NotAfter, iss.count())
	}
}

// testMagic is acmeConfig's shape with iss instead of an ACME directory.
func testMagic(t *testing.T, iss certmagic.Issuer, interval time.Duration) (*certmagic.Config, *certmagic.Cache) {
	t.Helper()
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		RenewCheckInterval: interval,
		Logger:             zap.NewNop(),
		GetConfigForCert:   func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	t.Cleanup(cache.Stop)
	magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: t.TempDir()},
		Logger:  zap.NewNop(),
		Issuers: []certmagic.Issuer{iss},
	})
	return magic, cache
}

// testIssuer signs each request with a throwaway CA. lifetime gives the
// nth certificate's NotBefore and NotAfter, relative to now.
type testIssuer struct {
	lifetime func(n int) (from, to time.Duration)

	mu     sync.Mutex
	issued int
	ca     *x509.Certificate
	key    *ecdsa.PrivateKey
}

func (*testIssuer) IssuerKey() string { return "test" }

func (i *testIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.ca == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
			NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		if i.ca, err = x509.ParseCertificate(der); err != nil {
			return nil, err
		}
		i.key = key
	}
	from, to := i.lifetime(i.issued)
	i.issued++
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, DNSNames: csr.DNSNames, NotBefore: now.Add(from), NotAfter: now.Add(to),
	}, i.ca, csr.PublicKey, i.key)
	if err != nil {
		return nil, err
	}
	return &certmagic.IssuedCertificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func (i *testIssuer) count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.issued
}

// servedSerial is the serial a handshake for name gets, or "" for none.
func servedSerial(d *Domains, name string) string {
	c, err := d.certificate(helloFor(name))
	if err != nil || c.Leaf == nil {
		return ""
	}
	return c.Leaf.SerialNumber.String()
}

// helloFor is a ClientHello for name. certmagic logs the remote address of
// a handshake it has no certificate for, so it carries a connection.
func helloFor(name string) *tls.ClientHelloInfo {
	c, _ := net.Pipe()
	return &tls.ClientHelloInfo{ServerName: name, Conn: c}
}

func eventually(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal(what)
}

func within(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal(what)
	}
}

func serving(t *testing.T, h http.Handler) (*http.Server, *conns, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	track := newConns()
	s := newServer(ln.Addr().String(), h, nil)
	go func() { _ = s.Serve(track.listen(ln)) }()
	return s, track, ln.Addr().String()
}

func TestRedirectHTTPS(t *testing.T) {
	d := NewDomains("tunnel.example.com")
	d.Domain("app.example.com", true)
	h := redirectHTTPS(d.Known)
	if !aborts(func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://nobody.example.com/", nil))
	}) {
		t.Fatal("unknown host was answered")
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/x?y=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	if res.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status=%d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "https://app.example.com/x?y=1" {
		t.Fatalf("Location=%q", loc)
	}
}

func TestOptionsStarForTheAddressGetsNoBytes(t *testing.T) {
	d := NewDomains("tunnel.example.com")
	_, _, addr := serving(t, redirectHTTPS(d.Known))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(c); len(b) > 0 {
		t.Fatalf("answered: %q", b)
	}
}

func TestWantsACMEALPN(t *testing.T) {
	if wantsACMEALPN(&tls.ClientHelloInfo{}) {
		t.Fatal("empty hello")
	}
	if wantsACMEALPN(&tls.ClientHelloInfo{SupportedProtos: []string{"h2", "http/1.1"}}) {
		t.Fatal("h2 only")
	}
	if !wantsACMEALPN(&tls.ClientHelloInfo{SupportedProtos: []string{"acme-tls/1"}}) {
		t.Fatal("acme-tls/1")
	}
	if wantsACMEALPN(&tls.ClientHelloInfo{SupportedProtos: []string{"h2", "acme-tls/1"}}) {
		t.Fatal("mixed")
	}
}

func TestDomainsRouted(t *testing.T) {
	d := NewDomains("tunnel.example.com")
	d.Domain("App.Example.com", true)
	d.Domain("*.wild.example.com", true)
	for name, want := range map[string]bool{
		"app.example.com.":        true,
		"a.wild.example.com":      true,
		"a.b.wild.example.com":    true, // frp walks up to *.wild.example.com
		"wild.example.com":        false,
		"other.example.com":       false,
		"tunnel.example.com":      false,
		"":                        false,
		"app.example.com:443":     true,
		"APP.EXAMPLE.COM.:8443":   true,
		"nobody.wild.example.org": false,
	} {
		if got := d.Routed(name); got != want {
			t.Errorf("Routed(%q) = %v", name, got)
		}
	}
	if !d.Known("Tunnel.Example.com") || d.Known("") || d.Known("other.example.com") {
		t.Fatal("Known")
	}
	if d.Allowed("a.wild.example.com") {
		t.Fatal("a name routed only by a wildcard must not be issued")
	}
	d.Domain("*", true)
	if !d.Routed("anything.example.org") {
		t.Fatal("catch-all route")
	}
	d.Domain("app.example.com", false)
	d.Domain("*", false)
	if d.Routed("app.example.com") {
		t.Fatal("removed route")
	}
}

// TestUnknownServerNameGetsNoBytes: a handshake for a name the edge does
// not serve, or with no name, reads nothing back: no certificate, no alert.
func TestUnknownServerNameGetsNoBytes(t *testing.T) {
	d := NewDomains("tunnel.example.com")
	d.Domain("app.example.com", true)
	d.Domain("*.wild.example.com", true)
	cert := selfSigned(t, "app.example.com")
	base := &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "app.example.com" {
			return nil, fmt.Errorf("no certificate for %s", hello.ServerName)
		}
		return &cert, nil
	}}
	cfg := requireTunnelCert(base, x509.NewCertPool(), "tunnel.example.com", d.Known)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(ln.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}), cfg)
	go func() { _ = s.ServeTLS(tlsOnly{ln}, "", "") }()
	t.Cleanup(func() { _ = s.Close() })
	addr := ln.Addr().String()

	// "a.wild.example.com" is routed but has no certificate, as under ACME.
	for _, sni := range []string{"nobody.example.com", "", "a.wild.example.com"} {
		c := dialCounting(t, addr)
		err := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
		if err == nil || c.read.Load() != 0 {
			t.Fatalf("sni %q: handshake err %v after %d bytes, want a silent close", sni, err, c.read.Load())
		}
	}
	c := dialCounting(t, addr)
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, _ := io.ReadAll(c); len(b) != 0 {
		t.Fatalf("plain HTTP on the TLS port got %q", b)
	}

	tc := tls.Client(dialCounting(t, addr), &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("known name: %v", err)
	}
}

type countingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

func dialCounting(t *testing.T, addr string) *countingConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return &countingConn{Conn: c}
}

func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestFrpControlIsForDarkNodesOnly: an operator or log-reader certificate
// could otherwise log in to frps and register any hostname.
func TestFrpControlIsForDarkNodesOnly(t *testing.T) {
	var hits atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(control.Close)
	h, err := Handler("tunnel.example.com", http.NotFoundHandler(), control.Config.Handler, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]int{
		"spiffe://tunnel.example.com/node/node1":  200,
		"spiffe://tunnel.example.com/ops/alice":   403,
		"spiffe://tunnel.example.com/logs/fb":     403,
		"spiffe://other.example.com/node/node1":   403,
		"spiffe://tunnel.example.com/node":        403,
		"spiffe://tunnel.example.com/admin/node1": 403,
	} {
		u, err := url.Parse(id)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "https://tunnel.example.com"+config.FrpWebsocketPath, nil)
		r.TLS = &tls.ConnectionState{ServerName: "tunnel.example.com", PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", id, rec.Code, want)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("frp control reached %d times, want once", hits.Load())
	}
	if NodeOnly("tunnel.example.com")(tls.ConnectionState{}) == nil {
		t.Fatal("no client certificate accepted")
	}
}

// stampForwarded runs before frps's proxy, which sends an absolute-form
// target on as it came and drops what Connection names.
func TestStampForwarded(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/a?b=1", nil)
	r.RequestURI = "http://app.example.com/a?b=1"
	r.RemoteAddr = "198.51.100.7:4242"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("Forwarded", "for=203.0.113.9")
	r.Header.Set("X-Request-Id", "id-1")
	r.Header.Set("Connection", "X-Real-IP, x-forwarded-for, X-Request-Id, Upgrade, X-Other")
	stampForwarded(r)
	if r.RequestURI != "/a?b=1" || r.URL.Host != "" || r.URL.Scheme != "" {
		t.Fatalf("target %q %q", r.RequestURI, r.URL)
	}
	for k, want := range map[string]string{
		"X-Forwarded-For": "198.51.100.7", "X-Real-Ip": "198.51.100.7", "Forwarded": "",
		"X-Forwarded-Host": "app.example.com", "X-Request-Id": "id-1", "Connection": "Upgrade, X-Other",
	} {
		if got := strings.Join(r.Header.Values(k), ","); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}
