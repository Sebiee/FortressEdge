package httpsvc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// syncBuffer is the access log's file, read while the edge writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) lines(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for line := range strings.Lines(b.b.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("access log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// backend is the service behind a TCP route: serve gets each connection
// the route dials.
type backend struct {
	addr  string
	dials atomic.Int64
	fail  error // Dial's error, for no_backend
}

func newBackend(t *testing.T, serve func(*net.TCPConn)) *backend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				serve(c.(*net.TCPConn))
			}()
		}
	}()
	return &backend{addr: ln.Addr().String()}
}

func echo(c *net.TCPConn) {
	_, _ = io.Copy(c, c)
	_ = c.CloseWrite()
}

// route is the backend as frps would hold it.
func (b *backend) route(alpn ...string) TCPRoute {
	return TCPRoute{Group: "node1", ALPN: alpn, Dial: func(net.Addr) (net.Conn, error) {
		b.dials.Add(1)
		if b.fail != nil {
			return nil, b.fail
		}
		return net.Dial("tcp", b.addr)
	}}
}

// routeEdge is the edge's port 443 as serve composes it: TCP routes
// split off after the ClientHello, the rest to an HTTPS server that
// answers app.example.com.
type routeEdge struct {
	addr    string
	streams *streams
	access  *syncBuffer
	roots   *x509.CertPool
	cancel  context.CancelFunc
	track   *conns
}

func newRouteEdge(t *testing.T, p config.Policy, routes map[string]TCPRoute) *routeEdge {
	t.Helper()
	certs := map[string]tls.Certificate{}
	roots := x509.NewCertPool()
	for _, name := range []string{"app.example.com", "db.example.com", "cache.example.com"} {
		c := selfSigned(t, name)
		certs[name] = c
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		roots.AddCert(leaf)
	}
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, ok := certs[hostname(hello.ServerName)]
		if !ok {
			return nil, fmt.Errorf("no certificate for %s", hello.ServerName)
		}
		return &c, nil
	}
	d := NewDomains("tunnel.example.com")
	d.Domain("app.example.com", true)
	for name := range routes {
		d.TCPDomain(name, true)
	}
	base := &tls.Config{GetCertificate: getCert, NextProtos: []string{"h2", "http/1.1"}}
	streamCfg := &tls.Config{GetCertificate: getCert}
	httpsCfg := requireTunnelCert(base, x509.NewCertPool(), "tunnel.example.com", d.Known)

	ctx, cancel := context.WithCancel(context.Background())
	if p.Limits == (config.Limits{}) {
		p.Limits = config.DefaultLimits()
	}
	p.AccessLog.On = true
	lim := newLivePolicy(p)
	st := &httpStats{}
	access := &syncBuffer{}
	st.access.Store(newAccessLog(access))
	lookup := func(name string) (TCPRoute, bool) { r, ok := routes[name]; return r, ok }
	tcp := newStreams(ctx, lookup, streamCfg, lim, nil, nil, st)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	track := newConns()
	s := newServer(raw.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "http ok")
	}), httpsCfg)
	go func() { _ = s.ServeTLS(tlsOnly{splitTLS(track.listen(raw), tcp.take)}, "", "") }()
	t.Cleanup(func() {
		cancel()
		_ = s.Close()
		track.closeAll()
	})
	return &routeEdge{addr: raw.Addr().String(), streams: tcp, access: access, roots: roots, cancel: cancel, track: track}
}

func (e *routeEdge) dial(t *testing.T, name string, alpn ...string) (*tls.Conn, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: name, RootCAs: e.roots, NextProtos: alpn})
	return tc, tc.Handshake()
}

// closed waits for ss's access log line: the connection's end.
func (e *routeEdge) logged(t *testing.T, n int) []map[string]any {
	t.Helper()
	var lines []map[string]any
	eventually(t, func() bool { lines = e.access.lines(t); return len(lines) >= n }, fmt.Sprintf("%d access log lines", n))
	return lines
}

func roundTrip(t *testing.T, c *tls.Conn, msg string) {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("echo %q, want %q", got, msg)
	}
}

func TestTCPRouteReachesBackend(t *testing.T) {
	b := newBackend(t, echo)
	e := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{"db.example.com": b.route()})

	c, err := e.dial(t, "db.example.com")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "hello, backend")
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(c); err != nil || len(rest) != 0 {
		t.Fatalf("after close_notify: %q %v", rest, err)
	}
	line := e.logged(t, 1)[0]
	for k, want := range map[string]any{
		"site": "db.example.com", "proto": "tcp", "group": "node1", "result": "ok", "close": "client",
		"in": float64(14), "out": float64(14), "ip": "127.0.0.1",
	} {
		if line[k] != want {
			t.Errorf("access log %s: %v, want %v (%v)", k, line[k], want, line)
		}
	}

	// HTTP names on the same port are unchanged.
	h, err := e.dial(t, "app.example.com", "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(h, "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
	resp, _ := io.ReadAll(h)
	if !bytes.HasSuffix(resp, []byte("http ok")) {
		t.Fatalf("http name: %q", resp)
	}
	// Plain bytes on the TLS port still get nothing.
	raw := dialCounting(t, e.addr)
	fmt.Fprintf(raw, "GET / HTTP/1.1\r\nHost: db.example.com\r\n\r\n")
	if got, _ := io.ReadAll(raw); len(got) != 0 {
		t.Fatalf("plain HTTP got %q", got)
	}
	// So does a name that is neither.
	if _, err := e.dial(t, "nobody.example.com"); err == nil {
		t.Fatal("unknown name: handshake succeeded")
	}
}

func TestTCPRouteALPN(t *testing.T) {
	b := newBackend(t, echo)
	e := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{
		"db.example.com":    b.route("postgresql"),
		"cache.example.com": b.route("a", "b"),
	})

	c, err := e.dial(t, "db.example.com", "postgresql")
	if err != nil {
		t.Fatal(err)
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "postgresql" {
		t.Fatalf("negotiated %q", p)
	}
	roundTrip(t, c, "SELECT 1")
	c.Close()

	// The client's preference wins among the route's protocols.
	c, err = e.dial(t, "cache.example.com", "x", "b", "a")
	if err != nil {
		t.Fatal(err)
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "b" {
		t.Fatalf("negotiated %q, want the client's first that the route takes", p)
	}
	roundTrip(t, c, "x") // the edge dials after the handshake
	c.Close()
	dials := b.dials.Load()

	// None of the route's: no_application_protocol, and the backend sees
	// nothing.
	if _, err := e.dial(t, "db.example.com", "h2", "http/1.1"); err == nil || !strings.Contains(err.Error(), "no application protocol") {
		t.Fatalf("wrong alpn: %v, want no_application_protocol", err)
	}
	// None at all: closed.
	if _, err := e.dial(t, "db.example.com"); err == nil {
		t.Fatal("no alpn: handshake succeeded")
	}
	lines := e.logged(t, 4)
	if b.dials.Load() != dials {
		t.Fatalf("refused handshakes dialed the backend %d times", b.dials.Load()-dials)
	}
	refused := 0
	for _, l := range lines { // in the order the connections ended
		if l["result"] == "alpn_refused" && l["site"] == "db.example.com" && l["alpn"] == nil {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("%d alpn_refused lines, want 2: %v", refused, lines)
	}
	if got := e.streams.snapshot()["db.example.com"]["alpn_refused"]; got != 2 {
		t.Fatalf("alpn_refused %d, want 2", got)
	}
}

// Each way closes on its own: the client's end of input reaches the
// backend, which still answers.
func TestTCPRouteHalfClose(t *testing.T) {
	b := newBackend(t, func(c *net.TCPConn) {
		q, err := io.ReadAll(c) // to the client's EOF
		if err != nil {
			return
		}
		fmt.Fprintf(c, "got %d bytes", len(q))
		_ = c.CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	})
	e := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{"db.example.com": b.route()})
	c, err := e.dial(t, "db.example.com")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "a query")
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "got 7 bytes" {
		t.Fatalf("answer after half-close: %q %v", got, err)
	}
	line := e.logged(t, 1)[0]
	if line["close"] != "client" || line["in"] != float64(7) || line["out"] != float64(11) {
		t.Fatalf("access log: %v", line)
	}

	// The backend closes first: the client reads EOF and can still send.
	b2 := newBackend(t, func(c *net.TCPConn) {
		io.WriteString(c, "bye")
		_ = c.CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	})
	e2 := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{"db.example.com": b2.route()})
	c, err = e2.dial(t, "db.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(c); err != nil || string(got) != "bye" {
		t.Fatalf("backend first: %q %v", got, err)
	}
	if _, err := io.WriteString(c, "late"); err != nil {
		t.Fatalf("write after the backend's EOF: %v", err)
	}
	c.CloseWrite()
	if l := e2.logged(t, 1)[0]; l["close"] != "backend" || l["in"] != float64(4) {
		t.Fatalf("access log: %v", l)
	}
}

func TestTCPRouteIdleTimeout(t *testing.T) {
	b := newBackend(t, echo)
	sites := map[string]config.SitePolicy{"db.example.com": {TCPIdleTimeout: ptr(300 * time.Millisecond)}}
	e := newRouteEdge(t, config.Policy{Sites: sites}, map[string]TCPRoute{"db.example.com": b.route()})
	c, err := e.dial(t, "db.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Traffic keeps it open past the timeout.
	for range 4 {
		roundTrip(t, c, "ping")
		time.Sleep(150 * time.Millisecond)
	}
	start := time.Now()
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read after idle: %v", err)
	}
	if quiet := time.Since(start); quiet > 2*time.Second {
		t.Fatalf("closed after %s quiet", quiet)
	}
	if l := e.logged(t, 1)[0]; l["close"] != "idle_timeout" || l["result"] != "ok" {
		t.Fatalf("access log: %v", l)
	}
}

func ptr[T any](v T) *T { return &v }

func TestTCPRouteConnsPerSource(t *testing.T) {
	b := newBackend(t, echo)
	routes := map[string]TCPRoute{"db.example.com": b.route(), "cache.example.com": b.route()}
	sites := map[string]config.SitePolicy{"db.example.com": {TCPConnsPerSource: ptr(2)}}
	e := newRouteEdge(t, config.Policy{Sites: sites}, routes)
	var open []*tls.Conn
	for range 2 {
		c, err := e.dial(t, "db.example.com")
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, "x")
		open = append(open, c)
	}
	if _, err := e.dial(t, "db.example.com"); err == nil {
		t.Fatal("third connection: handshake succeeded")
	}
	// The limit is per site: another route is not full.
	c, err := e.dial(t, "cache.example.com")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "x")
	if got := e.streams.snapshot()["db.example.com"]["policy_refused"]; got != 1 {
		t.Fatalf("policy_refused %d", got)
	}
	// A closed connection frees its place.
	open[0].Close()
	eventually(t, func() bool {
		c, err := e.dial(t, "db.example.com")
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, "a place after a close")

	// An exempt source is not limited.
	exempt := config.Policy{Sites: sites, Exempt: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	e2 := newRouteEdge(t, exempt, routes)
	for range 4 {
		c, err := e2.dial(t, "db.example.com")
		if err != nil {
			t.Fatalf("exempt: %v", err)
		}
		roundTrip(t, c, "x")
	}
}

func TestTCPRouteNoBackend(t *testing.T) {
	b := newBackend(t, echo)
	b.fail = errors.New("no work connection")
	e := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{"db.example.com": b.route()})
	c, err := e.dial(t, "db.example.com")
	if err != nil {
		t.Fatal(err) // the handshake comes first
	}
	if got, _ := io.ReadAll(c); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
	if l := e.logged(t, 1)[0]; l["result"] != "no_backend" || l["error"] == nil {
		t.Fatalf("access log: %v", l)
	}

	var buf bytes.Buffer
	w := metrics.NewWriter(&buf)
	e.streams.writeMetrics(w)
	w.Flush()
	for _, want := range []string{
		`fortressedge_tcp_route_connections{site="db.example.com"} 0`,
		`fortressedge_tcp_route_connections_total{site="db.example.com",result="no_backend"} 1`,
		`fortressedge_tcp_route_bytes_total{site="db.example.com",direction="in"} 0`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, buf.String())
		}
	}
}

func TestTCPRouteDrain(t *testing.T) {
	b := newBackend(t, echo)
	e := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{"db.example.com": b.route()})
	c, err := e.dial(t, "db.example.com")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "x")
	if e.track.Len() == 0 {
		t.Fatal("the TCP route's connection is not tracked")
	}
	e.cancel()
	e.track.closeAll()
	if l := e.logged(t, 1)[0]; l["close"] != "shutdown" {
		t.Fatalf("access log: %v", l)
	}
}

// The ACME challenge for a TCP route's name stays with the HTTPS server,
// which answers TLS-ALPN-01.
func TestTCPRouteLeavesACMEChallenge(t *testing.T) {
	s := newStreams(context.Background(), func(string) (TCPRoute, bool) { return TCPRoute{}, true }, nil, nil, nil, nil, &httpStats{})
	hello := helloFor("db.example.com")
	hello.SupportedProtos = []string{"acme-tls/1"}
	if s.take(nil, hello) {
		t.Fatal("took the ACME challenge")
	}
}

func TestDomainsTCPRoute(t *testing.T) {
	d := NewDomains("tunnel.example.com")
	d.Domain("*.example.com", true)
	d.TCPDomain("db.example.com", true)
	if !d.Known("db.example.com") || !d.TCPRoute("db.example.com") || !d.Allowed("db.example.com") {
		t.Fatal("a TCP route's name is known, and may have a certificate")
	}
	// HTTP for it goes to the wildcard, if any: the name itself is no
	// HTTP route.
	if r, ok := d.Route("db.example.com"); !ok || r != "*.example.com" {
		t.Fatalf("route %q %v", r, ok)
	}
	d.Domain("*.example.com", false)
	if d.KnownHTTP("db.example.com") {
		t.Fatal("a TCP route's name answers HTTP")
	}
	// The HTTP callback does not remove a TCP route's name.
	d.Domain("db.example.com", false)
	if !d.TCPRoute("db.example.com") {
		t.Fatal("removed by the HTTP callback")
	}
	d.TCPDomain("db.example.com", false)
	if d.Known("db.example.com") || d.TCPRoute("db.example.com") {
		t.Fatal("still known")
	}
}

// The tunnel name is never a TCP route: its connections need the HTTPS
// server's mutual TLS. frps refuses such a proxy; this holds without it.
func TestTCPRouteNeverTheTunnel(t *testing.T) {
	all := func(string) (TCPRoute, bool) { return TCPRoute{}, true }
	routes := notTunnel("Tunnel.example.com.", all)
	if _, ok := routes("tunnel.example.com"); ok {
		t.Fatal("the tunnel name is a TCP route")
	}
	if _, ok := routes("db.example.com"); !ok {
		t.Fatal("another name is not")
	}
	d := NewDomains("tunnel.example.com")
	d.TCPDomain("tunnel.example.com", true)
	if d.TCPRoute("tunnel.example.com") {
		t.Fatal("Domains took the tunnel name as a TCP route")
	}
}

// A TCP route whose certificate is not there yet closes with no bytes,
// as an HTTP name in that state does.
func TestTCPRouteWithoutCertificateIsSilent(t *testing.T) {
	b := newBackend(t, echo)
	e := newRouteEdge(t, config.Policy{}, map[string]TCPRoute{"nocert.example.com": b.route()})
	c := dialCounting(t, e.addr)
	err := tls.Client(c, &tls.Config{ServerName: "nocert.example.com", InsecureSkipVerify: true}).Handshake()
	if err == nil || c.read.Load() != 0 {
		t.Fatalf("handshake err %v after %d bytes, want a silent close", err, c.read.Load())
	}
	if b.dials.Load() != 0 {
		t.Fatal("dialed the backend")
	}
}

func TestDomainsTCPRouteDropsHeldCertificate(t *testing.T) {
	d := NewDomains("tunnel.example.com")
	d.SetTunnelGrace(time.Hour)
	crt, key := certPEM(t, "db.example.com", time.Now().Add(time.Hour))
	c, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.held = map[string]heldCert{"db.example.com": {&c, time.Now()}}
	d.mu.Unlock()
	if !d.KnownHTTP("db.example.com") {
		t.Fatal("a held name answers HTTP")
	}
	d.TCPDomain("db.example.com", true)
	if d.KnownHTTP("db.example.com") {
		t.Fatal("a TCP route's name still answers HTTP from a held certificate")
	}
}
