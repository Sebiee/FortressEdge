package httpsvc

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
)

var testLimits = config.DefaultLimits()

// testVisitors has the default burst, refilled at 1/s so that nothing
// comes back while a test runs.
func testVisitors(filt edgeFilter, known func(string) bool, exempt ...string) *visitors {
	lim := testLimits
	lim.RequestsPerSecond = 1
	return limitedVisitors(lim, filt, known, exempt...)
}

func limitedVisitors(lim config.Limits, filt edgeFilter, known func(string) bool, exempt ...string) *visitors {
	var ex []netip.Prefix
	for _, e := range exempt {
		ex = append(ex, netip.MustParsePrefix(e))
	}
	return newVisitors("tunnel.example.com", newLiveLimits(lim, ex), filt, known)
}

func hit(h http.Handler, remote, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestVisitorRateThenBan(t *testing.T) {
	filt := &fakeFilt{}
	v := testVisitors(filt, nil)
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for i := range testLimits.RequestBurst {
		if rec := hit(h, "203.0.113.9:1000", "app.example.com"); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec := hit(h, "203.0.113.9:1000", "app.example.com")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("over the burst: %d %v", rec.Code, rec.Header())
	}
	if rec := hit(h, "198.51.100.1:1000", "app.example.com"); rec.Code != 200 {
		t.Fatalf("another source is limited: %d", rec.Code)
	}
	for range testLimits.BanAfter {
		hit(h, "203.0.113.9:1000", "app.example.com")
	}
	if filt.n != 1 || filt.addr != netip.MustParseAddr("203.0.113.9") || filt.ttl != testLimits.Ban {
		t.Fatalf("ban n=%d addr=%v ttl=%s", filt.n, filt.addr, filt.ttl)
	}
	hit(h, "203.0.113.9:1000", "app.example.com")
	if filt.n != 1 || v.bans.Load() != 1 {
		t.Fatalf("banned again while banned: %d", filt.n)
	}
}

func TestVisitorIPv6CountsPerSlash64(t *testing.T) {
	v := testVisitors(nil, nil)
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for i := range testLimits.RequestBurst {
		// Rotating addresses inside one /64 does not buy more requests.
		hit(h, netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)}), 1).String(), "app.example.com")
	}
	if rec := hit(h, "[2001:db8::ffff:1]:1", "app.example.com"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same /64: %d", rec.Code)
	}
	if rec := hit(h, "[2001:db8:0:1::1]:1", "app.example.com"); rec.Code != 200 {
		t.Fatalf("next /64: %d", rec.Code)
	}
}

func TestVisitorExemptAndTrusted(t *testing.T) {
	v := testVisitors(nil, nil, "192.0.2.0/24")
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for range testLimits.RequestBurst + 10 {
		if rec := hit(h, "192.0.2.7:1", "app.example.com"); rec.Code != 200 {
			t.Fatalf("exempt source limited: %d", rec.Code)
		}
	}
	// A verified client certificate on the tunnel name: a dark node or an operator.
	for range testLimits.RequestBurst + 10 {
		req := httptest.NewRequest(http.MethodGet, "https://tunnel.example.com/~!ops/status", nil)
		req.RemoteAddr = "203.0.113.5:1"
		req.TLS = &tls.ConnectionState{ServerName: "tunnel.example.com", PeerCertificates: []*x509.Certificate{{}}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("tunnel client limited: %d", rec.Code)
		}
	}
}

func TestVisitorLimitHidesUnknownName(t *testing.T) {
	v := testVisitors(nil, func(h string) bool { return h == "app.example.com" })
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for range testLimits.RequestBurst {
		hit(h, "203.0.113.9:1", "other.example.com")
	}
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("an unknown name got a 429, not silence")
		}
	}()
	hit(h, "203.0.113.9:1", "other.example.com")
}

type addrConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }
func (c *addrConn) Close() error         { c.closed = true; return nil }

func TestVisitorConnCap(t *testing.T) {
	filt := &fakeFilt{}
	v := testVisitors(filt, nil, "192.0.2.0/24")
	conn := func(ip string) *addrConn {
		return &addrConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 1}}
	}
	var open []net.Conn
	for range testLimits.ConnsPerSource {
		c := v.admit(conn("203.0.113.9"))
		if c == nil {
			t.Fatal("refused under the cap")
		}
		open = append(open, c)
	}
	over := conn("203.0.113.9")
	if v.admit(over) != nil || !over.closed {
		t.Fatal("over the cap: not closed")
	}
	if v.admit(conn("192.0.2.1")) == nil {
		t.Fatal("exempt source refused")
	}
	open[0].Close()
	open[0].Close() // once
	if v.admit(conn("203.0.113.9")) == nil {
		t.Fatal("a closed connection was not given back")
	}
	if v.connLimited.Load() != 1 {
		t.Fatalf("conn_limited=%d", v.connLimited.Load())
	}
}

func TestVisitorSweep(t *testing.T) {
	v := testVisitors(nil, nil)
	now := time.Now()
	v.mu.Lock()
	v.get(netip.MustParsePrefix("203.0.113.1/32"), now.Add(-2*visitorIdle))
	v.get(netip.MustParsePrefix("203.0.113.2/32"), now).conns = 1
	v.get(netip.MustParsePrefix("203.0.113.3/32"), now.Add(-2*visitorIdle)).banned = now.Add(time.Minute)
	v.mu.Unlock()
	v.sweep(now)
	if len(v.m) != 2 {
		t.Fatalf("visitors after sweep: %v", v.m)
	}
}

func TestMaxConnsBounds(t *testing.T) {
	if n := maxConns(); n < 1024 || n > 32768 {
		t.Fatalf("maxConns=%d", n)
	}
}

func TestVisitorLimitsOff(t *testing.T) {
	filt := &fakeFilt{}
	off := testLimits
	off.RequestsPerSecond, off.ConnsPerSource = 0, 0
	v := limitedVisitors(off, filt, nil)
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for range 2 * testLimits.RequestBurst {
		if rec := hit(h, "203.0.113.9:1", "app.example.com"); rec.Code != 200 {
			t.Fatalf("requests_per_second 0 still limits: %d", rec.Code)
		}
	}
	for range 2 * testLimits.ConnsPerSource {
		if v.admit(&addrConn{remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}}) == nil {
			t.Fatal("connections_per_source 0 still limits")
		}
	}

	// ban 0: refused, never banned.
	noBan := testLimits
	noBan.Ban = 0
	v = limitedVisitors(noBan, filt, nil)
	h = v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for range testLimits.RequestBurst + 2*testLimits.BanAfter {
		hit(h, "203.0.113.9:1", "app.example.com")
	}
	if v.rateLimited.Load() == 0 || filt.n != 0 || v.bans.Load() != 0 {
		t.Fatalf("ban 0: limited=%d bans=%d filt=%d", v.rateLimited.Load(), v.bans.Load(), filt.n)
	}
}

func TestVisitorLimitsFromConfig(t *testing.T) {
	lim := testLimits
	lim.RequestsPerSecond, lim.RequestBurst, lim.MaxConns = 1, 3, 77
	v := limitedVisitors(lim, nil, nil)
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for range 3 {
		hit(h, "203.0.113.9:1", "app.example.com")
	}
	if rec := hit(h, "203.0.113.9:1", "app.example.com"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst 3: %d", rec.Code)
	}
	if v.maxConns != 77 || v.stats()["limits"].(map[string]any)["request_burst"] != 3 {
		t.Fatalf("max_connections=%d stats=%v", v.maxConns, v.stats())
	}
}

func TestVisitorLimitsChangeLive(t *testing.T) {
	lim := testLimits
	lim.RequestsPerSecond, lim.RequestBurst = 1, 1
	v := limitedVisitors(lim, nil, nil)
	h := v.limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	hit(h, "203.0.113.9:1", "app.example.com")
	if rec := hit(h, "203.0.113.9:1", "app.example.com"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst 1: %d", rec.Code)
	}

	// A bigger burst reaches the visitor that already exists.
	lim.RequestBurst = 50
	v.update(lim, nil)
	time.Sleep(1100 * time.Millisecond) // one token back at 1/s
	if rec := hit(h, "203.0.113.9:1", "app.example.com"); rec.Code != 200 {
		t.Fatalf("after update: %d", rec.Code)
	}

	// Exempt, then off, both without a new handler.
	v.update(lim, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	for range 10 {
		if rec := hit(h, "203.0.113.9:1", "app.example.com"); rec.Code != 200 {
			t.Fatalf("exempt: %d", rec.Code)
		}
	}
	lim.RequestsPerSecond = 0
	v.update(lim, nil)
	for range 10 {
		if rec := hit(h, "198.51.100.1:1", "app.example.com"); rec.Code != 200 {
			t.Fatalf("off: %d", rec.Code)
		}
	}

	// connections_per_source counts connections opened while it was off.
	lim.ConnsPerSource = 0
	v.update(lim, nil)
	conn := func() net.Conn {
		return v.admit(&addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 1}})
	}
	a, b := conn(), conn()
	lim.ConnsPerSource = 2
	v.update(lim, nil)
	if conn() != nil {
		t.Fatal("third connection admitted over a cap of 2")
	}
	a.Close()
	if conn() == nil {
		t.Fatal("refused after one closed")
	}
	b.Close()
}

func TestVisitorBanNeedsBanAfterWithinWindow(t *testing.T) {
	filt := &fakeFilt{}
	lim := testLimits
	lim.BanAfter, lim.BanWindow = 3, 100*time.Millisecond
	v := limitedVisitors(lim, filt, nil)
	k := netip.MustParsePrefix("203.0.113.9/32")
	for range 3 {
		v.strike(k, "test")
	}
	time.Sleep(150 * time.Millisecond) // a new window: the count starts over
	for range 3 {
		v.strike(k, "test")
	}
	if filt.n != 0 {
		t.Fatal("banned for refusals spread over two windows")
	}
	v.strike(k, "test") // the fourth in this window
	if filt.n != 1 {
		t.Fatalf("not banned after ban_after+1 strikes in one window: %d", filt.n)
	}
}
