package httpsvc

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeFilt struct {
	addr netip.Addr
	ttl  time.Duration
	n    int
}

func (f *fakeFilt) Ban(a netip.Addr, ttl time.Duration) error {
	f.n++
	f.addr = a
	f.ttl = ttl
	return nil
}
func (f *fakeFilt) Stats() map[string]uint64 { return nil }

func TestProtectHeaders(t *testing.T) {
	p := protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), &httpStats{}, nil)
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("nosniff=%q", rec.Header().Get("X-Content-Type-Options"))
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS on plaintext")
	}
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Header().Get("Strict-Transport-Security") != hstsHeader {
		t.Fatalf("HSTS=%q", rec.Header().Get("Strict-Transport-Security"))
	}
}

func TestRefuseMalformed(t *testing.T) {
	st := &httpStats{}
	p := refuseMalformed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), st, nil)
	long := "/" + strings.Repeat("a", testLimits.MaxURIBytes)
	for _, tc := range []struct {
		method, uri string
		want        int
	}{
		{http.MethodGet, "/a/b?q=../x", 200},
		{http.MethodGet, "/a/..b/c.", 200},
		{http.MethodOptions, "*", 200},
		{http.MethodTrace, "/", 405},
		{"TRACK", "/", 405},
		{http.MethodConnect, "/", 405},
		{http.MethodGet, "/a/../etc/passwd", 400},
		{http.MethodGet, "/a/%2e%2e/etc/passwd", 400},
		{http.MethodGet, "/a/./b", 400},
		{http.MethodGet, "/a/%00b", 400},
		{http.MethodGet, "/a%5c..%5cb", 400},
		{http.MethodGet, long, 414},
	} {
		req := httptest.NewRequest(tc.method, "http://app.example.com/", nil)
		req.RequestURI = tc.uri
		if tc.uri != "*" {
			// What net/http does with the request line: no cleanup.
			if u, err := url.ParseRequestURI(tc.uri); err == nil {
				req.URL = u
			} else {
				t.Fatalf("%s: %v", tc.uri, err)
			}
		}
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %.40s: status %d, want %d", tc.method, tc.uri, rec.Code, tc.want)
		}
		if tc.uri == "*" && rec.Body.Len() > 0 {
			t.Errorf("OPTIONS * reached the site: %q", rec.Body)
		}
	}
	if st.rejected.Load() != 9 {
		t.Fatalf("rejected=%d", st.rejected.Load())
	}
}

func TestBodyAndURILimitsChangeLive(t *testing.T) {
	lim := newLiveLimits(testLimits, nil)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	})
	h := refuseMalformed(protect(echo, nil, lim), nil, lim)
	send := func(uri, body string) int {
		req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+uri, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := send("/"+strings.Repeat("a", 2000), strings.Repeat("x", 4096)); code != 200 {
		t.Fatalf("defaults: %d", code)
	}
	small := testLimits
	small.MaxBodyBytes, small.MaxURIBytes = 1024, 1024
	lim.set(small, nil)
	if code := send("/", strings.Repeat("x", 4096)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body over 1KiB: %d", code)
	}
	if code := send("/"+strings.Repeat("a", 2000), ""); code != http.StatusRequestURITooLong {
		t.Fatalf("uri over 1KiB: %d", code)
	}
	small.MaxBodyBytes = 0 // no limit
	lim.set(small, nil)
	if code := send("/", strings.Repeat("x", 1<<20)); code != 200 {
		t.Fatalf("no body limit: %d", code)
	}
}
