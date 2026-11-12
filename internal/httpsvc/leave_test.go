package httpsvc

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
)

// An edge that leaves answers its health check 503 itself and serves every
// other site as before, closing each connection after its response.
func TestLeavingFailsOnlyTheHealthCheck(t *testing.T) {
	frps := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	p, err := config.ParsePolicy([]byte("sites:\n  check.example.com:\n    health_check: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	lim := newLivePolicy(p)
	leave := &Leave{For: 50 * time.Millisecond}
	h, err := Handler("tunnel.example.com", frps, nil, nil, &httpStats{}, nil, lim, leave)
	if err != nil {
		t.Fatal(err)
	}
	get := func(host string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
		return rec.Code, rec.Header().Get("Connection")
	}
	// A WebSocket's request: its 101 says Connection: Upgrade, never close.
	upgrade := func() string {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		req.Header.Set("Connection", "keep-alive, Upgrade")
		req.Header.Set("Upgrade", "websocket")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header().Get("Connection")
	}
	both := func(check, app int, conn string) {
		t.Helper()
		if got, c := get("check.example.com"); got != check || c != conn {
			t.Fatalf("health check: %d, Connection %q; want %d, %q", got, c, check, conn)
		}
		if got, c := get("app.example.com"); got != app || c != conn {
			t.Fatalf("a site: %d, Connection %q; want %d, %q", got, c, app, conn)
		}
	}
	both(http.StatusOK, http.StatusOK, "")

	leave.serving(func() bool { return lim.get().policy.HasHealthCheck() })
	ended := make(chan time.Time, 1)
	start := time.Now()
	leave.Begin(func() { ended <- time.Now() })
	if !leave.Leaving() {
		t.Fatal("not leaving after Begin")
	}
	both(http.StatusServiceUnavailable, http.StatusOK, "close")
	if c := upgrade(); c != "" {
		t.Fatalf("an upgrade while it leaves: Connection %q, want none from the edge", c)
	}
	select {
	case at := <-ended:
		if d := at.Sub(start); d < leave.For {
			t.Fatalf("the stage ended after %s, want %s", d, leave.For)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stage never ended")
	}
	// Past the stage the check keeps failing while requests in flight end.
	both(http.StatusServiceUnavailable, http.StatusOK, "close")
}

// A stop with nobody to tell ends at once: an edge that does not listen
// yet, or whose policy has no health check. So does a second signal.
func TestLeaveEndsAtOnceWithoutAHealthCheck(t *testing.T) {
	ends := func(l *Leave) bool {
		done := make(chan struct{})
		l.Begin(func() { close(done) })
		select {
		case <-done:
			return true
		case <-time.After(100 * time.Millisecond):
			return false
		}
	}
	if l := (&Leave{For: time.Hour}); !ends(l) || l.Leaving() {
		t.Fatal("an edge that does not listen yet must stop at once")
	}
	l := &Leave{For: time.Hour}
	l.serving(func() bool { return false })
	if !ends(l) || l.Leaving() {
		t.Fatal("an edge without a health check must stop at once")
	}

	l = &Leave{For: time.Hour}
	l.serving(func() bool { return true })
	n := 0
	end := func() { n++ }
	l.Begin(end)
	if n != 0 || !l.Leaving() {
		t.Fatalf("the first signal: ended %d times, leaving %v", n, l.Leaving())
	}
	l.Begin(end)
	l.Begin(end)
	if n != 1 {
		t.Fatalf("a second signal must end the stage, once: ended %d times", n)
	}
	var none *Leave
	if none.Leaving() {
		t.Fatal("a nil Leave leaves")
	}
}

// The whole stop, on a real listener: while the edge leaves, a new visitor
// is served and only the health check fails; when it then closes, the
// request in flight ends whole.
func TestLeaveServesUntilItCloses(t *testing.T) {
	release := make(chan struct{})
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			io.WriteString(w, "a")
			_ = http.NewResponseController(w).Flush()
			<-release
		}
		io.WriteString(w, "ok")
	})
	p, err := config.ParsePolicy([]byte("sites:\n  check.example.com:\n    health_check: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	lim := newLivePolicy(p)
	leave := &Leave{For: 300 * time.Millisecond}
	h, err := Handler("tunnel.example.com", frps, nil, nil, &httpStats{}, nil, lim, leave)
	if err != nil {
		t.Fatal(err)
	}
	addr := make(chan string, 1)
	s := newServer("127.0.0.1:0", h, nil)
	s.BaseContext = func(l net.Listener) context.Context {
		addr <- l.Addr().String()
		return context.Background()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- serve(ctx, []*http.Server{s}, newConns(), nil, &sockets{}, nil, 5*time.Second) }()
	at := <-addr
	leave.serving(func() bool { return lim.get().policy.HasHealthCheck() })

	// Each request is a new connection, as a balancer's check and a new
	// visitor are.
	get := func(host, path string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+at+path, nil)
		if err != nil {
			return nil, err
		}
		req.Host = host
		return (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}).Do(req)
	}
	status := func(host string) int {
		t.Helper()
		resp, err := get(host, "/")
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	slow, err := get("app.example.com", "/slow")
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Body.Close()
	if status("check.example.com") != http.StatusOK {
		t.Fatal("the health check fails before the stop")
	}

	leave.Begin(cancel)
	seen := 0
	for ctx.Err() == nil {
		// Asked before the request: one that the stage's end overtakes may
		// meet the closed port, and proves nothing.
		for host, want := range map[string]int{"check.example.com": http.StatusServiceUnavailable, "app.example.com": http.StatusOK} {
			resp, err := get(host, "/")
			if ctx.Err() != nil {
				if err == nil {
					resp.Body.Close()
				}
				continue
			}
			if err != nil {
				t.Fatalf("while it leaves, %s: %v", host, err)
			}
			resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatalf("while it leaves, %s: %d, want %d", host, resp.StatusCode, want)
			}
			seen++
		}
		time.Sleep(20 * time.Millisecond)
	}
	if seen < 4 {
		t.Fatalf("only %d requests answered while it left", seen)
	}
	select {
	case err := <-served:
		t.Fatalf("the edge closed with a request in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if body, err := io.ReadAll(slow.Body); err != nil || string(body) != "aok" {
		t.Fatalf("the request in flight: %q, %v", body, err)
	}
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("the edge did not close once its request ended")
	}
	if _, err := get("app.example.com", "/"); err == nil {
		t.Fatal("the port is still open")
	}
}
