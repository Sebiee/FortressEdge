package httpsvc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/fatedier/frp/pkg/util/vhost"

	"github.com/Sebiee/fortressedge/internal/config"
)

func TestSiteRequestIDStatsAndAccessLog(t *testing.T) {
	upstreamc := make(chan http.Header, 1)
	vhost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamc <- r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write(append([]byte("got "), body...))
	}))
	t.Cleanup(vhost.Close)
	logc := make(chan []byte, 1)
	st := &httpStats{}
	st.access.Store(newAccessLog(chanWriter(logc)))
	lim := newLivePolicy(config.Policy{Limits: config.DefaultLimits(), AccessLog: config.AccessLog{On: true}})
	h, err := Handler("tunnel.example.com", vhost.Config.Handler, nil, nil, st, nil, lim)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/items?token=secret", strings.NewReader("hello"))
	req.Host = "app.example.com"
	req.Header.Set("X-Request-Id", "spoofed")
	req.Header.Set("Forwarded", "for=9.9.9.9;proto=http")
	req.Header.Set("User-Agent", "test/1")
	res, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()

	upstream := <-upstreamc
	logLine := <-logc // written once the handler returns, after the response
	id := res.Header.Get(requestIDHeader)
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("%s=%q: %v", requestIDHeader, id, err)
	}
	if upstream.Get("X-Request-Id") != id {
		t.Fatalf("upstream X-Request-Id=%q, want %q", upstream.Get("X-Request-Id"), id)
	}
	if upstream.Get("Forwarded") != "" {
		t.Fatalf("Forwarded reached the origin: %q", upstream.Get("Forwarded"))
	}

	s := st.sitesSnapshot()["app.example.com"]
	if s["requests"] != 1 || s["2xx"] != 1 || s["in_flight"] != 0 || s["bytes_in"] != 5 || s["bytes_out"] != 9 {
		t.Fatalf("site stats: %v", s)
	}

	var line struct {
		Time                              time.Time
		ID, IP, Site, Method, Path, Proto string
		UA                                string `json:"ua"`
		Status                            int
		In, Out, Ms                       int64
		Level, Msg                        *string
	}
	if err := json.Unmarshal(logLine, &line); err != nil {
		t.Fatalf("access line %q: %v", string(logLine), err)
	}
	if line.ID != id || line.Site != "app.example.com" || line.Method != "POST" || line.Path != "/api/items" ||
		line.Status != 201 || line.In != 5 || line.Out != 9 || line.UA != "test/1" || line.IP != "127.0.0.1" || line.Time.IsZero() {
		t.Fatalf("access line: %s", string(logLine))
	}
	if line.Level != nil || line.Msg != nil || strings.Contains(string(logLine), "secret") {
		t.Fatalf("access line has extra fields or the query: %s", string(logLine))
	}
}

// chanWriter hands each write (one access line) to a test.
type chanWriter chan []byte

func (c chanWriter) Write(p []byte) (int, error) {
	c <- bytes.Clone(p)
	return len(p), nil
}

func TestSiteCountsBadGateway(t *testing.T) {
	st := &httpStats{}
	// frps writes 502 itself when the origin answers nothing.
	vhost := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	h, err := Handler("tunnel.example.com", vhost, nil, nil, st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	if s := st.sitesSnapshot()["app.example.com"]; s["5xx"] != 1 || st.badGateway.Load() != 1 {
		t.Fatalf("stats: %v bad_gateway=%d", s, st.badGateway.Load())
	}

	// A visitor who left is not the origin's fault.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil).WithContext(ctx))
	if st.badGateway.Load() != 1 {
		t.Fatalf("bad_gateway=%d after a visitor left", st.badGateway.Load())
	}
}

func TestMalformedUnknownNameStaysSilent(t *testing.T) {
	st := &httpStats{}
	h, err := Handler("tunnel.example.com", http.NotFoundHandler(), nil, nil, st,
		func(host string) (string, bool, bool) { return host, false, host == "app.example.com" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodTrace, "http://other.example.com/", nil)
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Fatal("a malformed request for an unknown name got an answer")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()
	// For a served name it is refused, counted, and logged like any request.
	req = httptest.NewRequest(http.MethodTrace, "http://app.example.com/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get(requestIDHeader) == "" {
		t.Fatalf("status=%d headers=%v", rec.Code, rec.Header())
	}
	if s := st.sitesSnapshot()["app.example.com"]; s["4xx"] != 1 || st.rejected.Load() != 1 {
		t.Fatalf("stats: %v rejected=%d", s, st.rejected.Load())
	}
}

// timeoutErr is a net.Error that timed out, as frps's header timeout is.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout awaiting response headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// A request frps could not proxy is one warning that names the site, the
// request, and the stage; the site counts it, and its access line says why.
func TestProxyErrorLine(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// frps's side: it reports, then answers 504, as its ErrorHandler does.
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ProxyError(r, &vhost.ProxyError{Stage: vhost.StageHeaders, Err: timeoutErr{}})
		w.WriteHeader(http.StatusGatewayTimeout)
	})
	logc := make(chan []byte, 1)
	st := &httpStats{}
	st.access.Store(newAccessLog(chanWriter(logc)))
	lim := newLivePolicy(config.Policy{Limits: config.DefaultLimits(), AccessLog: config.AccessLog{On: true}})
	route := func(host string) (string, bool, bool) { return "*.example.com", false, true }
	h, err := Handler("tunnel.example.com", frps, nil, nil, st, route, lim)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://vault.example.com/v1/sys/health?token=secret", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status %d", rec.Code)
	}
	line := logBuf.String()
	for _, want := range []string{`level=WARN msg="proxy error"`, "site=vault.example.com", "route=*.example.com", "method=GET",
		"path=/v1/sys/health", "ip=192.0.2.1", "id=" + rec.Header().Get(requestIDHeader),
		"trace_id=" + rec.Header().Get(traceIDHeader), "reason=header_timeout", "elapsed_ms=", "sent=0"} {
		if !strings.Contains(line, want) {
			t.Errorf("proxy error line lacks %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "secret") {
		t.Fatalf("the query reached the log: %s", line)
	}
	if n := st.site("*.example.com").proxyErrors[reasonHeaderTimeout].Load(); n != 1 {
		t.Fatalf("header_timeout count %d", n)
	}
	var acc map[string]any
	if err := json.Unmarshal(<-logc, &acc); err != nil {
		t.Fatal(err)
	}
	if acc["error"] != "header_timeout" || acc["route"] != "*.example.com" || acc["trace_id"] != rec.Header().Get(traceIDHeader) ||
		acc["span_id"] == nil || acc["start"] == nil || acc["us"] == nil || acc["headers_us"] == nil {
		t.Fatalf("access line: %v", acc)
	}
}

// max_body_size is the site's: refused up front when Content-Length says
// so, and answered 413 when a streamed body goes over on its way to frps.
func TestSiteBodyLimit(t *testing.T) {
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			// What frps's transport reports when the body read fails.
			ProxyError(r, &vhost.ProxyError{Stage: vhost.StageSend, Err: err})
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, "ok")
	})
	p, err := config.ParsePolicy([]byte("limits:\n  max_body_size: 1MiB\nsites:\n  small.example.com:\n    max_body_size: 1KiB\n"))
	if err != nil {
		t.Fatal(err)
	}
	st := &httpStats{}
	h, err := Handler("tunnel.example.com", frps, nil, nil, st, nil, newLivePolicy(p))
	if err != nil {
		t.Fatal(err)
	}
	send := func(host string, body io.Reader, size int64) int {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/", body)
		req.ContentLength = size
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	big := strings.Repeat("x", 4096)
	for _, tc := range []struct {
		host string
		size int64 // -1: streamed, no Content-Length
		want int
	}{
		{"small.example.com", 4096, http.StatusRequestEntityTooLarge},
		{"small.example.com", -1, http.StatusRequestEntityTooLarge},
		{"small.example.com", 512, http.StatusOK},
		{"other.example.com", 4096, http.StatusOK},
		{"other.example.com", -1, http.StatusOK},
	} {
		body := io.Reader(strings.NewReader(big[:max(tc.size, 4096)]))
		if tc.size == 512 {
			body = strings.NewReader(big[:512])
		}
		if tc.size < 0 {
			body = io.MultiReader(body) // hides the length
		}
		if got := send(tc.host, body, tc.size); got != tc.want {
			t.Errorf("%s, %d bytes: %d, want %d", tc.host, tc.size, got, tc.want)
		}
	}
	if n := st.site("small.example.com").limitHits[limitBody].Load(); n != 2 {
		t.Fatalf("body limit hits %d, want 2", n)
	}
	if n := st.site("small.example.com").proxyErrors[reasonSend].Load(); n != 0 {
		t.Fatalf("a body over the limit counted as a proxy error")
	}
}

// shortStall sets stallTimeout to d for the test.
func shortStall(t *testing.T, d time.Duration) {
	old := stallTimeout
	stallTimeout = d
	t.Cleanup(func() { stallTimeout = old })
}

// overHTTP1And2 serves h as the HTTPS server does, over HTTP/1.1 and
// then over HTTP/2, and runs f against each.
func overHTTP1And2(t *testing.T, h http.Handler, f func(t *testing.T, url string, c *http.Client)) {
	for _, h2 := range []bool{false, true} {
		s := httptest.NewUnstartedServer(h)
		s.Config = newServer("", h, nil)
		s.EnableHTTP2 = h2
		s.StartTLS()
		name := "HTTP/1.1"
		if h2 {
			name = "HTTP/2"
		}
		t.Run(name, func(t *testing.T) {
			defer s.Close()
			c := s.Client()
			c.Timeout = 20 * time.Second
			f(t, s.URL, c)
		})
	}
}

// frpsTakesBody reads a request's body to its end before it answers, as
// frps sends it to the origin first, and reports a failed read as frps
// does. A ?slow request has the origin take a second after the first
// byte.
var frpsTakesBody = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var first [1]byte
	_, err := io.ReadFull(r.Body, first[:])
	if r.URL.Query().Has("slow") {
		time.Sleep(time.Second)
	}
	if err == nil {
		_, err = io.Copy(io.Discard, r.Body)
	}
	if err != nil {
		ProxyError(r, &vhost.ProxyError{Stage: vhost.StageSend, Err: err})
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	io.WriteString(w, "ok")
})

// A body that stops coming ends its request after stallTimeout, answered
// 408 and counted: it held a work connection, an origin connection and
// edge memory for as long as the visitor liked. A body that comes a byte
// at a time, or that the origin is slow to take, goes through.
func TestSiteBodyStall(t *testing.T) {
	shortStall(t, 300*time.Millisecond)
	st := &httpStats{}
	h, err := Handler("tunnel.example.com", frpsTakesBody, nil, nil, st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	overHTTP1And2(t, h, func(t *testing.T, url string, c *http.Client) {
		post := func(path string, body func(*io.PipeWriter)) int {
			t.Helper()
			pr, pw := io.Pipe()
			defer pw.Close()
			go body(pw)
			// net/http's client waits for the body however it ends.
			giveUp := time.AfterFunc(5*time.Second, func() { pw.CloseWithError(errors.New("gave up")) })
			defer giveUp.Stop()
			res, err := c.Post(url+path, "text/plain", pr)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			return res.StatusCode
		}
		stalls := func(pw *io.PipeWriter) { pw.Write([]byte("x")) }
		trickles := func(pw *io.PipeWriter) {
			for range 10 {
				pw.Write([]byte("x"))
				time.Sleep(100 * time.Millisecond)
			}
			pw.Close()
		}
		start := time.Now()
		if code := post("/", stalls); code != http.StatusRequestTimeout || time.Since(start) > 5*time.Second {
			t.Errorf("stalled body: %d after %v", code, time.Since(start))
		}
		if code := post("/", trickles); code != http.StatusOK {
			t.Errorf("a body a byte every 100ms: %d", code)
		}
		if code := post("/?slow", trickles); code != http.StatusOK {
			t.Errorf("a body the origin is slow to take: %d", code)
		}
	})
	if s := st.site("127.0.0.1"); s.limitHits[limitBodyTimeout].Load() != 2 || s.proxyErrors[reasonSend].Load() != 0 {
		t.Fatalf("body_timeout %d, send errors %d", s.limitHits[limitBodyTimeout].Load(), s.proxyErrors[reasonSend].Load())
	}
}

// A response the visitor stops reading ends after stallTimeout: the write
// that waits on it fails, and frps lets go of the origin. One that comes
// in events with long quiet between them goes on.
func TestSiteResponseStall(t *testing.T) {
	shortStall(t, 300*time.Millisecond)
	ended := map[int]chan error{1: make(chan error, 1), 2: make(chan error, 1)} // by HTTP version
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			for _, ev := range []string{"a", "b", "c"} {
				io.WriteString(w, ev)
				http.NewResponseController(w).Flush()
				time.Sleep(700 * time.Millisecond)
			}
			return
		}
		chunk := make([]byte, 32<<10)
		var err error
		for i := 0; i < 4096 && err == nil; i++ { // 128 MiB, past every buffer on the way
			_, err = w.Write(chunk)
		}
		ended[r.ProtoMajor] <- err
	})
	h, err := Handler("tunnel.example.com", frps, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	overHTTP1And2(t, h, func(t *testing.T, url string, c *http.Client) {
		res, err := c.Get(url + "/events")
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(res.Body)
		res.Body.Close()
		if string(b) != "abc" || err != nil {
			t.Errorf("events: %q, %v", b, err)
		}
		res, err = c.Get(url + "/big")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		select {
		case err := <-ended[res.ProtoMajor]:
			if err == nil {
				t.Fatal("the whole response went to a visitor who read none of it")
			}
		case <-time.After(10 * time.Second): // crypto/tls gives its close_notify 5 s
			t.Fatal("the write to a visitor who reads nothing never failed")
		}
	})
}

// An HTTP/2 visitor that grants a stream no window holds it no longer
// than stallTimeout, even once frps is done with it: net/http sends the
// response's last bytes after the handler returns.
func TestSiteHTTP2StreamWithoutWindowEnds(t *testing.T) {
	shortStall(t, 200*time.Millisecond)
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "a short answer") })
	h, err := Handler("tunnel.example.com", frps, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.Config = newServer("", h, nil)
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	c := s.Client()
	c.Transport.(*http.Transport).HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: 1}
	res, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	time.Sleep(time.Second)
	if b, err := io.ReadAll(res.Body); err == nil || res.ProtoMajor != 2 {
		t.Fatalf("HTTP/%d: read %q after the stream should have ended", res.ProtoMajor, b)
	}
}

// A WebSocket is not under stallTimeout: once switched, it is quiet for
// as long as its ends like.
func TestSiteWebSocketOutlivesStallTimeout(t *testing.T) {
	shortStall(t, 100*time.Millisecond)
	frps := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		rw.WriteString("echo " + line)
		rw.Flush()
	})
	h, err := Handler("tunnel.example.com", frps, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr := serving(t, h)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", res, err)
	}
	time.Sleep(500 * time.Millisecond)
	io.WriteString(c, "hi\n")
	if line, err := br.ReadString('\n'); line != "echo hi\n" {
		t.Fatalf("after five times stallTimeout quiet: %q, %v", line, err)
	}
}
