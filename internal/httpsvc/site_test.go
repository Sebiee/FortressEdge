package httpsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
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
		func(host string) (string, bool) { return host, host == "app.example.com" }, nil)
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
	route := func(host string) (string, bool) { return "*.example.com", true }
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
