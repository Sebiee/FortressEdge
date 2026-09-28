package httpsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"
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
	st := &httpStats{access: newAccessLog(chanWriter(logc))}
	h, err := Handler("tunnel.example.com", vhost.Config.Handler, nil, nil, st, nil, nil)
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
		func(host string) bool { return host == "app.example.com" }, nil)
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
