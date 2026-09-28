package httpsvc

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"uuid"
)

// requestIDHeader carries a site request's id back to the visitor, who
// can quote it. The dark node gets it as X-Request-Id, the header gateways
// log, so one id finds the request in the edge's access log and the
// gateway's.
const requestIDHeader = "Fortress-Request-Id"

// requestIDHeaderOut carries the same id to the dark node.
const requestIDHeaderOut = "X-Request-Id"

// siteStats counts one published hostname's requests.
type siteStats struct {
	requests, inFlight, bytesIn, bytesOut atomic.Int64
	status                                [6]atomic.Int64 // by class: status[2] is 2xx
}

func (s *siteStats) snapshot() map[string]int64 {
	m := map[string]int64{
		"requests":  s.requests.Load(),
		"in_flight": s.inFlight.Load(),
		"bytes_in":  s.bytesIn.Load(),
		"bytes_out": s.bytesOut.Load(),
	}
	for c := 1; c < len(s.status); c++ {
		m[string(rune('0'+c))+"xx"] = s.status[c].Load()
	}
	return m
}

type httpStats struct {
	req, badGateway, rejected atomic.Int64

	mu    sync.Mutex
	sites map[string]*siteStats
	// access is the access log; nil when access_log is off.
	access *slog.Logger
}

func (st *httpStats) site(host string) *siteStats {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sites == nil {
		st.sites = make(map[string]*siteStats)
	}
	s := st.sites[host]
	if s == nil {
		s = &siteStats{}
		st.sites[host] = s
	}
	return s
}

func (st *httpStats) sitesSnapshot() map[string]map[string]int64 {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make(map[string]map[string]int64, len(st.sites))
	for host, s := range st.sites {
		out[host] = s.snapshot()
	}
	return out
}

// newAccessLog writes one JSON object per line to w: time, then the
// request's fields.
func newAccessLog(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
				return slog.Attr{}
			}
			return a
		},
	}))
}

// serveSite proxies a request for a published hostname: it gets an id,
// and is counted for host and written to the access log once it ends.
func (st *httpStats) serveSite(h http.Handler, host string, w http.ResponseWriter, r *http.Request) {
	if st == nil {
		h.ServeHTTP(w, r)
		return
	}
	s := st.site(host)
	id := uuid.NewV7().String()
	r.Header.Set(requestIDHeaderOut, id) // replaces one the visitor sent
	w.Header().Set(requestIDHeader, id)
	body := &countingBody{ReadCloser: r.Body}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = body
	}
	rec := &recorder{ResponseWriter: w}
	start := time.Now()
	s.requests.Add(1)
	s.inFlight.Add(1)
	defer func() {
		p := recover()
		s.inFlight.Add(-1)
		status := rec.status
		if status == 0 {
			status = http.StatusOK // nothing written: net/http sends 200
			if p != nil {
				status = statusClientClosed
			}
		}
		// frps answers 502 or 504 for an origin that failed, and 502 too
		// for a visitor who left: that one is the visitor's, not the origin's.
		if status == http.StatusBadGateway || status == http.StatusGatewayTimeout {
			if r.Context().Err() != nil {
				status = statusClientClosed
			} else {
				st.badGateway.Add(1)
			}
		}
		in, out := body.n.Load(), rec.n
		s.bytesIn.Add(in)
		s.bytesOut.Add(out)
		if c := status / 100; c > 0 && c < len(s.status) {
			s.status[c].Add(1)
		}
		if st.access != nil {
			// The path only: query strings carry tokens and session ids.
			st.access.LogAttrs(context.Background(), slog.LevelInfo, "",
				slog.String("id", id),
				slog.String("ip", clientIP(r).String()),
				slog.String("site", host),
				slog.String("method", r.Method),
				slog.String("path", r.URL.EscapedPath()),
				slog.String("proto", r.Proto),
				slog.Int("status", status),
				slog.Int64("in", in),
				slog.Int64("out", out),
				slog.Int64("ms", time.Since(start).Milliseconds()),
				slog.String("ua", r.UserAgent()),
			)
		}
		if p != nil {
			panic(p)
		}
	}()
	h.ServeHTTP(rec, r)
}

// statusClientClosed is nginx's 499: the visitor left before a response.
const statusClientClosed = 499

type countingBody struct {
	io.ReadCloser
	n atomic.Int64 // the transport may still read after the handler returns
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

// recorder keeps the status and the body size of a response. Flush and
// the rest reach the connection through Unwrap (http.ResponseController).
type recorder struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *recorder) WriteHeader(code int) {
	if w.status == 0 && code >= 200 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

// Hijack is a protocol upgrade (WebSocket): the proxy writes the 101 to
// the raw connection itself.
func (w *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil && w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return c, rw, err
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
