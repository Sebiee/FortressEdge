package httpsvc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/fatedier/frp/pkg/util/vhost"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// requestIDHeader carries a site request's id back to the visitor, who
// can quote it. The dark node gets it as X-Request-Id, the header gateways
// log, so one id finds the request in the edge's access log and the
// gateway's.
const requestIDHeader = "Fortress-Request-Id"

// requestIDHeaderOut carries the same id to the dark node.
const requestIDHeaderOut = "X-Request-Id"

// Why frps could not proxy a request (vhost.ProxyError's stage), as
// metrics and log lines name it.
const (
	reasonNoRoute = iota
	reasonDial
	reasonSend
	reasonHeaderTimeout
	reasonEOFHeaders
	reasonEOFBody
	nReasons
)

var reasonNames = [nReasons]string{"no_route", "dial", "send", "header_timeout", "eof_headers", "eof_body"}

// The limits a request to a site can hit once it is routed. The rest
// (connections per source, the header size) act before the edge knows
// the site.
const (
	limitRate = iota
	limitURI
	limitBody
	limitMalformed
	nLimits
)

var limitNames = [nLimits]string{"rate", "uri", "body", "malformed"}

// siteStats counts one site's requests: one published name, which a
// wildcard route shares between every name it covers.
type siteStats struct {
	requests, inFlight, bytesIn, bytesOut atomic.Int64
	status                                [6]atomic.Int64 // by class: status[2] is 2xx
	// headers is the time to the response headers: the origin's
	// answering time, as the visitor saw it, less the network.
	headers     metrics.Histogram
	totalNS     atomic.Int64 // every request's whole time, body and streams included
	proxyErrors [nReasons]atomic.Int64
	limitHits   [nLimits]atomic.Int64
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
	// access is the access log; nil until a policy turns it on.
	access atomic.Pointer[slog.Logger]
}

// site returns the stats of the site published as route.
func (st *httpStats) site(route string) *siteStats {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sites == nil {
		st.sites = make(map[string]*siteStats)
	}
	s := st.sites[route]
	if s == nil {
		s = &siteStats{}
		st.sites[route] = s
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

// siteReq is one site request while the edge serves it. frps's error hook
// (ProxyError) finds it in the request's context, on the request's own
// goroutine.
type siteReq struct {
	id          string
	host, route string
	start       time.Time
	trace       trace
	site        *siteStats
	rec         *recorder
	body        *countingBody
	// failure is why frps could not proxy the request, for the access log.
	failure string
}

type siteReqKey struct{}

func siteReqOf(r *http.Request) *siteReq {
	rs, _ := r.Context().Value(siteReqKey{}).(*siteReq)
	return rs
}

// serveSite proxies a request for host, which the route published: it
// gets an id and a trace, the site's settings (pol), and is counted for
// the site and written to the access log once it ends.
func (st *httpStats) serveSite(h http.Handler, host, route string, pol config.Site, trustTrace bool, w http.ResponseWriter, r *http.Request) {
	s := st.site(route)
	rs := &siteReq{id: uuid.NewV7().String(), host: host, route: route, start: time.Now(), site: s}
	r.Header.Set(requestIDHeaderOut, rs.id) // replaces one the visitor sent
	w.Header().Set(requestIDHeader, rs.id)
	rs.trace = startTrace(r.Header, trustTrace)
	w.Header().Set(traceIDHeader, rs.trace.traceID)
	rs.rec = &recorder{ResponseWriter: w, start: rs.start}
	body := &countingBody{ReadCloser: r.Body}
	if r.Body != nil && r.Body != http.NoBody {
		if n := pol.MaxBodyBytes; n > 0 {
			// w, not the recorder: net/http closes the connection after a
			// body that went over, which only its own writer can mark.
			body.ReadCloser = http.MaxBytesReader(w, r.Body, n)
		}
		r.Body = body
	}
	rs.body = body
	ctx := context.WithValue(r.Context(), siteReqKey{}, rs)
	ctx = vhost.WithResponseHeaderTimeout(ctx, pol.ResponseHeaderTimeout)
	r = r.WithContext(ctx)
	s.requests.Add(1)
	s.inFlight.Add(1)
	defer func() {
		p := recover()
		st.finish(rs, r, pol.AccessLog, p != nil)
		if p != nil {
			panic(p)
		}
	}()
	if n := pol.MaxBodyBytes; n > 0 && r.ContentLength > n {
		s.limitHits[limitBody].Add(1)
		rs.rec.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	h.ServeHTTP(rs.rec, r)
}

// finish counts rs once it ended, aborted when the handler panicked (a
// hidden or cut response), and writes its access log line if logged.
func (st *httpStats) finish(rs *siteReq, r *http.Request, logged, aborted bool) {
	s := rs.site
	elapsed := time.Since(rs.start)
	s.inFlight.Add(-1)
	status := rs.rec.status
	if status == 0 {
		status = http.StatusOK // nothing written: net/http sends 200
		if aborted {
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
	in, out := rs.body.n.Load(), rs.rec.n
	s.bytesIn.Add(in)
	s.bytesOut.Add(out)
	if c := status / 100; c > 0 && c < len(s.status) {
		s.status[c].Add(1)
	}
	if rs.rec.headers > 0 {
		s.headers.Observe(rs.rec.headers)
	}
	s.totalNS.Add(int64(elapsed))
	if acc := st.access.Load(); acc != nil && logged {
		rs.log(acc, r, status, in, out, elapsed)
	}
}

// log writes rs's access log line. It carries what a collector needs to
// rebuild the edge's span: the trace, span, and parent ids, the start,
// and the durations.
func (rs *siteReq) log(acc *slog.Logger, r *http.Request, status int, in, out int64, elapsed time.Duration) {
	attrs := make([]slog.Attr, 0, 24)
	attrs = append(attrs,
		slog.String("id", rs.id),
		slog.String("ip", clientIP(r).String()),
		slog.String("site", rs.host),
	)
	if rs.route != rs.host {
		attrs = append(attrs, slog.String("route", rs.route))
	}
	attrs = append(attrs,
		slog.String("method", r.Method),
		// The path only: query strings carry tokens and session ids.
		slog.String("path", r.URL.EscapedPath()),
		slog.String("proto", r.Proto),
		slog.Int("status", status),
		slog.Int64("in", in),
		slog.Int64("out", out),
		slog.Int64("ms", elapsed.Milliseconds()),
		slog.String("start", rs.start.UTC().Format(time.RFC3339Nano)),
		slog.Int64("us", elapsed.Microseconds()),
	)
	if rs.rec.headers > 0 {
		attrs = append(attrs, slog.Int64("headers_us", rs.rec.headers.Microseconds()))
	}
	attrs = append(attrs,
		slog.String("ua", r.UserAgent()),
		slog.String("trace_id", rs.trace.traceID),
		slog.String("span_id", rs.trace.spanID),
	)
	if rs.trace.parent != "" {
		attrs = append(attrs, slog.String("parent_id", rs.trace.parent))
	}
	if l := rs.trace.link; l.valid() {
		attrs = append(attrs, slog.String("link_trace_id", l.traceID), slog.String("link_span_id", l.spanID))
	}
	if rs.failure != "" {
		attrs = append(attrs, slog.String("error", rs.failure))
	}
	acc.LogAttrs(context.Background(), slog.LevelInfo, "", attrs...)
}

// ProxyError is frps's error hook (OnProxyError): every request frps
// could not proxy, on the request's goroutine. It logs one line that says
// where it failed and for whom, and counts it for the site. frps then
// answers 502 or 504, or, when the body broke off, cuts the response.
func ProxyError(r *http.Request, err error) {
	rs := siteReqOf(r)
	if rs == nil { // not a site request of this edge: frps's own port
		slog.Warn("proxy error", "site", hostname(r.Host), "err", err)
		return
	}
	if rs.body.tooLarge.Load() {
		// The body passed max_body_size on the way: the visitor's, and
		// the answer is 413, not a failed origin.
		rs.site.limitHits[limitBody].Add(1)
		rs.rec.override = http.StatusRequestEntityTooLarge
		return
	}
	attrs := []any{
		"site", rs.host, "method", r.Method, "path", r.URL.EscapedPath(), "ip", clientIP(r).String(),
		"id", rs.id, "trace_id", rs.trace.traceID, "span_id", rs.trace.spanID,
	}
	if rs.route != rs.host {
		attrs = append(attrs, "route", rs.route)
	}
	var pe *vhost.ProxyError
	if !errors.As(err, &pe) {
		// The visitor left before the origin answered: its choice.
		slog.Debug("proxy: visitor left", append(attrs, "err", err)...)
		return
	}
	reason := proxyReason(pe)
	rs.failure = reasonNames[reason]
	rs.site.proxyErrors[reason].Add(1)
	slog.Warn("proxy error", append(attrs, "reason", rs.failure,
		"elapsed_ms", time.Since(rs.start).Milliseconds(), "sent", rs.rec.n, "err", pe.Err)...)
}

func proxyReason(pe *vhost.ProxyError) int {
	switch pe.Stage {
	case vhost.StageRoute:
		return reasonNoRoute
	case vhost.StageDial:
		return reasonDial
	case vhost.StageSend:
		return reasonSend
	case vhost.StageBody:
		return reasonEOFBody
	}
	var ne net.Error
	if errors.As(pe.Err, &ne) && ne.Timeout() {
		return reasonHeaderTimeout
	}
	return reasonEOFHeaders
}

// statusClientClosed is nginx's 499: the visitor left before a response.
const statusClientClosed = 499

type countingBody struct {
	io.ReadCloser
	n atomic.Int64 // the transport may still read after the handler returns
	// tooLarge is a body that went over max_body_size. The error frps
	// reports for it does not unwrap to the *http.MaxBytesError (net/http
	// wraps a body read error in a type of its own), so it is kept here.
	tooLarge atomic.Bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	var over *http.MaxBytesError
	if err != nil && errors.As(err, &over) {
		b.tooLarge.Store(true)
	}
	return n, err
}

// recorder keeps the status, the time to the headers, and the body size
// of a response. Flush and the rest reach the connection through Unwrap
// (http.ResponseController).
type recorder struct {
	http.ResponseWriter
	start   time.Time
	status  int
	headers time.Duration // since start, when they were written
	n       int64
	// override replaces the status frps writes: the edge knows better why
	// the request failed.
	override int
}

func (w *recorder) WriteHeader(code int) {
	if w.status == 0 && code >= 200 {
		if w.override != 0 {
			code = w.override
		}
		w.wrote(code)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) wrote(code int) {
	w.status = code
	if !w.start.IsZero() {
		w.headers = max(time.Since(w.start), 1)
	}
}

func (w *recorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.wrote(http.StatusOK)
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
		w.wrote(http.StatusSwitchingProtocols)
	}
	return c, rw, err
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
