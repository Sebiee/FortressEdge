package httpsvc

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	idleTimeout = 65 * time.Second
	hstsHeader  = "max-age=63072000; includeSubDomains"
)

// edgeFilter is the XDP blocklist. Stats feeds ops/status. Ban pins a
// source that keeps breaking the visitor limits, so its later packets die
// in XDP.
type edgeFilter interface {
	Ban(netip.Addr, time.Duration) error
	Stats() map[string]uint64
}

func clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func statusExtra(st *httpStats, filt edgeFilter, track *conns, vis *visitors) map[string]any {
	m := map[string]any{
		"connections":      track.Len(),
		"http_requests":    st.req.Load(),
		"http_bad_gateway": st.badGateway.Load(),
		"http_rejected":    st.rejected.Load(),
		"sites":            st.sitesSnapshot(),
		"kernel_tcp":       kernelTCP(),
	}
	if vis != nil {
		for k, v := range vis.stats() {
			m[k] = v
		}
	}
	if filt != nil {
		for k, v := range filt.Stats() {
			m["xdp_"+k] = v
		}
	}
	return m
}

// protect counts every request on 443 and sets the security headers. A
// site request's body limit is its site's (serveSite).
func protect(h http.Handler, st *httpStats) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st != nil {
			st.req.Add(1)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", hstsHeader)
		}
		h.ServeHTTP(w, r)
	})
}

// refuseMalformed answers a request malformed finds with its status and
// an empty body. It sits behind routing, so a name the edge does not
// serve stays silent whatever the path.
func refuseMalformed(h http.Handler, st *httpStats, lim *liveLimits) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := malformed(r, lim.get().MaxURIBytes); code != 0 {
			if st != nil {
				st.rejected.Add(1)
			}
			if rs := siteReqOf(r); rs != nil {
				hit := limitMalformed
				if code == http.StatusRequestURITooLong {
					hit = limitURI
				}
				rs.site.limitHits[hit].Add(1)
			}
			w.WriteHeader(code)
			return
		}
		if r.Method == http.MethodOptions && r.RequestURI == "*" {
			// A question for the server, not a site; proxied, it would
			// become "OPTIONS /*". Answered here, as net/http would.
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// malformed returns the status for a request no site should get, 0 for
// the rest. net/http has already refused broken framing and control
// characters. Ambiguous paths are refused rather than cleaned up, so the
// edge and the gateway behind it cannot read one path two ways. Browsers
// never send dot segments; they resolve them first.
func malformed(r *http.Request, maxURI int) int {
	switch r.Method {
	case http.MethodTrace, "TRACK", http.MethodConnect:
		return http.StatusMethodNotAllowed
	}
	if len(r.RequestURI) > maxURI {
		return http.StatusRequestURITooLong
	}
	if r.Method == http.MethodOptions && r.RequestURI == "*" {
		return 0
	}
	p := r.URL.Path
	if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || strings.Contains(p, "\\") {
		return http.StatusBadRequest
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return http.StatusBadRequest
		}
	}
	return 0
}
