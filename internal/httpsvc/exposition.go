package httpsvc

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sebiee/fortressedge/internal/metrics"
)

// writeMetrics writes what the HTTP side counts, as /~!ops/metrics
// serves it. Label sets that never happened are left out: an edge with
// a few dozen sites stays at a few hundred series.
func writeMetrics(w *metrics.Writer, st *httpStats, filt edgeFilter, track *conns, vis *visitors, domains *Domains) {
	if track != nil {
		w.Family("fortressedge_connections", "gauge", "Open connections on ports 80 and 443, upgraded ones included.")
		w.Int("fortressedge_connections", int64(track.Len()))
	}
	st.writeMetrics(w)
	if vis != nil {
		vis.writeMetrics(w)
	}
	if filt != nil {
		writeXDP(w, filt)
	}
	w.Family("fortressedge_kernel_tcp_total", "counter", "The kernel's TCP counters since boot (/proc/net/netstat, snmp), by counter.")
	k := kernelTCP()
	for _, name := range slices.Sorted(maps.Keys(k)) {
		w.Int("fortressedge_kernel_tcp_total", int64(k[name]), "counter", name)
	}
	domains.writeMetrics(w)
}

func (st *httpStats) writeMetrics(w *metrics.Writer) {
	st.mu.Lock()
	names := slices.Sorted(maps.Keys(st.sites))
	sites := make([]*siteStats, len(names))
	for i, n := range names {
		sites[i] = st.sites[n]
	}
	st.mu.Unlock()

	w.Family("fortressedge_http_requests_total", "counter", "Site requests, by site (the published name) and status class.")
	for i, s := range sites {
		for c := 1; c < len(s.status); c++ {
			if n := s.status[c].Load(); n > 0 {
				w.Int("fortressedge_http_requests_total", n, "site", names[i], "code_class", strconv.Itoa(c)+"xx")
			}
		}
	}
	w.Family("fortressedge_http_request_duration_seconds", "histogram",
		"Time from a site request's arrival to its response headers, by site.")
	for i, s := range sites {
		s.headers.Write(w, "fortressedge_http_request_duration_seconds", "site", names[i])
	}
	w.Family("fortressedge_http_request_seconds_total", "counter",
		"Site requests' whole time, bodies and upgraded streams included, by site.")
	for i, s := range sites {
		w.Sample("fortressedge_http_request_seconds_total", time.Duration(s.totalNS.Load()).Seconds(), "site", names[i])
	}
	w.Family("fortressedge_http_bytes_total", "counter", "Body bytes of site requests (in) and responses (out), by site.")
	for i, s := range sites {
		w.Int("fortressedge_http_bytes_total", s.bytesIn.Load(), "site", names[i], "direction", "in")
		w.Int("fortressedge_http_bytes_total", s.bytesOut.Load(), "site", names[i], "direction", "out")
	}
	w.Family("fortressedge_http_requests_in_flight", "gauge", "Site requests being served now, by site.")
	for i, s := range sites {
		w.Int("fortressedge_http_requests_in_flight", s.inFlight.Load(), "site", names[i])
	}
	w.Family("fortressedge_proxy_errors_total", "counter",
		"Site requests frps could not proxy, by site and reason: no_tunnel, dial, send, header_timeout, eof_headers, eof_body.")
	for i, s := range sites {
		for r := range nReasons {
			if n := s.proxyErrors[r].Load(); n > 0 {
				w.Int("fortressedge_proxy_errors_total", n, "site", names[i], "reason", reasonNames[r])
			}
		}
	}
	st.limitFamily(w, names, sites)
}

// limitFamily starts fortressedge_limit_hits_total with the sites' hits;
// visitors adds the hits no site can be named for.
func (st *httpStats) limitFamily(w *metrics.Writer, names []string, sites []*siteStats) {
	w.Family("fortressedge_limit_hits_total", "counter",
		"Requests and connections the visitor limits refused, by site and limit: rate, uri, body, malformed, connections (no site).")
	for i, s := range sites {
		for l := range nLimits {
			if n := s.limitHits[l].Load(); n > 0 {
				w.Int("fortressedge_limit_hits_total", n, "site", names[i], "limit", limitNames[l])
			}
		}
	}
}

func (v *visitors) writeMetrics(w *metrics.Writer) {
	// Continues fortressedge_limit_hits_total.
	w.Int("fortressedge_limit_hits_total", v.connLimited.Load(), "limit", "connections")
	w.Family("fortressedge_visitors", "gauge", "Sources (IPv4 addresses, IPv6 /64s) the limits track now.")
	v.mu.Lock()
	n := len(v.m)
	v.mu.Unlock()
	w.Int("fortressedge_visitors", int64(n))
	w.Family("fortressedge_bans_total", "counter", "Sources banned in XDP for breaking the limits.")
	w.Int("fortressedge_bans_total", v.bans.Load())
	w.Family("fortressedge_banned_sources", "gauge", "Sources banned now.")
	w.Int("fortressedge_banned_sources", int64(v.banned()))
}

func writeXDP(w *metrics.Writer, filt edgeFilter) {
	stats := filt.Stats()
	w.Family("fortressedge_xdp_packets_total", "counter", "Packets the XDP filter saw, by action (pass, drop) and reason.")
	for _, name := range slices.Sorted(maps.Keys(stats)) {
		action, reason, _ := strings.Cut(name, "_")
		if name == "pass" {
			reason = "service" // HTTP, HTTPS, and QUIC to the edge's ports
		}
		if action != "pass" && action != "drop" {
			continue
		}
		w.Int("fortressedge_xdp_packets_total", int64(stats[name]), "action", action, "reason", reason)
	}
	if et, ok := filt.(interface{ EtherTypes() map[string]uint64 }); ok {
		m := et.EtherTypes()
		w.Family("fortressedge_xdp_ethertype_drops_total", "counter",
			"Frames dropped for their EtherType (reason ethertype), by EtherType: 0x88cc is LLDP, llc an IEEE 802.3 frame such as STP.")
		for _, t := range slices.Sorted(maps.Keys(m)) {
			w.Int("fortressedge_xdp_ethertype_drops_total", int64(m[t]), "ethertype", t)
		}
	}
}

func (d *Domains) writeMetrics(w *metrics.Writer) {
	if d == nil {
		return
	}
	w.Family("fortressedge_published_names", "gauge", "Names dark nodes publish now, wildcards included.")
	w.Int("fortressedge_published_names", int64(d.Published()))
	d.mu.Lock()
	names := []string{d.tunnel}
	for name := range d.names {
		if name != d.tunnel && issueable(name) {
			names = append(names, name)
		}
	}
	cache := d.cache
	d.mu.Unlock()
	slices.Sort(names[1:])
	w.Family("fortressedge_certificate_not_after_seconds", "gauge",
		"When the certificate the edge serves for a name expires, in Unix seconds: the tunnel name and each site.")
	if cache != nil {
		for _, name := range names {
			var last time.Time
			for _, c := range cache.AllMatchingCertificates(name) {
				if c.Leaf != nil && c.Leaf.NotAfter.After(last) {
					last = c.Leaf.NotAfter
				}
			}
			if !last.IsZero() {
				w.Int("fortressedge_certificate_not_after_seconds", last.Unix(), "name", name)
			}
		}
	}
	d.certMu.Lock()
	orders := maps.Clone(d.orders)
	d.certMu.Unlock()
	keys := slices.SortedFunc(maps.Keys(orders), func(a, b certOrder) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return strings.Compare(result(a.ok), result(b.ok))
	})
	for _, renewal := range []bool{false, true} {
		name, help := "fortressedge_certificate_obtains_total", "First certificates obtained for a name, by name and result (ok, failed)."
		if renewal {
			name, help = "fortressedge_certificate_renewals_total", "Certificate renewals, by name and result (ok, failed)."
		}
		w.Family(name, "counter", help)
		for _, k := range keys {
			if k.renewal == renewal {
				w.Int(name, orders[k], "name", k.name, "result", result(k.ok))
			}
		}
	}
}

func result(ok bool) string {
	if ok {
		return "ok"
	}
	return "failed"
}
