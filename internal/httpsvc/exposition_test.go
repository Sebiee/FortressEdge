package httpsvc

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// xdpFilt is an edgeFilter with counters and EtherTypes.
type xdpFilt struct{}

func (xdpFilt) Ban(netip.Addr, time.Duration) error { return nil }
func (xdpFilt) Stats() map[string]uint64 {
	return map[string]uint64{"pass": 10, "drop_ethertype": 4, "pass_arp": 2}
}
func (xdpFilt) EtherTypes() map[string]uint64 { return map[string]uint64{"0x88cc": 3, "llc": 1} }

// Every sample follows its own family's TYPE line, and no family comes
// twice: what Prometheus's parser insists on.
func TestWriteMetrics(t *testing.T) {
	st := &httpStats{}
	s := st.site("*.example.com")
	s.requests.Add(3)
	s.status[2].Add(2)
	s.status[5].Add(1)
	s.headers.Observe(30 * time.Millisecond)
	s.proxyErrors[reasonEOFBody].Add(1)
	s.limitHits[limitRate].Add(4)
	st.site("b.example.com").requests.Add(1)
	vis := limitedVisitors(config.DefaultLimits(), nil, nil)
	vis.connLimited.Add(2)
	var b bytes.Buffer
	w := metrics.NewWriter(&b)
	writeMetrics(w, st, xdpFilt{}, newConns(), vis, NewDomains("tunnel.example.com"))
	w.Flush()
	out := b.String()

	seen := map[string]bool{}
	family := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			family, _, _ = strings.Cut(name, " ")
			if seen[family] {
				t.Fatalf("family %s twice", family)
			}
			seen[family] = true
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		name, _, _ := strings.Cut(line, "{")
		name, _, _ = strings.Cut(name, " ")
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
		if name != family && base != family {
			t.Fatalf("sample %q outside its family (in %s)", line, family)
		}
	}
	for _, want := range []string{
		`fortressedge_http_requests_total{site="*.example.com",code_class="2xx"} 2`,
		`fortressedge_http_requests_total{site="*.example.com",code_class="5xx"} 1`,
		`fortressedge_http_request_duration_seconds_bucket{site="*.example.com",le="0.1"} 1`,
		`fortressedge_proxy_errors_total{site="*.example.com",reason="eof_body"} 1`,
		`fortressedge_limit_hits_total{site="*.example.com",limit="rate"} 4`,
		`fortressedge_limit_hits_total{limit="connections"} 2`,
		`fortressedge_http_requests_in_flight{site="b.example.com"} 0`,
		`fortressedge_xdp_packets_total{action="pass",reason="service"} 10`,
		`fortressedge_xdp_packets_total{action="drop",reason="ethertype"} 4`,
		`fortressedge_xdp_ethertype_drops_total{ethertype="0x88cc"} 3`,
		`fortressedge_published_names 0`,
		`fortressedge_banned_sources 0`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("no %s", want)
		}
	}
	// A reason or class that never happened is no series.
	if strings.Contains(out, `reason="dial"`) || strings.Contains(out, `code_class="4xx"`) {
		t.Fatalf("zero series written:\n%s", out)
	}
}
