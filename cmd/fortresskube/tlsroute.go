package main

import (
	"cmp"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/cache"
)

var tlsRoutes = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "tlsroutes"}

// alpnAnnotation lists the ALPN protocols a TLSRoute's clients may
// select, comma-separated: postgresql for PostgreSQL's direct TLS. A
// client that offers none of them is refused.
const alpnAnnotation = "fortressedge.io/alpn"

// tlsProxyPrefix names a TLSRoute hostname's proxy apart from an
// HTTPRoute hostname's, which is the name itself.
const tlsProxyPrefix = "tls:"

type backendRef struct {
	Group     *string `json:"group"`
	Kind      *string `json:"kind"`
	Name      string  `json:"name"`
	Namespace *string `json:"namespace"`
	Port      *int32  `json:"port"`
}

// refusal is a route, or one of its hostnames, that fortresskube does
// not publish, and why.
type refusal struct {
	kind     string // HTTPRoute or TLSRoute
	route    string // namespace/name
	hostname string // "" for the whole route
	reason   string
}

func (r refusal) String() string {
	if r.hostname == "" {
		return r.route + ": " + r.reason
	}
	return r.route + " " + r.hostname + ": " + r.reason
}

// Why a route or a hostname of it is not published.
const (
	refusedNoHostnames   = "no_hostnames"          // the edge gets a certificate per exact name
	refusedHostname      = "invalid_hostname"      // a wildcard, or not a DNS name
	refusedBackend       = "invalid_backend"       // no backendRefs, not a Service, or no port
	refusedNamespace     = "backend_namespace"     // a Service in another namespace: no ReferenceGrant check
	refusedService       = "backend_service"       // the Service is missing, ExternalName, or headless
	refusedALPN          = "invalid_alpn"          // fortressedge.io/alpn
	refusedHTTPRoute     = "hostname_of_httproute" // a name is an HTTP name or a TCP route
	refusedOlderTLSRoute = "hostname_of_tlsroute"  // an older TLSRoute has it
	refusedStatic        = "static_proxy"          // a proxy of the frpc config has it
)

// publishedTLS is one tcp-tls proxy per hostname of each TLSRoute gw
// accepted that a listener which accepted it takes, dialing the cluster
// IP of the route's first backend Service directly: the edge ends TLS,
// so the Gateway's proxy, which routes a TLS stream by its server name,
// cannot take the stream. A hostname a static proxy has is refused, and
// so are one an HTTPRoute publishes (httpNames) and one an older
// TLSRoute has.
func (p *publisher) publishedTLS(v view, gw *gateway, httpNames map[string]bool) ([]v1.ProxyConfigurer, []refusal) {
	rs := routes(v.tlsRoutes)
	// The oldest route keeps a hostname two routes name.
	slices.SortFunc(rs, func(a, b route) int {
		if c := a.Metadata.CreationTimestamp.Compare(b.Metadata.CreationTimestamp.Time); c != 0 {
			return c
		}
		return cmp.Compare(a.key(), b.key())
	})
	var (
		out     []v1.ProxyConfigurer
		refused []refusal
		taken   = map[string]bool{}
	)
	for _, r := range rs {
		ls := gw.accepted(&r, &tlsKind, labelsOf(v, r.Metadata.Namespace))
		if len(ls) == 0 {
			continue
		}
		key, annotation := r.key(), r.Metadata.Annotations[alpnAnnotation]
		ip, port, reason := backendOf(&r, v.services)
		if reason == "" {
			reason = checkALPN(annotation)
		}
		if reason == "" && len(r.Spec.Hostnames) == 0 {
			reason = refusedNoHostnames
		}
		if reason != "" {
			refused = append(refused, refusal{kind: tlsKind.name, route: key, reason: reason})
			continue
		}
		alpn := splitALPN(annotation)
		for _, h := range r.Spec.Hostnames {
			h = strings.ToLower(h)
			switch {
			case strings.Contains(h, "*") || len(k8svalidation.IsDNS1123Subdomain(h)) > 0:
				refused = append(refused, refusal{tlsKind.name, key, h, refusedHostname})
				continue
			case !covers(ls, h):
				continue
			case p.static[h]:
				refused = append(refused, refusal{tlsKind.name, key, h, refusedStatic})
				continue
			case httpNames[h]:
				refused = append(refused, refusal{tlsKind.name, key, h, refusedHTTPRoute})
				continue
			case taken[h]:
				refused = append(refused, refusal{tlsKind.name, key, h, refusedOlderTLSRoute})
				continue
			}
			taken[h] = true
			p := &v1.TCPTLSProxyConfig{CustomDomains: []string{h}, ALPN: alpn}
			p.Name, p.Type, p.LocalIP, p.LocalPort = tlsProxyPrefix+h, string(v1.ProxyTypeTCPTLS), ip, port
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b v1.ProxyConfigurer) int {
		return cmp.Compare(a.GetBaseConfig().Name, b.GetBaseConfig().Name)
	})
	return out, refused
}

// backendOf is the route's first backend, a Service of its own
// namespace, as its cluster IP and its port; or why there is none.
func backendOf(r *route, services cache.Store) (ip string, port int, reason string) {
	ns := r.Metadata.Namespace
	if len(r.Spec.Rules) == 0 || len(r.Spec.Rules[0].BackendRefs) == 0 {
		return "", 0, refusedBackend
	}
	b := r.Spec.Rules[0].BackendRefs[0]
	if deref(b.Group, "") != "" || deref(b.Kind, "Service") != "Service" || len(k8svalidation.IsDNS1035Label(b.Name)) > 0 ||
		b.Port == nil || *b.Port < 1 || *b.Port > 65535 {
		return "", 0, refusedBackend
	}
	if deref(b.Namespace, ns) != ns {
		return "", 0, refusedNamespace
	}
	ip, ok := clusterIP(services, ns, b.Name)
	if !ok {
		return "", 0, refusedService
	}
	return ip, int(*b.Port), ""
}

// clusterIP is the cluster IP of the Service ns/name. A missing Service
// has none, nor has a headless or an ExternalName one: a name to resolve
// could point anywhere, the cloud's metadata service and the API server
// included.
func clusterIP(services cache.Store, ns, name string) (string, bool) {
	var svc struct {
		Spec struct {
			Type      string `json:"type"`
			ClusterIP string `json:"clusterIP"`
		} `json:"spec"`
	}
	if !get(services, ns+"/"+name, &svc) || svc.Spec.Type == "ExternalName" {
		return "", false
	}
	ip, err := netip.ParseAddr(svc.Spec.ClusterIP)
	return ip.String(), err == nil
}

func splitALPN(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// checkALPN refuses what the edge would: a protocol name of more than
// 255 bytes, or the ACME challenge's.
func checkALPN(s string) string {
	for _, p := range splitALPN(s) {
		if len(p) > 255 || p == "acme-tls/1" {
			return refusedALPN
		}
	}
	return ""
}

// routeStats is what fortresskube publishes and refuses, for its metrics
// and its log.
type routeStats struct {
	mu        sync.Mutex
	http, tls int
	refused   map[refusal]bool     // now
	refusals  map[kindReason]int64 // each time a refusal appeared
}

type kindReason struct{ kind, reason string }

// update records a publication, and returns the refusals that are new
// since the last.
func (s *routeStats) update(http, tls int, refused []refusal) []refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refusals == nil {
		s.refusals = map[kindReason]int64{}
	}
	now := map[refusal]bool{}
	var fresh []refusal
	for _, r := range refused {
		now[r] = true
		if !s.refused[r] {
			fresh = append(fresh, r)
			s.refusals[kindReason{r.kind, r.reason}]++
		}
	}
	s.http, s.tls, s.refused = http, tls, now
	return fresh
}

func (s *routeStats) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP fortresskube_published_names Names fortresskube publishes, by the kind of route: http (HTTPRoute), tls (TLSRoute).")
	fmt.Fprintln(w, "# TYPE fortresskube_published_names gauge")
	fmt.Fprintf(w, "fortresskube_published_names{kind=\"http\"} %d\n", s.http)
	fmt.Fprintf(w, "fortresskube_published_names{kind=\"tls\"} %d\n", s.tls)
	now := map[kindReason]int{}
	for r := range s.refused {
		now[kindReason{r.kind, r.reason}]++
	}
	for _, k := range []*routeKind{&httpKind, &tlsKind} {
		m := strings.ToLower(k.name)
		fmt.Fprintf(w, "# HELP fortresskube_refused_%ss %ss and %s hostnames not published now, by reason.\n", m, k.name, k.name)
		fmt.Fprintf(w, "# TYPE fortresskube_refused_%ss gauge\n", m)
		for _, reason := range k.refusals {
			fmt.Fprintf(w, "fortresskube_refused_%ss{reason=%q} %d\n", m, reason, now[kindReason{k.name, reason}])
		}
		fmt.Fprintf(w, "# HELP fortresskube_%s_refusals_total Times a %s or hostname came to be refused, by reason.\n", m, k.name)
		fmt.Fprintf(w, "# TYPE fortresskube_%s_refusals_total counter\n", m)
		for _, reason := range k.refusals {
			fmt.Fprintf(w, "fortresskube_%s_refusals_total{reason=%q} %d\n", m, reason, s.refusals[kindReason{k.name, reason}])
		}
	}
}
