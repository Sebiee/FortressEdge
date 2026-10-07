package main

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

var tlsRoutes = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "tlsroutes"}

// alpnAnnotation lists the ALPN protocols a TLSRoute's clients may
// select, comma-separated: postgresql for PostgreSQL's direct TLS. A
// client that offers none of them is refused.
const alpnAnnotation = "fortressedge.io/alpn"

// tlsProxyPrefix names a TLSRoute hostname's proxy apart from an
// HTTPRoute hostname's, which is the name itself.
const tlsProxyPrefix = "tls:"

type tlsRoute struct {
	Spec struct {
		Hostnames []string `json:"hostnames"`
		Rules     []struct {
			BackendRefs []struct {
				Group     *string `json:"group"`
				Kind      *string `json:"kind"`
				Name      string  `json:"name"`
				Namespace *string `json:"namespace"`
				Port      *int32  `json:"port"`
			} `json:"backendRefs"`
		} `json:"rules"`
	} `json:"spec"`
	Status routeStatus `json:"status"`
}

// refusal is a TLSRoute, or one of its hostnames, that fortresskube does
// not publish, and why.
type refusal struct {
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

// Why a TLSRoute or a hostname of it is not published.
const (
	refusedNoHostnames   = "no_hostnames"          // the edge gets a certificate per exact name
	refusedHostname      = "invalid_hostname"      // a wildcard, or not a DNS name
	refusedBackend       = "invalid_backend"       // no backendRefs, not a Service, or no port
	refusedNamespace     = "backend_namespace"     // a Service in another namespace: no ReferenceGrant check
	refusedALPN          = "invalid_alpn"          // fortressedge.io/alpn
	refusedHTTPRoute     = "hostname_of_httproute" // a name is an HTTP name or a TCP route
	refusedOlderTLSRoute = "hostname_of_tlsroute"  // an older TLSRoute has it
)

var refusalReasons = []string{
	refusedNoHostnames, refusedHostname, refusedBackend, refusedNamespace, refusedALPN, refusedHTTPRoute, refusedOlderTLSRoute,
}

// publishedTLS is one tcp-tls proxy per hostname of each TLSRoute the
// Gateway gwNS/gwName reports as Accepted, dialing the route's first
// backend Service directly: the edge ends TLS, so the Gateway's proxy,
// which routes a TLS stream by its server name, cannot take the stream.
// A hostname an HTTPRoute publishes (httpNames) is refused, and so is one
// an older TLSRoute has.
func publishedTLS(objs []any, gwNS, gwName string, httpNames map[string]bool) ([]v1.ProxyConfigurer, []refusal) {
	type candidate struct {
		u *unstructured.Unstructured
		r tlsRoute
	}
	var routes []candidate
	for _, o := range objs {
		u, ok := o.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		var r tlsRoute
		if runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &r) != nil || !r.Status.acceptedBy(u.GetNamespace(), gwNS, gwName) {
			continue
		}
		routes = append(routes, candidate{u, r})
	}
	// The oldest route keeps a hostname two routes name.
	slices.SortFunc(routes, func(a, b candidate) int {
		if c := a.u.GetCreationTimestamp().Compare(b.u.GetCreationTimestamp().Time); c != 0 {
			return c
		}
		return cmp.Compare(a.u.GetNamespace()+"/"+a.u.GetName(), b.u.GetNamespace()+"/"+b.u.GetName())
	})
	var (
		out     []v1.ProxyConfigurer
		refused []refusal
		taken   = map[string]bool{}
	)
	for _, c := range routes {
		ns, key := c.u.GetNamespace(), c.u.GetNamespace()+"/"+c.u.GetName()
		host, port, reason := backendOf(&c.r, ns)
		if reason == "" {
			reason = checkALPN(c.u.GetAnnotations()[alpnAnnotation])
		}
		if reason == "" && len(c.r.Spec.Hostnames) == 0 {
			reason = refusedNoHostnames
		}
		if reason != "" {
			refused = append(refused, refusal{route: key, reason: reason})
			continue
		}
		alpn := splitALPN(c.u.GetAnnotations()[alpnAnnotation])
		for _, h := range c.r.Spec.Hostnames {
			h = strings.ToLower(h)
			switch {
			case strings.Contains(h, "*") || len(k8svalidation.IsDNS1123Subdomain(h)) > 0:
				refused = append(refused, refusal{key, h, refusedHostname})
				continue
			case httpNames[h]:
				refused = append(refused, refusal{key, h, refusedHTTPRoute})
				continue
			case taken[h]:
				refused = append(refused, refusal{key, h, refusedOlderTLSRoute})
				continue
			}
			taken[h] = true
			p := &v1.TCPTLSProxyConfig{CustomDomains: []string{h}, ALPN: alpn}
			p.Name, p.Type, p.LocalIP, p.LocalPort = tlsProxyPrefix+h, string(v1.ProxyTypeTCPTLS), host, port
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b v1.ProxyConfigurer) int {
		return cmp.Compare(a.GetBaseConfig().Name, b.GetBaseConfig().Name)
	})
	return out, refused
}

// backendOf is the route's first backend, a Service of its own
// namespace, as <name>.<namespace>.svc and its port; or why there is none.
func backendOf(r *tlsRoute, ns string) (host string, port int, reason string) {
	if len(r.Spec.Rules) == 0 || len(r.Spec.Rules[0].BackendRefs) == 0 {
		return "", 0, refusedBackend
	}
	b := r.Spec.Rules[0].BackendRefs[0]
	if deref(b.Group, "") != "" || deref(b.Kind, "Service") != "Service" || b.Name == "" || b.Port == nil || *b.Port < 1 || *b.Port > 65535 {
		return "", 0, refusedBackend
	}
	if deref(b.Namespace, ns) != ns {
		return "", 0, refusedNamespace
	}
	return fmt.Sprintf("%s.%s.svc", b.Name, ns), int(*b.Port), ""
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
	refused   map[refusal]bool // now
	refusals  map[string]int64 // each time a refusal appeared, by reason
}

// update records a publication, and returns the refusals that are new
// since the last.
func (s *routeStats) update(http, tls int, refused []refusal) []refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refusals == nil {
		s.refusals = map[string]int64{}
	}
	now := map[refusal]bool{}
	var fresh []refusal
	for _, r := range refused {
		now[r] = true
		if !s.refused[r] {
			fresh = append(fresh, r)
			s.refusals[r.reason]++
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
	now := map[string]int{}
	for r := range s.refused {
		now[r.reason]++
	}
	fmt.Fprintln(w, "# HELP fortresskube_refused_tlsroutes TLSRoutes and TLSRoute hostnames not published now, by reason.")
	fmt.Fprintln(w, "# TYPE fortresskube_refused_tlsroutes gauge")
	for _, reason := range refusalReasons {
		fmt.Fprintf(w, "fortresskube_refused_tlsroutes{reason=%q} %d\n", reason, now[reason])
	}
	fmt.Fprintln(w, "# HELP fortresskube_tlsroute_refusals_total Times a TLSRoute or hostname came to be refused, by reason.")
	fmt.Fprintln(w, "# TYPE fortresskube_tlsroute_refusals_total counter")
	for _, reason := range slices.Sorted(maps.Keys(s.refusals)) {
		fmt.Fprintf(w, "fortresskube_tlsroute_refusals_total{reason=%q} %d\n", reason, s.refusals[reason])
	}
}
