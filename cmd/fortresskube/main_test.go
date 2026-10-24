package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

const controller = "example.com/gateway-controller"

var public = map[string]any{"name": "public", "namespace": "infra"}

// obj is m as an informer's store holds it.
func obj(t *testing.T, m map[string]any) *unstructured.Unstructured {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	u := &unstructured.Unstructured{}
	require.NoError(t, u.UnmarshalJSON(b))
	return u
}

// gatewayObj is the Gateway infra/public, of the class cilium, with
// listeners; with none, an HTTP one and a TLS one that take every route.
func gatewayObj(t *testing.T, listeners ...map[string]any) *unstructured.Unstructured {
	all := map[string]any{"namespaces": map[string]any{"from": "All"}}
	if listeners == nil {
		listeners = []map[string]any{
			{"name": "http", "protocol": "HTTP", "port": 80, "allowedRoutes": all},
			{"name": "tls", "protocol": "TLS", "port": 443, "allowedRoutes": all},
		}
	}
	return obj(t, map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]any{"namespace": "infra", "name": "public"},
		"spec":     map[string]any{"gatewayClassName": "cilium", "listeners": listeners},
	})
}

func nsObj(t *testing.T, name string, labels map[string]string) *unstructured.Unstructured {
	return obj(t, map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": name, "labels": labels},
	})
}

func svcObj(t *testing.T, ns, name string, spec map[string]any) *unstructured.Unstructured {
	return obj(t, map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"namespace": ns, "name": name},
		"spec":     spec,
	})
}

func clusterIPSvc(t *testing.T, ns, name, ip string) *unstructured.Unstructured {
	return svcObj(t, ns, name, map[string]any{"type": "ClusterIP", "clusterIP": ip})
}

func classObj(t *testing.T, name, controllerName string) *unstructured.Unstructured {
	return obj(t, map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
		"metadata": map[string]any{"name": name},
		"spec":     map[string]any{"controllerName": controllerName},
	})
}

// testRoute is a route; a field left zero is the common case.
type testRoute struct {
	kind        string // HTTPRoute (when "") or TLSRoute
	ns, name    string
	age         time.Time
	generation  int64 // 1 when 0
	annotations map[string]string
	hostnames   []string
	parentRefs  []map[string]any // public when nil
	backend     map[string]any   // the first rule's backendRef; none when nil
	status      []map[string]any // accepted at each parentRef when nil
}

func (r testRoute) obj(t *testing.T) *unstructured.Unstructured {
	t.Helper()
	r.kind = cmp.Or(r.kind, "HTTPRoute")
	r.generation = cmp.Or(r.generation, 1)
	if r.parentRefs == nil {
		r.parentRefs = []map[string]any{public}
	}
	if r.status == nil {
		for _, ref := range r.parentRefs {
			r.status = append(r.status, status(ref, controller, r.generation, "True", "True"))
		}
	}
	meta := map[string]any{"namespace": r.ns, "name": cmp.Or(r.name, "r"), "generation": r.generation, "creationTimestamp": r.age.UTC().Format(time.RFC3339)}
	if r.annotations != nil {
		meta["annotations"] = r.annotations
	}
	spec := map[string]any{"parentRefs": r.parentRefs, "hostnames": r.hostnames}
	if r.backend != nil {
		spec["rules"] = []map[string]any{{"backendRefs": []map[string]any{r.backend}}}
	}
	return obj(t, map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": r.kind,
		"metadata": meta, "spec": spec, "status": map[string]any{"parents": r.status},
	})
}

// status is a route's status at ref, as controllerName wrote it for
// generation.
func status(ref map[string]any, controllerName string, generation int64, accepted, resolvedRefs string) map[string]any {
	return map[string]any{
		"parentRef":      ref,
		"controllerName": controllerName,
		"conditions": []map[string]any{
			{"type": "Accepted", "status": accepted, "observedGeneration": generation},
			{"type": "ResolvedRefs", "status": resolvedRefs, "observedGeneration": generation},
		},
	}
}

// apiView is a view of objs, as the informers' stores hold them, with
// TLSRoutes watched.
func apiView(t *testing.T, objs ...*unstructured.Unstructured) view {
	t.Helper()
	newStore := func() cache.Store { return cache.NewStore(cache.MetaNamespaceKeyFunc) }
	v := view{gateways: newStore(), classes: newStore(), namespaces: newStore(), services: newStore(), httpRoutes: newStore(), tlsRoutes: newStore()}
	stores := map[string]cache.Store{
		"Gateway": v.gateways, "GatewayClass": v.classes, "Namespace": v.namespaces, "Service": v.services,
		"HTTPRoute": v.httpRoutes, "TLSRoute": v.tlsRoutes,
	}
	for _, o := range objs {
		require.NoError(t, stores[o.GetKind()].Add(o))
	}
	return v
}

var testPublisher = &publisher{gwNS: "infra", gwName: "public", backend: backend{host: "gw.infra.svc.cluster.local.", port: 80}}

// names is the domains of proxies.
func names(proxies []v1.ProxyConfigurer) []string {
	out := []string{}
	for _, p := range proxies {
		var m msg.NewProxy
		p.MarshalToMsg(&m)
		out = append(out, m.CustomDomains...)
	}
	return out
}

func TestPublished(t *testing.T) {
	v := apiView(t, gatewayObj(t), classObj(t, "cilium", controller),
		testRoute{ns: "blog", name: "blog", hostnames: []string{"Blog.example.com", "*.example.com", "app.example.com"}}.obj(t),
		testRoute{ns: "shop", hostnames: []string{"app.example.com"}}.obj(t),
		testRoute{ns: "blog", name: "nohosts"}.obj(t),
	)

	got, _, _ := testPublisher.publication(v)

	for _, p := range got {
		h := p.(*v1.HTTPProxyConfig)
		require.Equal(t, "http", h.Type)
		require.Equal(t, []string{h.Name}, h.CustomDomains)
		require.Equal(t, "gw.infra.svc.cluster.local.", h.LocalIP)
		require.Equal(t, 80, h.LocalPort)
	}
	require.Equal(t, []string{"app.example.com", "blog.example.com"}, names(got))
}

// A route counts as accepted only by the word of the Gateway's own
// controller, for the route's current generation, at a parentRef the
// route still has.
func TestPublishedTrustsOnlyTheGatewaysController(t *testing.T) {
	other := map[string]any{"name": "internal", "namespace": "infra"}
	cases := func(section map[string]any) []testRoute {
		return []testRoute{
			{hostnames: []string{"accepted.example.com"}},
			{hostnames: []string{"section.example.com"}, parentRefs: []map[string]any{section}},
			{ns: "infra", hostnames: []string{"implicit-ns.example.com"}, parentRefs: []map[string]any{{"name": "public"}}},
			{generation: 5, hostnames: []string{"current.example.com"}},
			{hostnames: []string{"rejected.example.com"}, status: []map[string]any{status(public, controller, 1, "False", "True")}},
			{hostnames: []string{"unreconciled.example.com"}, status: []map[string]any{}},
			{hostnames: []string{"foreign.example.com"}, status: []map[string]any{status(public, "attacker.example/whatever", 1, "True", "True")}},
			{generation: 5, hostnames: []string{"stale.example.com"}, status: []map[string]any{status(public, controller, 1, "True", "True")}},
			{hostnames: []string{"dropped.example.com"}, parentRefs: []map[string]any{other},
				status: []map[string]any{status(public, controller, 1, "True", "True"), status(other, controller, 1, "True", "True")}},
			{hostnames: []string{"other-section.example.com"}, status: []map[string]any{status(section, controller, 1, "True", "True")}},
			{hostnames: []string{"other-gw.example.com"}, parentRefs: []map[string]any{other}},
			{hostnames: []string{"service.example.com"}, parentRefs: []map[string]any{{"name": "public", "namespace": "infra", "group": "", "kind": "Service"}}},
		}
	}
	want := []string{"accepted.example.com", "current.example.com", "implicit-ns.example.com", "section.example.com"}
	for kind, listener := range map[string]string{"HTTPRoute": "http", "TLSRoute": "tls"} {
		t.Run(kind, func(t *testing.T) {
			objs := []*unstructured.Unstructured{gatewayObj(t), classObj(t, "cilium", controller), clusterIPSvc(t, "blog", "app", "10.0.0.1"), clusterIPSvc(t, "infra", "app", "10.0.0.2")}
			for i, r := range cases(map[string]any{"name": "public", "namespace": "infra", "sectionName": listener}) {
				r.kind, r.ns, r.name, r.backend = kind, cmp.Or(r.ns, "blog"), fmt.Sprint("r", i), map[string]any{"name": "app", "port": 80}
				objs = append(objs, r.obj(t))
			}
			httpProxies, tlsProxies, _ := testPublisher.publication(apiView(t, objs...))
			got := names(append(httpProxies, tlsProxies...))
			slices.Sort(got)
			require.Equal(t, want, got)
		})
	}

	accepted := testRoute{hostnames: []string{"accepted.example.com"}}.obj(t)
	for name, objs := range map[string][]*unstructured.Unstructured{
		"no gateway":             {classObj(t, "cilium", controller), accepted},
		"no gateway class":       {gatewayObj(t), accepted},
		"another class's status": {gatewayObj(t), classObj(t, "cilium", "example.com/other-controller"), accepted},
	} {
		httpProxies, _, _ := testPublisher.publication(apiView(t, objs...))
		require.Empty(t, httpProxies, name)
	}
}

// The http proxies dial the Gateway's Service at its cluster IP, never a
// name the pod's DNS search list could resolve to another namespace's
// pod. Without the cluster IP, each name is refused, and stays an HTTP
// name.
func TestPublishedDialsTheGatewaysClusterIP(t *testing.T) {
	pub := &publisher{gwNS: "infra", gwName: "public", backend: backend{svcNS: "infra", svc: "cilium-gateway-public", port: 80}}
	routes := []*unstructured.Unstructured{
		gatewayObj(t), classObj(t, "cilium", controller), clusterIPSvc(t, "blog", "db", "10.0.0.1"),
		testRoute{ns: "blog", hostnames: []string{"blog.example.com"}}.obj(t),
		testRoute{kind: "TLSRoute", ns: "blog", name: "db", hostnames: []string{"blog.example.com"}, backend: map[string]any{"name": "db", "port": 5432}}.obj(t),
	}

	httpProxies, _, _ := pub.publication(apiView(t, append(routes, clusterIPSvc(t, "infra", "cilium-gateway-public", "fd00::a"))...))
	require.Len(t, httpProxies, 1)
	require.Equal(t, "fd00::a", httpProxies[0].GetBaseConfig().LocalIP)
	require.Equal(t, 80, httpProxies[0].GetBaseConfig().LocalPort)

	for name, gwSvc := range map[string][]*unstructured.Unstructured{
		"missing":      nil,
		"headless":     {svcObj(t, "infra", "cilium-gateway-public", map[string]any{"type": "ClusterIP", "clusterIP": "None"})},
		"externalname": {svcObj(t, "infra", "cilium-gateway-public", map[string]any{"type": "ExternalName", "externalName": "attacker.example.com"})},
	} {
		httpProxies, tlsProxies, refused := pub.publication(apiView(t, append(routes, gwSvc...)...))
		require.Empty(t, httpProxies, name)
		require.Empty(t, tlsProxies, name)
		require.ElementsMatch(t, []refusal{
			{"HTTPRoute", "blog/r", "blog.example.com", refusedService},
			{"TLSRoute", "blog/db", "blog.example.com", refusedHTTPRoute},
		}, refused, name)

		var stats routeStats
		stats.update(0, 0, refused)
		rec := httptest.NewRecorder()
		stats.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		require.Contains(t, rec.Body.String(), `fortresskube_refused_httproutes{reason="backend_service"} 1`)
		require.Contains(t, rec.Body.String(), `fortresskube_httproute_refusals_total{reason="backend_service"} 1`)
	}
}

// A name a proxy of the frpc config has stays that proxy's: a route of
// either kind that names it is refused, so frps never groups a tenant's
// proxy with the operator's.
func TestPublishedLeavesTheConfigsNamesAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frpc.toml")
	require.NoError(t, os.WriteFile(path, []byte(`serverAddr = "edge.example.com"
[[proxies]]
name = "grafana"
type = "http"
localIP = "10.0.0.5"
localPort = 3000
customDomains = ["Grafana.Ops.example.com"]
[[proxies]]
name = "pg"
type = "tcp-tls"
localIP = "10.0.0.6"
localPort = 5432
customDomains = ["db.ops.example.com"]
`), 0o644))
	res, err := config.LoadClientConfigResult(path, true)
	require.NoError(t, err)
	pub := *testPublisher
	pub.static = staticNames(res.Proxies)

	v := apiView(t, gatewayObj(t), classObj(t, "cilium", controller), clusterIPSvc(t, "tenant", "db", "10.0.0.7"),
		testRoute{ns: "tenant", hostnames: []string{"app.tenant.example.com", "grafana.ops.example.com", "db.ops.example.com"}}.obj(t),
		testRoute{kind: "TLSRoute", ns: "tenant", name: "db", hostnames: []string{"db.tenant.example.com", "db.ops.example.com", "grafana.ops.example.com"},
			backend: map[string]any{"name": "db", "port": 5432}}.obj(t),
	)
	httpProxies, tlsProxies, refused := pub.publication(v)

	require.Equal(t, []string{"app.tenant.example.com"}, names(httpProxies))
	require.Equal(t, []string{"db.tenant.example.com"}, names(tlsProxies))
	require.ElementsMatch(t, []refusal{
		{"HTTPRoute", "tenant/r", "grafana.ops.example.com", refusedStatic},
		{"HTTPRoute", "tenant/r", "db.ops.example.com", refusedStatic},
		{"TLSRoute", "tenant/db", "db.ops.example.com", refusedStatic},
		{"TLSRoute", "tenant/db", "grafana.ops.example.com", refusedStatic},
	}, refused)
}

// -backend is a Service, dialed at its cluster IP, or an address that
// no DNS search list changes.
func TestParseBackend(t *testing.T) {
	for in, want := range map[string]backend{
		"envoy-public.envoy-gateway-system.svc:8080": {svcNS: "envoy-gateway-system", svc: "envoy-public", port: 8080},
		"10.0.0.1:80":                    {host: "10.0.0.1", port: 80},
		"[fd00::1]:80":                   {host: "fd00::1", port: 80},
		"gw.infra.svc.cluster.local.:80": {host: "gw.infra.svc.cluster.local.", port: 80},
	} {
		got, err := parseBackend(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, in := range []string{
		"gw.infra.svc.cluster.local:80", "gateway:80", "localhost:80", "gw.infra.svc:0", "gw.infra.svc",
		"Bad_Name.infra.svc:80", "gw.infra.svc:http",
	} {
		_, err := parseBackend(in)
		require.Error(t, err, in)
	}
}

// The file's own settings stand; the keys it leaves out get
// fortresskube's defaults, not frpc's.
func TestTunnelDefaults(t *testing.T) {
	dir := t.TempDir()
	load := func(toml string) *v1.ClientCommonConfig {
		t.Helper()
		path := filepath.Join(dir, "frpc.toml")
		if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := config.LoadClientConfigResult(path, true)
		if err != nil {
			t.Fatal(err)
		}
		var file v1.ClientConfig
		if err := config.LoadConfigureFromFile(path, &file, false); err != nil {
			t.Fatal(err)
		}
		tunnelDefaults(res.Common, &file.ClientCommonConfig)
		return res.Common
	}
	c := load("serverAddr = \"edge.example.com\"\n")
	if c.Transport.DeadServerTimeout != deadServerTimeout || c.Transport.DialServerTimeout != dialServerTimeout ||
		c.LoginFailExit == nil || *c.LoginFailExit {
		t.Fatalf("defaults: %+v loginFailExit=%v", c.Transport, c.LoginFailExit)
	}
	if h, _ := os.Hostname(); c.User != h || h == "" {
		t.Fatalf("user %q, want the host name %q", c.User, h)
	}
	c = load("serverAddr = \"edge.example.com\"\nloginFailExit = true\nuser = \"edge-a\"\n" +
		"transport.deadServerTimeout = 10\ntransport.dialServerTimeout = 5\n")
	if c.Transport.DeadServerTimeout != 10 || c.Transport.DialServerTimeout != 5 || !*c.LoginFailExit || c.User != "edge-a" {
		t.Fatalf("the file's own: %+v loginFailExit=%v user=%q", c.Transport, *c.LoginFailExit, c.User)
	}
}
