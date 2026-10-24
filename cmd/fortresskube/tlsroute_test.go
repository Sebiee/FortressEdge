package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func svc(name string, port int) map[string]any { return map[string]any{"name": name, "port": port} }

func TestPublishedTLS(t *testing.T) {
	old, young := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	pg := map[string]string{alpnAnnotation: "postgresql"}
	tls := func(ns, name string, age time.Time, annotations map[string]string, hostnames []string, backend map[string]any) *unstructured.Unstructured {
		return testRoute{kind: "TLSRoute", ns: ns, name: name, age: age, annotations: annotations, hostnames: hostnames, backend: backend}.obj(t)
	}
	v := apiView(t, gatewayObj(t), classObj(t, "cilium", controller),
		clusterIPSvc(t, "prod", "postgresql-rw", "10.0.0.1"), clusterIPSvc(t, "dev", "postgresql-rw", "10.0.0.2"),
		clusterIPSvc(t, "dev", "valkey", "fd00::3"), clusterIPSvc(t, "dev", "x", "10.0.0.4"),
		testRoute{ns: "web", hostnames: []string{"app.example.com"}}.obj(t),
		tls("dev", "db", young, pg, []string{"DB.dev.example.com", "*.dev.example.com", "app.example.com"}, svc("postgresql-rw", 5432)),
		tls("prod", "db", old, map[string]string{alpnAnnotation: " postgresql , x "}, []string{"db.prod.example.com", "db.dev.example.com"}, svc("postgresql-rw", 5432)),
		tls("dev", "cache", old, nil, []string{"cache.dev.example.com"}, svc("valkey", 6379)),
		tls("dev", "nobackend", old, nil, []string{"nb.example.com"}, nil),
		tls("dev", "noport", old, nil, []string{"np.example.com"}, map[string]any{"name": "x"}),
		tls("dev", "foreign", old, nil, []string{"f.example.com"}, map[string]any{"name": "x", "port": 1, "namespace": "prod"}),
		tls("dev", "notsvc", old, nil, []string{"ns.example.com"}, map[string]any{"name": "x", "port": 1, "kind": "ServiceImport", "group": "multicluster.x-k8s.io"}),
		tls("dev", "acme", old, map[string]string{alpnAnnotation: "acme-tls/1"}, []string{"acme.example.com"}, svc("x", 1)),
		tls("dev", "nohosts", old, nil, nil, svc("x", 1)),
	)
	_, got, refused := testPublisher.publication(v)

	type pub struct {
		name, domain, target string
		alpn                 []string
	}
	var pubs []pub
	for _, p := range got {
		c := p.(*v1.TCPTLSProxyConfig)
		require.Equal(t, "tcp-tls", c.Type)
		require.Len(t, c.CustomDomains, 1)
		pubs = append(pubs, pub{c.Name, c.CustomDomains[0], fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort), c.ALPN})
	}
	require.Equal(t, []pub{
		{"tls:cache.dev.example.com", "cache.dev.example.com", "fd00::3:6379", nil},
		// The older route keeps the name both have.
		{"tls:db.dev.example.com", "db.dev.example.com", "10.0.0.1:5432", []string{"postgresql", "x"}},
		{"tls:db.prod.example.com", "db.prod.example.com", "10.0.0.1:5432", []string{"postgresql", "x"}},
	}, pubs)

	var reasons []string
	for _, r := range refused {
		reasons = append(reasons, r.String())
	}
	require.ElementsMatch(t, []string{
		"dev/db db.dev.example.com: hostname_of_tlsroute",
		"dev/db *.dev.example.com: invalid_hostname",
		"dev/db app.example.com: hostname_of_httproute",
		"dev/nobackend: invalid_backend",
		"dev/noport: invalid_backend",
		"dev/notsvc: invalid_backend",
		"dev/foreign: backend_namespace",
		"dev/acme: invalid_alpn",
		"dev/nohosts: no_hostnames",
	}, reasons)

	// Each refusal is new once, and counted then.
	var stats routeStats
	require.Len(t, stats.update(0, len(got), refused), len(refused))
	require.Empty(t, stats.update(0, len(got), refused))
	rec := httptest.NewRecorder()
	stats.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		`fortresskube_published_names{kind="tls"} 3`,
		`fortresskube_refused_tlsroutes{reason="invalid_backend"} 3`,
		`fortresskube_tlsroute_refusals_total{reason="hostname_of_httproute"} 1`,
	} {
		require.Contains(t, rec.Body.String(), want)
	}
}

// A route publishes only the names that a listener which accepted it
// takes: one whose protocol carries the route's kind, whose
// allowedRoutes have the route's namespace, and whose hostname covers
// the name. A TLSRoute's Service is dialed at its cluster IP, and only
// when the Gateway resolved it.
func TestPublishedOnlyNamesAListenerTakes(t *testing.T) {
	team := func(name string) map[string]any {
		return map[string]any{"namespaces": map[string]any{"from": "Selector", "selector": map[string]any{
			"matchLabels": map[string]any{"kubernetes.io/metadata.name": name}}}}
	}
	gw := gatewayObj(t,
		map[string]any{"name": "web-b", "protocol": "HTTP", "port": 80, "hostname": "*.team-b.example.com", "allowedRoutes": team("team-b")},
		map[string]any{"name": "grpc", "protocol": "HTTPS", "port": 443, "hostname": "grpc.example.com",
			"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "All"}, "kinds": []map[string]any{{"kind": "GRPCRoute"}}}},
		map[string]any{"name": "tls-a", "protocol": "TLS", "port": 443, "hostname": "*.team-a.example.com", "allowedRoutes": team("team-a")},
		map[string]any{"name": "tls-b", "protocol": "TLS", "port": 443, "hostname": "*.team-b.example.com", "allowedRoutes": team("team-b")},
		map[string]any{"name": "tls-infra", "protocol": "TLS", "port": 8443, "hostname": "db.infra.example.com"},
	)
	ref := func(extra map[string]any) map[string]any {
		r := maps.Clone(public)
		maps.Copy(r, extra)
		return r
	}
	old, young := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	tls := func(ns, name string, hostnames []string, backend string) testRoute {
		return testRoute{kind: "TLSRoute", ns: ns, name: name, age: young, hostnames: hostnames, backend: svc(backend, 5432)}
	}
	evil := tls("team-b", "evil", []string{"db.team-b.example.com", "db.team-a.example.com", "x.y.team-b.example.com"}, "steal")
	evil.age = old
	pinned := tls("team-b", "pinned", []string{"cache.team-a.example.com"}, "steal")
	pinned.parentRefs = []map[string]any{ref(map[string]any{"sectionName": "tls-a"})}
	onHTTP := tls("team-b", "on-http", []string{"web.team-b.example.com"}, "steal")
	onHTTP.parentRefs = []map[string]any{ref(map[string]any{"sectionName": "web-b"})}
	unresolved := tls("team-b", "unresolved", []string{"unresolved.team-b.example.com"}, "steal")
	unresolved.status = []map[string]any{status(public, controller, 1, "True", "False")}
	infra := tls("infra", "db", []string{"db.infra.example.com", "other.infra.example.com"}, "pg")
	infra.parentRefs = []map[string]any{ref(map[string]any{"port": 8443})}
	wrongPort := tls("infra", "wrong-port", []string{"db.infra.example.com"}, "pg")
	wrongPort.parentRefs = []map[string]any{ref(map[string]any{"port": 443})}

	v := apiView(t, gw, classObj(t, "cilium", controller),
		nsObj(t, "team-a", map[string]string{"kubernetes.io/metadata.name": "team-a"}),
		nsObj(t, "team-b", map[string]string{"kubernetes.io/metadata.name": "team-b"}),
		clusterIPSvc(t, "team-a", "pg", "10.0.0.10"), clusterIPSvc(t, "team-b", "steal", "10.0.0.20"),
		clusterIPSvc(t, "infra", "pg", "10.0.0.30"),
		svcObj(t, "team-b", "metadata", map[string]any{"type": "ExternalName", "externalName": "169.254.169.254.nip.io"}),
		svcObj(t, "team-b", "headless", map[string]any{"type": "ClusterIP", "clusterIP": "None"}),
		testRoute{ns: "team-b", name: "web", hostnames: []string{"app.team-b.example.com", "app.team-a.example.com", "grpc.example.com"}}.obj(t),
		evil.obj(t),
		tls("team-a", "db", []string{"db.team-a.example.com"}, "pg").obj(t),
		pinned.obj(t), onHTTP.obj(t), unresolved.obj(t), infra.obj(t), wrongPort.obj(t),
		tls("team-b", "external", []string{"metadata.team-b.example.com"}, "metadata").obj(t),
		tls("team-b", "headless", []string{"headless.team-b.example.com"}, "headless").obj(t),
		tls("team-b", "missing", []string{"missing.team-b.example.com"}, "missing").obj(t),
		tls("team-b", "badname", []string{"badname.team-b.example.com"}, "Steal_DB").obj(t),
	)
	httpProxies, tlsProxies, refused := testPublisher.publication(v)

	require.Equal(t, []string{"app.team-b.example.com"}, names(httpProxies))
	targets := map[string]string{}
	for _, p := range tlsProxies {
		c := p.GetBaseConfig()
		targets[names([]v1.ProxyConfigurer{p})[0]] = fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort)
	}
	require.Equal(t, map[string]string{
		"db.team-a.example.com":  "10.0.0.10:5432",
		"db.team-b.example.com":  "10.0.0.20:5432",
		"x.y.team-b.example.com": "10.0.0.20:5432",
		"db.infra.example.com":   "10.0.0.30:5432",
	}, targets)
	var reasons []string
	for _, r := range refused {
		reasons = append(reasons, r.String())
	}
	require.ElementsMatch(t, []string{
		"team-b/external: backend_service",
		"team-b/headless: backend_service",
		"team-b/missing: backend_service",
		"team-b/badname: invalid_backend",
	}, reasons)
}

// The oldest route the Gateway accepted holds a name even while it
// cannot publish it: the name does not pass to a younger route because
// the older one's Service is gone for a while, or its annotation is
// wrong.
func TestOlderTLSRouteHoldsItsNames(t *testing.T) {
	old, young := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	v := apiView(t, gatewayObj(t), classObj(t, "cilium", controller), clusterIPSvc(t, "prod", "db", "10.0.0.1"),
		clusterIPSvc(t, "staging", "db", "10.0.0.3"),
		testRoute{kind: "TLSRoute", ns: "dev", name: "db", age: old, hostnames: []string{"db.example.com"}, backend: svc("gone", 5432)}.obj(t),
		testRoute{kind: "TLSRoute", ns: "staging", name: "db", age: old, annotations: map[string]string{alpnAnnotation: "acme-tls/1"},
			hostnames: []string{"cache.example.com"}, backend: svc("db", 5432)}.obj(t),
		testRoute{kind: "TLSRoute", ns: "prod", name: "db", age: young, hostnames: []string{"db.example.com", "cache.example.com", "free.example.com"}, backend: svc("db", 5432)}.obj(t),
	)
	_, tlsProxies, refused := testPublisher.publication(v)

	require.Equal(t, []string{"free.example.com"}, names(tlsProxies))
	var reasons []string
	for _, r := range refused {
		reasons = append(reasons, r.String())
	}
	require.ElementsMatch(t, []string{
		"dev/db: backend_service",
		"staging/db: invalid_alpn",
		"prod/db db.example.com: hostname_of_tlsroute",
		"prod/db cache.example.com: hostname_of_tlsroute",
	}, reasons)
}

// A TLSRoute on a watched API is published, refused while an HTTPRoute
// has its name, and unpublished when deleted.
func TestPublicationFollowsTheAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheme := runtime.NewScheme()
	resources := map[schema.GroupVersionResource]string{
		httpRoutes: "HTTPRouteList", tlsRoutes: "TLSRouteList", gateways: "GatewayList", gatewayClasses: "GatewayClassList",
		namespaces: "NamespaceList", services: "ServiceList",
	}
	for r, list := range resources {
		scheme.AddKnownTypeWithName(r.GroupVersion().WithKind(list), &unstructured.UnstructuredList{})
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, resources)
	_, err := dyn.Resource(gateways).Namespace("infra").Create(ctx, gatewayObj(t), metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = dyn.Resource(gatewayClasses).Create(ctx, classObj(t, "cilium", controller), metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = dyn.Resource(services).Namespace("dev").Create(ctx, clusterIPSvc(t, "dev", "pg", "10.0.0.1"), metav1.CreateOptions{})
	require.NoError(t, err)
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0)
	v := view{}
	var synced []cache.InformerSynced
	for r, store := range map[schema.GroupVersionResource]*cache.Store{
		httpRoutes: &v.httpRoutes, tlsRoutes: &v.tlsRoutes, gateways: &v.gateways, gatewayClasses: &v.classes,
		namespaces: &v.namespaces, services: &v.services,
	} {
		inf := factory.ForResource(r).Informer()
		*store = inf.GetStore()
		synced = append(synced, inf.HasSynced)
	}
	factory.Start(ctx.Done())
	require.True(t, cache.WaitForCacheSync(ctx.Done(), synced...))

	tlsNames := func() []string {
		_, tls, _ := testPublisher.publication(v)
		var out []string
		for _, p := range tls {
			out = append(out, p.GetBaseConfig().Name)
		}
		return out
	}
	wait := func(want []string) {
		t.Helper()
		require.EventuallyWithT(t, func(c *assert.CollectT) { assert.Equal(c, want, tlsNames()) }, 5*time.Second, 20*time.Millisecond)
	}
	tr := testRoute{kind: "TLSRoute", ns: "dev", name: "db", age: time.Now(), hostnames: []string{"db.example.com"}, backend: svc("pg", 5432)}.obj(t)
	_, err = dyn.Resource(tlsRoutes).Namespace("dev").Create(ctx, tr, metav1.CreateOptions{})
	require.NoError(t, err)
	wait([]string{"tls:db.example.com"})

	hr := testRoute{ns: "dev", hostnames: []string{"db.example.com"}}.obj(t)
	_, err = dyn.Resource(httpRoutes).Namespace("dev").Create(ctx, hr, metav1.CreateOptions{})
	require.NoError(t, err)
	wait(nil)
	require.NoError(t, dyn.Resource(httpRoutes).Namespace("dev").Delete(ctx, "r", metav1.DeleteOptions{}))
	wait([]string{"tls:db.example.com"})

	require.NoError(t, dyn.Resource(tlsRoutes).Namespace("dev").Delete(ctx, "db", metav1.DeleteOptions{}))
	wait(nil)
}

func TestOldEdge(t *testing.T) {
	require.True(t, oldEdge("unknown proxy type: tcp-tls"))
	require.True(t, oldEdge("type [tcp-tls] not supported: it needs a server that ends TLS itself"))
	require.False(t, oldEdge("domain [x] belongs to http proxies, it cannot have tcp-tls ones too"))
}

// Discovery decides: TLSRoutes served, not served (off for good), or an
// error to try again.
func TestTLSRoutesServed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		resources []string
		served    bool
		notFound  bool
	}{
		{"served", 200, []string{"httproutes", "tlsroutes"}, true, false},
		{"group without tlsroutes", 200, []string{"httproutes"}, false, false},
		{"no such group", 404, nil, false, true},
		{"api server error", 500, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/apis/gateway.networking.k8s.io/v1" {
					http.NotFound(w, r)
					return
				}
				if tc.status != 200 {
					w.WriteHeader(tc.status)
					return
				}
				list := metav1.APIResourceList{GroupVersion: "gateway.networking.k8s.io/v1"}
				for _, r := range tc.resources {
					list.APIResources = append(list.APIResources, metav1.APIResource{Name: r, Namespaced: true})
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(list)
			}))
			defer srv.Close()
			served, err := tlsRoutesServed(&rest.Config{Host: srv.URL})
			require.Equal(t, tc.served, served)
			require.Equal(t, tc.notFound, apierrors.IsNotFound(err), "%v", err)
			if tc.status == 500 {
				require.Error(t, err)
			}
		})
	}
}
