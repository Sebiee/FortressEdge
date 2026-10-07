package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// tlsRouteObj is a TLSRoute in ns, created at age, to backend
// (name:port in ns) or none.
func tlsRouteObj(t *testing.T, ns, name string, age time.Time, annotations map[string]string, hostnames []string, backend map[string]any, parents ...map[string]any) *unstructured.Unstructured {
	t.Helper()
	spec := map[string]any{"hostnames": hostnames}
	if backend != nil {
		spec["rules"] = []map[string]any{{"backendRefs": []map[string]any{backend}}}
	}
	meta := map[string]any{"namespace": ns, "name": name, "creationTimestamp": age.UTC().Format(time.RFC3339)}
	if annotations != nil {
		meta["annotations"] = annotations
	}
	b, err := json.Marshal(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "TLSRoute",
		"metadata":   meta,
		"spec":       spec,
		"status":     map[string]any{"parents": parents},
	})
	require.NoError(t, err)
	u := &unstructured.Unstructured{}
	require.NoError(t, u.UnmarshalJSON(b))
	return u
}

func svc(name string, port int) map[string]any { return map[string]any{"name": name, "port": port} }

func TestPublishedTLS(t *testing.T) {
	public := map[string]any{"name": "public", "namespace": "infra"}
	ok := parent(public, "True")
	old, young := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	pg := map[string]string{alpnAnnotation: "postgresql"}
	objs := []any{
		tlsRouteObj(t, "dev", "db", young, pg, []string{"DB.dev.example.com", "*.dev.example.com", "app.example.com"}, svc("postgresql-rw", 5432), ok),
		tlsRouteObj(t, "prod", "db", old, map[string]string{alpnAnnotation: " postgresql , x "}, []string{"db.prod.example.com", "db.dev.example.com"}, svc("postgresql-rw", 5432), ok),
		tlsRouteObj(t, "dev", "cache", old, nil, []string{"cache.dev.example.com"}, svc("valkey", 6379), ok),
		tlsRouteObj(t, "dev", "rejected", old, nil, []string{"rejected.example.com"}, svc("x", 1), parent(public, "False")),
		tlsRouteObj(t, "dev", "nobackend", old, nil, []string{"nb.example.com"}, nil, ok),
		tlsRouteObj(t, "dev", "noport", old, nil, []string{"np.example.com"}, map[string]any{"name": "x"}, ok),
		tlsRouteObj(t, "dev", "foreign", old, nil, []string{"f.example.com"}, map[string]any{"name": "x", "port": 1, "namespace": "prod"}, ok),
		tlsRouteObj(t, "dev", "notsvc", old, nil, []string{"ns.example.com"}, map[string]any{"name": "x", "port": 1, "kind": "ServiceImport", "group": "multicluster.x-k8s.io"}, ok),
		tlsRouteObj(t, "dev", "acme", old, map[string]string{alpnAnnotation: "acme-tls/1"}, []string{"acme.example.com"}, svc("x", 1), ok),
		tlsRouteObj(t, "dev", "nohosts", old, nil, nil, svc("x", 1), ok),
	}
	got, refused := publishedTLS(objs, "infra", "public", map[string]bool{"app.example.com": true})

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
		{"tls:cache.dev.example.com", "cache.dev.example.com", "valkey.dev.svc:6379", nil},
		// The older route keeps the name both have.
		{"tls:db.dev.example.com", "db.dev.example.com", "postgresql-rw.prod.svc:5432", []string{"postgresql", "x"}},
		{"tls:db.prod.example.com", "db.prod.example.com", "postgresql-rw.prod.svc:5432", []string{"postgresql", "x"}},
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

// A TLSRoute on a watched API is published, refused while an HTTPRoute
// has its name, and unpublished when deleted.
func TestPublicationFollowsTheAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheme := runtime.NewScheme()
	gvk := func(kind string) schema.GroupVersionKind {
		return schema.GroupVersionKind{Group: gatewayGroup, Version: "v1", Kind: kind}
	}
	scheme.AddKnownTypeWithName(gvk("HTTPRouteList"), &unstructured.UnstructuredList{})
	scheme.AddKnownTypeWithName(gvk("TLSRouteList"), &unstructured.UnstructuredList{})
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		httpRoutes: "HTTPRouteList", tlsRoutes: "TLSRouteList",
	})
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0)
	httpInf, tlsInf := factory.ForResource(httpRoutes).Informer(), factory.ForResource(tlsRoutes).Informer()
	factory.Start(ctx.Done())
	require.True(t, cache.WaitForCacheSync(ctx.Done(), httpInf.HasSynced, tlsInf.HasSynced))

	ok := parent(map[string]any{"name": "public", "namespace": "infra"}, "True")
	names := func() []string {
		_, tls, _ := publication(httpInf.GetStore(), tlsInf.GetStore(), "infra", "public", "gw.infra.svc", 80)
		var out []string
		for _, p := range tls {
			out = append(out, p.GetBaseConfig().Name)
		}
		return out
	}
	wait := func(want []string) {
		t.Helper()
		require.EventuallyWithT(t, func(c *assert.CollectT) { assert.Equal(c, want, names()) }, 5*time.Second, 20*time.Millisecond)
	}
	tr := tlsRouteObj(t, "dev", "db", time.Now(), nil, []string{"db.example.com"}, svc("pg", 5432), ok)
	_, err := dyn.Resource(tlsRoutes).Namespace("dev").Create(ctx, tr, metav1.CreateOptions{})
	require.NoError(t, err)
	wait([]string{"tls:db.example.com"})

	hr := route(t, "dev", []string{"db.example.com"}, ok).(*unstructured.Unstructured)
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
