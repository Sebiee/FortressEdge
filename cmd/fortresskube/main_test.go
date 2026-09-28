package main

import (
	"encoding/json"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func route(t *testing.T, ns string, hostnames []string, parents ...map[string]any) any {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"namespace": ns, "name": "r"},
		"spec":       map[string]any{"hostnames": hostnames},
		"status":     map[string]any{"parents": parents},
	})
	require.NoError(t, err)
	u := &unstructured.Unstructured{}
	require.NoError(t, u.UnmarshalJSON(b))
	return u
}

func parent(ref map[string]any, accepted string) map[string]any {
	return map[string]any{
		"parentRef":  ref,
		"conditions": []map[string]any{{"type": "Accepted", "status": accepted}},
	}
}

func TestPublished(t *testing.T) {
	public := map[string]any{"name": "public", "namespace": "infra"}
	objs := []any{
		route(t, "blog", []string{"Blog.example.com", "*.example.com", "app.example.com"}, parent(public, "True")),
		route(t, "shop", []string{"app.example.com"}, parent(public, "True")),
		route(t, "evil", []string{"rejected.example.com"}, parent(public, "False")),
		route(t, "infra", []string{"implicit-ns.example.com"}, parent(map[string]any{"name": "public"}, "True")),
		route(t, "blog", []string{"other-gw.example.com"}, parent(map[string]any{"name": "internal", "namespace": "infra"}, "True")),
		route(t, "blog", []string{"service.example.com"}, parent(map[string]any{"name": "public", "namespace": "infra", "group": "", "kind": "Service"}, "True")),
		route(t, "blog", nil, parent(public, "True")),
		route(t, "blog", []string{"unreconciled.example.com"}),
	}

	got := published(objs, "infra", "public", "gw.infra.svc", 80)

	var names []string
	for _, p := range got {
		h := p.(*v1.HTTPProxyConfig)
		require.Equal(t, "http", h.Type)
		require.Equal(t, []string{h.Name}, h.CustomDomains)
		require.Equal(t, "gw.infra.svc", h.LocalIP)
		require.Equal(t, 80, h.LocalPort)
		names = append(names, h.Name)
	}
	require.Equal(t, []string{"app.example.com", "blog.example.com", "implicit-ns.example.com"}, names)
}
