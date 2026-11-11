package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"
)

// The probe follows the backend's listener, keeps the last address while
// the name does not resolve, and fails without one.
func TestBackendHealth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	var lookupErr error
	lookups := 0
	b := newBackendHealth(backend{host: "backend.example.", port: port}, nil, nil)
	b.lookup = func(context.Context, string) ([]string, error) {
		lookups++
		if lookupErr != nil {
			return nil, lookupErr
		}
		return []string{"127.0.0.1"}, nil
	}
	probe := func() int {
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Code
	}

	require.Equal(t, http.StatusOK, probe(), "backend listening")

	lookupErr = errors.New("no DNS")
	require.Equal(t, http.StatusOK, probe(), "DNS away: the last address")

	require.NoError(t, ln.Close())
	require.Equal(t, http.StatusServiceUnavailable, probe(), "backend gone")
	require.NotEmpty(t, b.down)

	fresh := newBackendHealth(backend{host: "backend.example.", port: port}, nil, nil)
	fresh.lookup = b.lookup
	require.Error(t, fresh.check(context.Background()), "never resolved, DNS away")

	n := lookups
	literal := newBackendHealth(backend{host: "127.0.0.1", port: port}, nil, nil)
	literal.lookup = b.lookup
	require.Error(t, literal.check(context.Background()))
	require.Equal(t, n, lookups, "an address is not looked up")
}

// A Service backend is checked at its cluster IP from the Services watch,
// as the proxies dial it, never an address it had before; it passes until
// the Services are listed, and while the Service has no cluster IP.
func TestBackendHealthService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	services := cache.NewStore(cache.MetaNamespaceKeyFunc)
	listed := false
	b := newBackendHealth(backend{svcNS: "infra", svc: "cilium-gateway-public", port: port}, services, func() bool { return listed })
	dials := 0
	dial := b.dial
	b.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials++
		return dial(ctx, network, addr)
	}
	require.NoError(t, b.check(context.Background()), "Services not listed yet")

	listed = true
	require.NoError(t, b.check(context.Background()), "no such Service")
	require.True(t, b.unchecked)

	svc := clusterIPSvc(t, "infra", "cilium-gateway-public", "127.0.0.1")
	require.NoError(t, services.Add(svc))
	require.NoError(t, b.check(context.Background()))
	require.False(t, b.unchecked)
	require.Equal(t, 1, dials)

	require.NoError(t, services.Update(svcObj(t, "infra", "cilium-gateway-public", map[string]any{"type": "ExternalName", "externalName": "127.0.0.1"})))
	require.NoError(t, b.check(context.Background()), "ExternalName")
	require.Equal(t, 1, dials, "the old cluster IP is not dialled")

	require.NoError(t, services.Update(svc))
	require.NoError(t, ln.Close())
	require.Error(t, b.check(context.Background()), "backend gone")
	require.NotEmpty(t, b.down)

	require.NoError(t, services.Delete(svc))
	require.NoError(t, b.check(context.Background()), "Service deleted")
	require.Equal(t, 2, dials, "the old cluster IP is not dialled")
}
