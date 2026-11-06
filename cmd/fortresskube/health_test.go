package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
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
	b := newBackendHealth("cilium-gateway-public.infra.svc", port)
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

	fresh := newBackendHealth("cilium-gateway-public.infra.svc", port)
	fresh.lookup = b.lookup
	require.Error(t, fresh.check(context.Background()), "never resolved, DNS away")

	n := lookups
	literal := newBackendHealth("127.0.0.1", port)
	literal.lookup = b.lookup
	require.Error(t, literal.check(context.Background()))
	require.Equal(t, n, lookups, "an address is not looked up")
}
