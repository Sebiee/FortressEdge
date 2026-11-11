package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
	"github.com/stretchr/testify/require"
)

func TestSpreadIndex(t *testing.T) {
	// A StatefulSet's replicas take the addresses in turn.
	require.Equal(t, uint32(0), spreadIndex("fortresskube-private-0"))
	require.Equal(t, uint32(3), spreadIndex("fortresskube-private-3"))
	// A Deployment's get a place from their name: always the same one.
	require.Equal(t, spreadIndex("fortresskube-7c9f8d6b5-x2x4q"), spreadIndex("fortresskube-7c9f8d6b5-x2x4q"))
	require.NotEqual(t, spreadIndex("fortresskube-7c9f8d6b5-x2x4q"), spreadIndex("fortresskube-7c9f8d6b5-k8zzp"))
}

func TestPick(t *testing.T) {
	ctx := context.Background()
	addrs := []string{"192.0.2.3", "192.0.2.1", "192.0.2.2", "192.0.2.1"}
	p := newPicker("tunnel.example.com", "replica-1")
	p.lookup = func(context.Context, string) ([]string, error) { return addrs, nil }

	require.Equal(t, "192.0.2.2", p.pick(ctx), "replica 1 takes the second of the sorted addresses")
	require.Equal(t, "192.0.2.2", p.pick(ctx), "and keeps it")
	p.dialled(false)
	require.Equal(t, "192.0.2.3", p.pick(ctx), "a dial that failed moves on to the next address")
	p.dialled(false)
	require.Equal(t, "192.0.2.1", p.pick(ctx), "and around")
	p.dialled(true)
	require.Equal(t, "192.0.2.2", p.pick(ctx), "a dial that worked: the next one starts at its own again")

	p.lookup = func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }
	require.Equal(t, "tunnel.example.com", p.pick(ctx), "a name that does not resolve is left to the dial")
	require.Equal(t, "192.0.2.9", newPicker("192.0.2.9", "replica-1").pick(ctx), "an address is dialled as it is")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// A renewal opens a new tunnel under another user, sends new requests
// through it, and closes the old one only when the request it carries has
// ended.
func TestRenewRetiresTheOldTunnelWhenIdle(t *testing.T) {
	old := retireTick
	retireTick = 20 * time.Millisecond
	t.Cleanup(func() { retireTick = old })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The edge's frps: every client is the same dark node, so their
	// proxies share the name.
	scfg := &v1.ServerConfig{
		BindAddr: "127.0.0.1", BindPort: freePort(t), ProxyBindAddr: "127.0.0.1", VhostHTTPPort: freePort(t),
		Identity: func(net.Conn) string { return "node" },
	}
	require.NoError(t, scfg.Complete())
	svr, err := server.NewService(scfg)
	require.NoError(t, err)
	go svr.Run(ctx)
	t.Cleanup(func() { _ = svr.Close() })

	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The edge keeps a work connection for the next request, for up to
		// a minute. Closing each one here lets the test see a tunnel
		// without requests at once.
		w.Header().Set("Connection", "close")
		if r.URL.Path != "/slow" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		_, _ = io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "b")
	}))
	t.Cleanup(backend.Close)
	host, portStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	off := false
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: scfg.BindPort, User: "replica", LoginFailExit: &off}
	common.Transport.Protocol = "tcp"
	common.Transport.TLS.Enable = &off
	require.NoError(t, common.Complete())
	proxies := []v1.ProxyConfigurer{&v1.HTTPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "site.test", Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: host, LocalPort: port}},
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"site.test"}},
	}}
	ts := newTunnels(common, proxies, nil)
	require.NoError(t, ts.start(ctx))

	visit := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(scfg.VhostHTTPPort)+path, nil)
		if err != nil {
			return nil, err
		}
		req.Host = "site.test"
		return (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	}
	served := func() bool {
		resp, err := visit("/")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == http.StatusOK && string(body) == "ok"
	}
	require.Eventually(t, served, 10*time.Second, 50*time.Millisecond, "the site answers through the tunnel")

	// A request that lasts, on the first tunnel.
	slow, err := visit("/slow")
	require.NoError(t, err)
	t.Cleanup(func() { slow.Body.Close() })
	first := make([]byte, 1)
	_, err = io.ReadFull(slow.Body, first)
	require.NoError(t, err)
	require.Equal(t, "a", string(first))
	before := ts.cur
	require.Eventually(t, func() bool { return before.streams.Load() == 1 }, 2*time.Second, 10*time.Millisecond)

	require.True(t, ts.renew(ctx))
	require.NotSame(t, before, ts.cur)
	require.Equal(t, "replica-1", ts.cur.user, "the new tunnel logs in under its own user")
	require.True(t, served(), "new requests go through the new tunnel")

	// The old tunnel stays while its request lasts.
	time.Sleep(10 * retireTick)
	require.True(t, before.open.Load(), "the old tunnel stays open while it carries a request")
	ts.mu.Lock()
	retiring := len(ts.retiring)
	ts.mu.Unlock()
	require.Equal(t, 1, retiring)

	close(release)
	rest, err := io.ReadAll(slow.Body)
	require.NoError(t, err)
	require.Equal(t, "b", string(rest), "the request on the old tunnel ends whole")
	require.Eventually(t, func() bool {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		return len(ts.retiring) == 0 && !before.open.Load()
	}, 5*time.Second, 20*time.Millisecond, "then the old tunnel closes")
	require.True(t, served())

	var metrics bytes.Buffer
	ts.writeMetrics(&metrics)
	require.Contains(t, metrics.String(), "fortresskube_tunnel_up 1\n")
	require.Contains(t, metrics.String(), `fortresskube_tunnel_info{server="127.0.0.1"} 1`)
	require.Contains(t, metrics.String(), `fortresskube_tunnel_renewals_total{result="ok"} 1`)
	require.Contains(t, metrics.String(), "fortresskube_tunnels_retiring 0\n")
}
