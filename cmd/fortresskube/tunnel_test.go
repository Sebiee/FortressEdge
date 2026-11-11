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
	// The edge keeps idle work connections for the next request; they
	// count until it drops them with the retired tunnel's proxies.
	require.Eventually(t, func() bool { return before.streams.Load() >= 1 }, 2*time.Second, 10*time.Millisecond)

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

	// A new tunnel the edge refuses a name the current one has does not
	// take over, though it runs another.
	oldReady := renewReady
	renewReady = time.Second
	t.Cleanup(func() { renewReady = oldReady })
	refused := []v1.ProxyConfigurer{
		&v1.HTTPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{Name: "site.test", Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: host, LocalPort: port}},
			DomainConfig:    v1.DomainConfig{CustomDomains: []string{"site.test."}},
		},
		&v1.HTTPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{Name: "other.test", Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: host, LocalPort: port}},
			DomainConfig:    v1.DomainConfig{CustomDomains: []string{"other.test"}},
		},
	}
	ts.mu.Lock()
	next, err := ts.open(ctx, refused)
	ts.mu.Unlock()
	require.NoError(t, err)
	t.Cleanup(next.close)
	require.Eventually(t, func() bool { return next.runs("other.test") }, 10*time.Second, 20*time.Millisecond)
	require.False(t, next.ready(ctx, refused, ts.cur), "site.test would go dark")
}

// A replica with maxRetiring tunnels still carrying streams does not
// renew, so its logins on the edge stay bounded, and renews again once one
// of them closed.
func TestRenewWaitsForRetiringTunnels(t *testing.T) {
	old := renewReady
	renewReady = 100 * time.Millisecond
	t.Cleanup(func() { renewReady = old })
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: freePort(t), User: "replica"}
	require.NoError(t, common.Complete())
	ts := newTunnels(common, nil, nil)
	ts.cur = &tunnel{set: ts, born: time.Now()}
	ts.retiring = []*tunnel{{}, {}}
	require.False(t, ts.renew(context.Background()))
	var metrics bytes.Buffer
	ts.writeMetrics(&metrics)
	require.Contains(t, metrics.String(), `fortresskube_tunnel_renewals_total{result="skipped"} 1`)
	require.Equal(t, 0, ts.gen, "no tunnel was opened")

	ts.retiring = ts.retiring[:1]
	ts.renew(context.Background())
	require.Equal(t, 1, ts.gen, "a tunnel was opened")
}
