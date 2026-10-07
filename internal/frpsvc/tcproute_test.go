//go:build linux

package frpsvc

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// TestTCPRouteThroughFrp runs a tcp-tls proxy through frps and an
// in-process frpc: the route appears with its ALPN, a stream reaches the
// local service and closes one way at a time through the work
// connection, a name an http proxy holds is refused and counted, and the
// route goes when frpc drops the proxy.
func TestTCPRouteThroughFrp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var mu sync.Mutex
	events, httpNames := map[string]bool{}, map[string]bool{}
	frps, err := Start(ctx, Options{OnTCPDomain: func(d string, added bool) {
		mu.Lock()
		events[d] = added
		mu.Unlock()
	}, Tunnel: "tunnel.example.com", OnDomain: func(d string, added bool) {
		mu.Lock()
		httpNames[d] = added
		mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer frps.Stop()

	// The local service answers the size of what it read, after the
	// client's EOF, then closes its side.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c)
				io.WriteString(c, "read "+string(b))
				c.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	tcpTLS := func(name, domain string, alpn ...string) v1.ProxyConfigurer {
		c := &v1.TCPTLSProxyConfig{CustomDomains: []string{domain}, ALPN: alpn}
		c.Name, c.Type, c.LocalIP, c.LocalPort = name, "tcp-tls", "127.0.0.1", port
		return c
	}
	httpProxy := &v1.HTTPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "app", Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: port}},
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"app.example.com"}},
	}
	common := &v1.ClientCommonConfig{
		ServerAddr: config.FrpsBindAddr, ServerPort: config.FrpsTCPPort, LoginFailExit: new(false),
		Transport: v1.ClientTransportConfig{Protocol: "tcp", WireProtocol: "v2"},
	}
	common.Transport.TLS.Enable = new(false)
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	src := source.NewConfigSource()
	// frpc registers its proxies at once: the HTTP name comes first, so
	// the tcp-tls claim on it is the second.
	proxies := []v1.ProxyConfigurer{httpProxy, tcpTLS("db", "db.example.com", "postgresql"), tcpTLS("tunnel", "tunnel.example.com")}
	if err := src.ReplaceAll(proxies, nil); err != nil {
		t.Fatal(err)
	}
	svc, err := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(src)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = svc.Run(ctx) }()
	defer func() { svc.Close(); <-done }()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, ok := frps.TCPRoute("db.example.com"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no tcp-tls route")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for {
		mu.Lock()
		up := httpNames["app.example.com"]
		mu.Unlock()
		if up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no http route")
		}
		time.Sleep(50 * time.Millisecond)
	}
	proxies = append(proxies, tcpTLS("clash", "app.example.com"))
	if err := svc.UpdateConfigSource(common, proxies, nil); err != nil {
		t.Fatal(err)
	}
	route, _ := frps.TCPRoute("DB.example.com")
	if len(route.ALPN) != 1 || route.ALPN[0] != "postgresql" {
		t.Fatalf("alpn %q", route.ALPN)
	}
	mu.Lock()
	if !events["db.example.com"] {
		t.Fatalf("OnTCPDomain: %v", events)
	}
	mu.Unlock()

	// Half-close through the work connection, both ways.
	c, err := route.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "SELECT 1")
	if err := netpkg.CloseWrite(c); err != nil {
		t.Fatalf("close write through the tunnel: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "read SELECT 1" {
		t.Fatalf("answer: %q %v", got, err)
	}
	c.Close()

	// The tcp-tls proxy for the http name was refused.
	want := `fortressedge_name_conflicts_total{name="app.example.com",refused="tcp_route"}`
	var buf bytes.Buffer
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(buf.String(), want); {
		if time.Now().After(deadline) {
			t.Fatalf("metrics lack %s:\n%s", want, buf.String())
		}
		time.Sleep(50 * time.Millisecond)
		buf.Reset()
		w := metrics.NewWriter(&buf)
		frps.WriteMetrics(w)
		w.Flush()
	}
	if _, ok := frps.TCPRoute("app.example.com"); ok {
		t.Fatal("app.example.com is a tcp-tls route too")
	}
	if _, ok := frps.TCPRoute("tunnel.example.com"); ok {
		t.Fatal("the tunnel name is a tcp-tls route")
	}

	// Dropping the proxy drops the route.
	if err := svc.UpdateConfigSource(common, []v1.ProxyConfigurer{httpProxy}, nil); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		gone := !events["db.example.com"]
		mu.Unlock()
		if _, ok := frps.TCPRoute("db.example.com"); !ok && gone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the route stayed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
