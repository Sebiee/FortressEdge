package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
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

// freePort is a port that is free on every one of addrs now.
func freePort(t *testing.T, addrs ...string) int {
	t.Helper()
	for range 20 {
		first, err := net.Listen("tcp", net.JoinHostPort(addrs[0], "0"))
		require.NoError(t, err)
		port := first.Addr().(*net.TCPAddr).Port
		free := true
		for _, addr := range addrs[1:] {
			l, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
			if err != nil {
				free = false
				break
			}
			l.Close()
		}
		first.Close()
		if free {
			return port
		}
	}
	t.Fatalf("no port free on all of %v", addrs)
	return 0
}

// renewLab is the edges' frps behind one name, a backend whose /slow
// answers "a" at once and "b" once release closes, and replicas' tunnels
// publishing it as site.test.
type renewLab struct {
	ctx        context.Context
	edges      []*labEdge
	tunnelPort int
	host       string // the backend
	port       int
	release    chan struct{}
	// dial is the edge the next login goes to, as a balancer in front of
	// the edges would choose it: an index into edges.
	dial atomic.Int32
}

type labEdge struct {
	addr string
	svr  *server.Service
	site string // where it serves visitors
	// old makes the replicas read the edge's logins as an edge of 0.10.0
	// answers them: without a count.
	old atomic.Bool
}

// newRenewLab is a lab with one edge, 127.0.0.1, or two, with 127.0.0.2.
func newRenewLab(t *testing.T, edges int) *renewLab {
	old := retireTick
	retireTick = 20 * time.Millisecond
	t.Cleanup(func() { retireTick = old })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// The edges' frps: every client is the same dark node, so their
	// proxies share the name. The tunnel port is the same on every edge,
	// as behind a balancer.
	addrs := []string{"127.0.0.1", "127.0.0.2"}[:edges]
	for _, addr := range addrs {
		probe, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
		if err != nil {
			t.Skipf("no loopback address %s for an edge: %v", addr, err)
		}
		probe.Close()
	}
	l := &renewLab{ctx: ctx, tunnelPort: freePort(t, addrs...), release: make(chan struct{})}
	for _, addr := range addrs {
		scfg := &v1.ServerConfig{
			BindAddr: addr, BindPort: l.tunnelPort, ProxyBindAddr: addr, VhostHTTPPort: freePort(t, addr),
			Identity: func(net.Conn) string { return "node" },
		}
		require.NoError(t, scfg.Complete())
		svr, err := server.NewService(scfg)
		require.NoError(t, err)
		go svr.Run(ctx)
		t.Cleanup(func() { _ = svr.Close() })
		l.edges = append(l.edges, &labEdge{addr: addr, svr: svr, site: net.JoinHostPort(addr, strconv.Itoa(scfg.VhostHTTPPort))})
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		_, _ = io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		<-l.release
		_, _ = io.WriteString(w, "b")
	}))
	t.Cleanup(backend.Close)
	// Before the backend closes, which waits for its requests.
	t.Cleanup(func() {
		select {
		case <-l.release:
		default:
			close(l.release)
		}
	})
	host, portStr, err := net.SplitHostPort(backend.Listener.Addr().String())
	require.NoError(t, err)
	l.host = host
	l.port, err = strconv.Atoi(portStr)
	require.NoError(t, err)
	return l
}

// site is a proxy that publishes name and forwards to the lab's backend.
func (l *renewLab) site(name string) []v1.ProxyConfigurer {
	return []v1.ProxyConfigurer{&v1.HTTPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: name, Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: l.host, LocalPort: l.port}},
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{name}},
	}}
}

// tunnels is a replica's tunnels, not started. It dials one name for all
// the edges, and each login goes to the edge of l.dial.
func (l *renewLab) tunnels(t *testing.T, name string) *tunnels {
	off := false
	common := &v1.ClientCommonConfig{ServerAddr: "tunnel.test", ServerPort: l.tunnelPort, User: name, LoginFailExit: &off}
	common.Transport.Protocol = "tcp"
	common.Transport.TLS.Enable = &off
	require.NoError(t, common.Complete())
	ts := newTunnels(common, l.site("site.test"), nil)
	ts.pick.lookup = func(context.Context, string) ([]string, error) { return []string{l.edges[l.dial.Load()].addr}, nil }
	ts.login = func(tn *tunnel) (string, int, bool) {
		runID, peers, ok := tn.login()
		if ok && l.edges[l.edgeOf(tn)].old.Load() {
			peers = 0
		}
		return runID, peers, ok
	}
	return ts
}

// replica starts a replica, and waits until its edge serves the site
// through its tunnel.
func (l *renewLab) replica(t *testing.T, name string) *tunnels {
	ts := l.tunnels(t, name)
	require.NoError(t, ts.start(l.ctx))
	require.Eventually(t, func() bool { return ts.cur.runs("site.test") }, 10*time.Second, 20*time.Millisecond, "%s publishes the site", name)
	require.Eventually(t, func() bool { return l.carries(l.edgeOf(ts.cur)) }, 10*time.Second, 20*time.Millisecond, "the site answers through the tunnel")
	return ts
}

// edgeOf is the edge tn dialled last.
func (l *renewLab) edgeOf(tn *tunnel) int {
	addr, _ := tn.server.Load().(string)
	return slices.IndexFunc(l.edges, func(e *labEdge) bool { return e.addr == addr })
}

// logins counts the node's logins on each edge: tunnels, tunnels that
// retire, and second logins that look.
func (l *renewLab) logins() []int {
	n := make([]int, len(l.edges))
	for i, e := range l.edges {
		n[i] = e.svr.Clients()["node"]
	}
	return n
}

// settles waits until the edges have want logins: the looks closed, and
// the retired tunnels with them.
func (l *renewLab) settles(t *testing.T, want ...int) {
	t.Helper()
	require.Eventually(t, func() bool { return slices.Equal(l.logins(), want) }, 10*time.Second, 20*time.Millisecond,
		"logins on the edges: %v, want %v", l.logins(), want)
}

func (l *renewLab) visit(edge int, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(l.ctx, http.MethodGet, "http://"+l.edges[edge].site+path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = "site.test"
	return (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
}

// carries reports whether the edge answers a request for the site: frps
// answers 404 for a name no tunnel publishes there.
func (l *renewLab) carries(edge int) bool {
	resp, err := l.visit(edge, "/")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode == http.StatusOK && string(body) == "ok"
}

// slow starts a request at edge that lasts until release.
func (l *renewLab) slow(t *testing.T, edge int) *http.Response {
	t.Helper()
	resp, err := l.visit(edge, "/slow")
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	first := make([]byte, 1)
	_, err = io.ReadFull(resp.Body, first)
	require.NoError(t, err)
	require.Equal(t, "a", string(first))
	return resp
}

// slowOn starts a request that lasts until release on tn, a tunnel at
// edge. The edge takes the tunnels of a name in turn, and may send a
// request or two to a tunnel just retired while it takes the names back;
// those last until release too.
func (l *renewLab) slowOn(t *testing.T, edge int, tn *tunnel) *http.Response {
	t.Helper()
	for {
		before := tn.streams.Load()
		resp := l.slow(t, edge)
		if tn.streams.Load() > before {
			return resp
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func retiring(ts *tunnels) []*tunnel {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return slices.Clone(ts.retiring)
}

func metricsOf(ts *tunnels) string {
	var b bytes.Buffer
	ts.writeMetrics(&b)
	return b.String()
}

// Four replicas whose tunnels are all at one of two edges: the looks move
// one tunnel, then another, and from then on none, whichever edge the
// balancer offers. The first edge serves the site all the while.
func TestLooksMoveTunnelsUntilTheSpreadIsEven(t *testing.T) {
	l := newRenewLab(t, 2)
	var rs []*tunnels
	for i := range 4 {
		rs = append(rs, l.replica(t, fmt.Sprintf("replica-%d", i)))
	}
	l.settles(t, 4, 0)
	require.False(t, l.carries(1), "the second edge has no tunnel yet")

	// A visitor of the first edge, all the while.
	var visits, dark atomic.Int64
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			visits.Add(1)
			if !l.carries(0) {
				dark.Add(1)
			}
		}
	}()

	l.dial.Store(1)
	first := rs[0].cur
	require.Equal(t, lookMoved, rs[0].look(l.ctx), "4 and 0: the first edge lets one go")
	require.NotSame(t, first, rs[0].cur)
	require.Equal(t, "replica-0-1", rs[0].cur.user, "the new tunnel logs in under its own user")
	require.Equal(t, 1, l.edgeOf(rs[0].cur))
	l.settles(t, 3, 1)
	require.True(t, l.carries(1))
	require.Equal(t, lookMoved, rs[1].look(l.ctx), "3 and 1: and one more")
	l.settles(t, 2, 2)

	// 2 and 2: no tunnel moves any more, to either edge, its own included.
	for round := range 2 {
		for edge := range l.edges {
			l.dial.Store(int32(edge))
			for i, ts := range rs {
				cur := ts.cur
				require.Equal(t, lookStayed, ts.look(l.ctx), "round %d: replica %d is offered edge %d", round, i, edge)
				require.Same(t, cur, ts.cur)
			}
		}
	}
	l.settles(t, 2, 2)
	require.True(t, l.carries(0))
	require.True(t, l.carries(1))

	close(stop)
	<-stopped
	require.Positive(t, visits.Load())
	require.Zero(t, dark.Load(), "of %d requests to the first edge", visits.Load())

	require.Contains(t, metricsOf(rs[0]), `fortresskube_tunnel_looks_total{result="moved"} 1`)
	require.Contains(t, metricsOf(rs[0]), `fortresskube_tunnel_looks_total{result="stayed"} 4`)
	require.Contains(t, metricsOf(rs[0]), `fortresskube_tunnel_info{server="127.0.0.2"} 1`)
	require.Contains(t, metricsOf(rs[3]), `fortresskube_tunnel_looks_total{result="moved"} 0`)
	require.Contains(t, metricsOf(rs[3]), `fortresskube_tunnel_looks_total{result="stayed"} 4`)
	require.Contains(t, metricsOf(rs[3]), `fortresskube_tunnel_looks_total{result="failed"} 0`)
	require.Contains(t, metricsOf(rs[3]), "fortresskube_tunnel_up 1\n")
}

// One replica and two edges: the tunnel never moves, since its edge would
// be left without one. A look that stays changes nothing: the tunnel and
// the request it carries are the same after it, the other edge got no
// proxy, and the second login is gone.
func TestLookNeverMovesTheOnlyTunnel(t *testing.T) {
	l := newRenewLab(t, 2)
	ts := l.replica(t, "replica")
	cur := ts.cur
	slow := l.slowOn(t, 0, cur)

	for range 2 {
		l.dial.Store(1)
		require.Equal(t, lookStayed, ts.look(l.ctx), "the other edge is offered")
		require.False(t, l.carries(1), "the look published at the other edge")
		l.dial.Store(0)
		require.Equal(t, lookStayed, ts.look(l.ctx), "its own edge is offered")
	}
	require.Same(t, cur, ts.cur)
	require.True(t, cur.runs("site.test"))
	require.Empty(t, retiring(ts))
	require.True(t, l.carries(0))
	l.settles(t, 1, 0)
	require.Equal(t, int64(1+4), ts.dialsOK.Load(), "the tunnel dialled once, and each look once")

	close(l.release)
	rest, err := io.ReadAll(slow.Body)
	require.NoError(t, err)
	require.Equal(t, "b", string(rest), "the request on the tunnel ends whole")
	require.Contains(t, metricsOf(ts), `fortresskube_tunnel_looks_total{result="stayed"} 4`)
	require.Contains(t, metricsOf(ts), `fortresskube_tunnel_looks_total{result="moved"} 0`)
	require.Contains(t, metricsOf(ts), "fortresskube_tunnels_retiring 0\n")
}

// Two replicas at one edge look at the same moment, and the other edge
// would take either: at most one moves, and the first edge keeps a tunnel.
// (None moves when each look was counted before the other was answered:
// the other edge then offered both the second place.) The next look that
// comes alone moves one.
func TestLooksAtTheSameMomentLeaveTheEdgeATunnel(t *testing.T) {
	l := newRenewLab(t, 2)
	rs := []*tunnels{l.replica(t, "replica-0"), l.replica(t, "replica-1")}
	l.dial.Store(1)
	results := make([]lookResult, len(rs))
	var wg sync.WaitGroup
	for i, ts := range rs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = ts.look(l.ctx)
		}()
	}
	wg.Wait()
	slices.Sort(results)
	require.Equal(t, lookStayed, results[1], "both tunnels left the edge")
	if results[0] != lookMoved {
		require.Equal(t, lookStayed, results[0])
		l.settles(t, 2, 0)
		require.Equal(t, lookMoved, rs[0].look(l.ctx))
	}
	l.settles(t, 1, 1)
	require.True(t, l.carries(0))
	require.True(t, l.carries(1))
}

// A move opens a new tunnel under another user, sends new requests through
// it, and closes the old one only when the request it carries has ended.
func TestMoveRetiresTheOldTunnelWhenIdle(t *testing.T) {
	l := newRenewLab(t, 2)
	ts := l.replica(t, "replica-0")
	l.replica(t, "replica-1")

	// A request that lasts, on the first tunnel.
	before := ts.cur
	slow := l.slowOn(t, 0, before)

	l.dial.Store(1)
	require.Equal(t, lookMoved, ts.look(l.ctx))
	require.NotSame(t, before, ts.cur)
	require.True(t, l.carries(1), "new requests go through the new tunnel")

	// The old tunnel stays while its request lasts.
	time.Sleep(10 * retireTick)
	require.True(t, before.up(), "the old tunnel stays open while it carries a request")
	require.Equal(t, []*tunnel{before}, retiring(ts))
	require.False(t, before.runs("site.test"), "the old tunnel took its names back")
	require.Contains(t, metricsOf(ts), "fortresskube_tunnels_retiring 1\n")

	close(l.release)
	rest, err := io.ReadAll(slow.Body)
	require.NoError(t, err)
	require.Equal(t, "b", string(rest), "the request on the old tunnel ends whole")
	require.Eventually(t, func() bool { return len(retiring(ts)) == 0 && !before.up() },
		5*time.Second, 20*time.Millisecond, "then the old tunnel closes")
	l.settles(t, 1, 1)
	require.True(t, l.carries(0))
	require.True(t, l.carries(1))
}

// The edge lets a tunnel go, but the other edge refuses the new login the
// site: the replica tells its edge that the tunnel stays, the edge counts
// it again, and the tunnel is as it was.
func TestMoveThatCannotPublishTakesItsLeaveBack(t *testing.T) {
	oldReady := renewReady
	renewReady = time.Second
	t.Cleanup(func() { renewReady = oldReady })
	l := newRenewLab(t, 2)
	ts := l.replica(t, "replica-0")
	l.replica(t, "replica-1")
	// At the second edge the name is another node's.
	require.NoError(t, l.edges[1].svr.BindDomain("site.test", "another"))

	cur := ts.cur
	slow := l.slowOn(t, 0, cur)
	l.dial.Store(1)
	require.Equal(t, lookFailed, ts.look(l.ctx))
	require.Same(t, cur, ts.cur)
	require.True(t, cur.runs("site.test"))
	require.Empty(t, retiring(ts))
	l.settles(t, 2, 0)

	// What a login at the first edge is told: both tunnels serve there.
	l.dial.Store(0)
	probe := l.tunnels(t, "probe")
	probe.mu.Lock()
	look, err := probe.open(l.ctx, nil, nil)
	probe.mu.Unlock()
	require.NoError(t, err)
	t.Cleanup(look.close)
	wait, cancel := context.WithTimeout(l.ctx, 10*time.Second)
	defer cancel()
	_, n, ok := probe.loggedIn(wait, look)
	require.True(t, ok)
	require.Equal(t, 2+1, n, "the edge counts the tunnel that stayed")

	close(l.release)
	rest, err := io.ReadAll(slow.Body)
	require.NoError(t, err)
	require.Equal(t, "b", string(rest), "the request on the tunnel ends whole")
	require.Contains(t, metricsOf(ts), `fortresskube_tunnel_looks_total{result="failed"} 1`)
}

// An edge of 0.10.0 or older gives no count and knows no question: when
// the edge the look reaches is one, or the edge of the tunnel, the new
// login becomes the tunnel without a question, as every renewal did. With
// no such edge left, the only tunnel stays where it is.
func TestLookWithAnOldEdgeMovesWithoutAsking(t *testing.T) {
	l := newRenewLab(t, 2)
	ts := l.replica(t, "replica")
	l.edges[1].old.Store(true)

	l.dial.Store(1)
	require.Equal(t, lookOldEdge, ts.look(l.ctx), "the look reaches the old edge")
	require.Equal(t, 1, l.edgeOf(ts.cur))
	l.settles(t, 0, 1)
	require.True(t, l.carries(1))

	l.dial.Store(0)
	require.Equal(t, lookOldEdge, ts.look(l.ctx), "the tunnel is at the old edge")
	require.Equal(t, 0, l.edgeOf(ts.cur))
	l.settles(t, 1, 0)
	require.True(t, l.carries(0))

	l.edges[1].old.Store(false)
	l.dial.Store(1)
	require.Equal(t, lookStayed, ts.look(l.ctx), "both edges count")
	require.Equal(t, 0, l.edgeOf(ts.cur))
	require.Contains(t, metricsOf(ts), `fortresskube_tunnel_looks_total{result="old_edge"} 2`)
	require.Contains(t, metricsOf(ts), `fortresskube_tunnel_looks_total{result="stayed"} 1`)
}

// A tunnel that is not logged in, as after its edge went away, has no edge
// to ask and none to leave without a tunnel: the second login becomes the
// tunnel, as a renewal's did, though it is the node's only one.
func TestLookWithoutALoginTakesTheNewOne(t *testing.T) {
	l := newRenewLab(t, 2)
	ts := l.replica(t, "replica")
	down, login := ts.cur, ts.login
	ts.login = func(tn *tunnel) (string, int, bool) {
		if tn == down {
			return "", 0, false
		}
		return login(tn)
	}
	l.dial.Store(1)
	require.Equal(t, lookMoved, ts.look(l.ctx))
	require.Equal(t, 1, l.edgeOf(ts.cur))
	require.True(t, l.carries(1))
	l.settles(t, 0, 1)
}

// The tunnel's edge goes away before it answers: the look fails, the
// second login is closed, and the tunnel comes back by itself, as after
// any lost connection.
func TestLookWithoutAnAnswerLeavesTheTunnelToItself(t *testing.T) {
	l := newRenewLab(t, 2)
	ts := l.replica(t, "replica-0")
	l.replica(t, "replica-1")
	cur, login := ts.cur, ts.login
	var once sync.Once
	ts.login = func(tn *tunnel) (string, int, bool) {
		runID, peers, ok := login(tn)
		if tn == cur && ok {
			// The look has logged in, and asks next.
			once.Do(func() { _ = l.edges[0].svr.Close() })
		}
		return runID, peers, ok
	}
	l.dial.Store(1)
	require.Equal(t, lookFailed, ts.look(l.ctx))
	require.Same(t, cur, ts.cur)
	require.Empty(t, retiring(ts))
	require.Eventually(t, func() bool { return cur.up() && cur.runs("site.test") && l.carries(1) },
		10*time.Second, 20*time.Millisecond, "the tunnel dials again, and the balancer gives it the edge that is left")
	require.Eventually(t, func() bool { return l.logins()[1] == 2 }, 10*time.Second, 20*time.Millisecond,
		"both replicas' tunnels, and no second login: %v", l.logins())
	require.Contains(t, metricsOf(ts), `fortresskube_tunnel_looks_total{result="failed"} 1`)
}

// With an old edge, a look opens a new tunnel under another user, sends
// new requests through it, and closes the old one only when the request
// it carries has ended, as a renewal did.
func TestOldEdgeLookRetiresTheOldTunnelWhenIdle(t *testing.T) {
	l := newRenewLab(t, 1)
	l.edges[0].old.Store(true)
	ts := l.replica(t, "replica")
	ctx, release := l.ctx, l.release
	served := func() bool { return l.carries(0) }

	// A request that lasts, on the first tunnel.
	slow := l.slow(t, 0)
	before := ts.cur
	// The edge keeps idle work connections for the next request; they
	// count until it drops them with the retired tunnel's proxies.
	require.Eventually(t, func() bool { return before.streams.Load() >= 1 }, 2*time.Second, 10*time.Millisecond)

	require.Equal(t, lookOldEdge, ts.look(ctx))
	require.NotSame(t, before, ts.cur)
	require.Equal(t, "replica-1", ts.cur.user, "the new tunnel logs in under its own user")
	require.True(t, served(), "new requests go through the new tunnel")

	// The old tunnel stays while its request lasts.
	time.Sleep(10 * retireTick)
	require.True(t, before.up(), "the old tunnel stays open while it carries a request")
	require.Len(t, retiring(ts), 1)

	close(release)
	rest, err := io.ReadAll(slow.Body)
	require.NoError(t, err)
	require.Equal(t, "b", string(rest), "the request on the old tunnel ends whole")
	require.Eventually(t, func() bool { return len(retiring(ts)) == 0 && !before.up() },
		5*time.Second, 20*time.Millisecond, "then the old tunnel closes")
	require.True(t, served())

	metrics := metricsOf(ts)
	require.Contains(t, metrics, "fortresskube_tunnel_up 1\n")
	require.Contains(t, metrics, `fortresskube_tunnel_info{server="127.0.0.1"} 1`)
	require.Contains(t, metrics, `fortresskube_tunnel_looks_total{result="old_edge"} 1`)
	require.Contains(t, metrics, "fortresskube_tunnels_retiring 0\n")

	// A new tunnel the edge refuses a name the current one has does not
	// take over, though it runs another.
	refused := append(l.site("site.test"), l.site("other.test")...)
	refused[0].(*v1.HTTPProxyConfig).CustomDomains = []string{"site.test."}
	ts.mu.Lock()
	next, err := ts.open(ctx, refused, nil)
	ts.mu.Unlock()
	require.NoError(t, err)
	t.Cleanup(next.close)
	require.Eventually(t, func() bool { return next.runs("other.test") }, 10*time.Second, 20*time.Millisecond)
	wait, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	require.False(t, next.ready(wait, refused, ts.cur), "site.test would go dark")
}

// With an old edge a look is never skipped: one that would keep more than
// maxRetiring old tunnels closes the oldest, with what it still carries,
// and the others' requests end whole.
func TestOldEdgeLooksCloseTheOldestPastMaxRetiring(t *testing.T) {
	l := newRenewLab(t, 1)
	l.edges[0].old.Store(true)
	ts := l.replica(t, "replica")
	var slows []*http.Response
	var tunnels []*tunnel
	for range maxRetiring + 1 {
		cur := ts.cur
		slows = append(slows, l.slowOn(t, 0, cur))
		tunnels = append(tunnels, cur)
		require.Equal(t, lookOldEdge, ts.look(l.ctx))
	}

	require.Equal(t, tunnels[1:], retiring(ts), "the oldest is gone, the others stay")
	_, err := io.ReadAll(slows[0].Body)
	require.Error(t, err, "the oldest tunnel's request is cut")

	close(l.release)
	for i, resp := range slows[1:] {
		rest, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "request %d", i+1)
		require.Equal(t, "b", string(rest), "request %d ends whole", i+1)
	}
	require.True(t, l.carries(0))

	metrics := metricsOf(ts)
	require.Contains(t, metrics, fmt.Sprintf(`fortresskube_tunnel_looks_total{result="old_edge"} %d`, maxRetiring+1))
	require.Contains(t, metrics, "fortresskube_tunnels_cut_total 1\n")
	require.NotContains(t, metrics, "fortresskube_tunnel_streams_cut_total 0\n")
}

// fakeConnector stands in for frp's connector to the edge.
type fakeConnector struct{ fail error }

func (f fakeConnector) Open() error              { return f.fail }
func (fakeConnector) Connect() (net.Conn, error) { return nil, errors.New("no connection") }
func (fakeConnector) Close() error               { return nil }

// frp makes a connector for each login. At a reconnect the old one's Close
// may come after the new one's Open: the tunnel is up until the connector
// it is up on closes.
func TestTunnelUpFollowsItsCurrentConnector(t *testing.T) {
	tn := &tunnel{set: &tunnels{pick: newPicker("192.0.2.1", "replica-0")}}
	conn := func(fail error) *countingConnector { return &countingConnector{Connector: fakeConnector{fail}, t: tn} }
	a, b := conn(nil), conn(nil)
	require.NoError(t, a.Open())
	require.True(t, tn.up())
	require.NoError(t, b.Open())
	require.NoError(t, a.Close())
	require.True(t, tn.up(), "the old connector's late Close left the tunnel down")
	require.Error(t, conn(errors.New("refused")).Open())
	require.True(t, tn.up(), "a failed dial took down the connection that is up")
	require.NoError(t, b.Close())
	require.False(t, tn.up())
	require.Equal(t, int64(2), tn.set.dialsOK.Load())
	require.Equal(t, int64(1), tn.set.dialsFailed.Load())
}
