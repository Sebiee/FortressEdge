package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/log"
)

// A replica holds one tunnel. Three things here keep that one tunnel in the
// right place when the server name stands for several edges:
//
//   - the pick: a name with several addresses (one per location of an edge
//     service) is dialled at one of them, chosen by the replica's own name,
//     so replicas spread over the addresses; an address that does not answer
//     is passed over until the next dial;
//   - the renewal (-renew): at a fixed age the replica opens a new tunnel
//     and retires the old one, so a balancer in front of several edges can
//     give an edge that came back its share;
//   - the retirement: the old tunnel takes no new request, and closes when
//     the requests and TCP sessions it carries have ended. The edge keeps a
//     work connection for the next request for up to a minute, so that is
//     up to a minute after the last request.

var (
	// renewReady is how long a new tunnel gets to log in and publish.
	renewReady = 15 * time.Second
	// retireTick is how often a retiring tunnel is looked at; after three
	// looks without a request in flight it is closed.
	retireTick = time.Second
)

// picker chooses the address a dial goes to.
type picker struct {
	host   string // serverAddr as configured: a name or an address
	start  uint32 // this replica's place among the addresses
	lookup func(context.Context, string) ([]string, error)

	mu     sync.Mutex
	failed int // dials that failed in a row
}

func newPicker(host, replica string) *picker {
	return &picker{host: host, start: spreadIndex(replica), lookup: net.DefaultResolver.LookupHost}
}

// spreadIndex is a replica's place among the server's addresses: the number
// its name ends with (a StatefulSet's ordinal, so replicas 0, 1, 2 take
// addresses 0, 1, 2), else a hash of the name.
func spreadIndex(replica string) uint32 {
	if i := strings.LastIndexByte(replica, '-'); i >= 0 {
		if n, err := strconv.ParseUint(replica[i+1:], 10, 32); err == nil {
			return uint32(n)
		}
	}
	h := fnv.New32a()
	_, _ = io.WriteString(h, replica)
	return h.Sum32()
}

// pick is the address to dial now: the replica's own among the name's
// addresses, the next one after each dial that failed. A name that does
// not resolve, or an address, is returned as it is.
func (p *picker) pick(ctx context.Context) string {
	if net.ParseIP(p.host) != nil {
		return p.host
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := p.lookup(ctx, p.host)
	if err != nil || len(addrs) == 0 {
		return p.host
	}
	addrs = slices.Clone(addrs)
	slices.Sort(addrs)
	addrs = slices.Compact(addrs)
	p.mu.Lock()
	defer p.mu.Unlock()
	return addrs[(uint64(p.start)+uint64(p.failed))%uint64(len(addrs))]
}

func (p *picker) dialled(ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		p.failed = 0
	} else {
		p.failed++
	}
}

// tunnel is one frp client and what it carries.
type tunnel struct {
	set  *tunnels
	svc  *client.Service
	user string
	born time.Time

	open    atomic.Bool  // its connection to the edge is up
	streams atomic.Int64 // work connections that carry a request now
	retired atomic.Bool  // closed by fortresskube, not by a failure
	server  atomic.Value // string: the address it dialled last
	stop    context.CancelFunc
}

// connector makes the tunnel's connection to the edge, at the picked
// address, and counts what it carries.
func (t *tunnel) connector(ctx context.Context, cfg *v1.ClientCommonConfig) client.Connector {
	c := *cfg
	if c.Transport.TLS.ServerName == "" && net.ParseIP(c.ServerAddr) == nil {
		c.Transport.TLS.ServerName = c.ServerAddr
	}
	c.ServerAddr = t.set.pick.pick(ctx)
	t.server.Store(c.ServerAddr)
	return &countingConnector{Connector: client.NewConnector(ctx, &c), t: t}
}

type countingConnector struct {
	client.Connector
	t       *tunnel
	control atomic.Bool // the first connection is the control connection
}

func (c *countingConnector) Open() error {
	err := c.Connector.Open()
	c.t.set.pick.dialled(err == nil)
	c.t.set.dialled(err == nil)
	c.t.open.Store(err == nil)
	return err
}

func (c *countingConnector) Connect() (net.Conn, error) {
	conn, err := c.Connector.Connect()
	if err != nil || c.control.CompareAndSwap(false, true) {
		return conn, err
	}
	return &workConn{Conn: conn, t: c.t}, nil
}

func (c *countingConnector) Close() error {
	c.t.open.Store(false)
	return c.Connector.Close()
}

// workConn is a work connection. It waits at the edge until a request
// needs it; the edge's first bytes on it start that request, and its close
// ends it.
type workConn struct {
	net.Conn
	t *tunnel

	mu         sync.Mutex
	used, done bool
}

func (w *workConn) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if n > 0 {
		w.mu.Lock()
		if !w.used && !w.done {
			w.used = true
			w.t.streams.Add(1)
		}
		w.mu.Unlock()
	}
	return n, err
}

func (w *workConn) Close() error {
	w.mu.Lock()
	if !w.done {
		w.done = true
		if w.used {
			w.t.streams.Add(-1)
		}
	}
	w.mu.Unlock()
	return w.Conn.Close()
}

// tunnels is the replica's tunnel, and for a while the ones it retires.
type tunnels struct {
	common   *v1.ClientCommonConfig
	visitors []v1.VisitorConfigurer
	pick     *picker
	failed   chan error // the current tunnel ended by itself

	mu       sync.Mutex
	cur      *tunnel
	retiring []*tunnel
	proxies  []v1.ProxyConfigurer
	gen      int

	dialsOK, dialsFailed       atomic.Int64
	renewalsOK, renewalsFailed atomic.Int64
}

func newTunnels(common *v1.ClientCommonConfig, proxies []v1.ProxyConfigurer, visitors []v1.VisitorConfigurer) *tunnels {
	return &tunnels{
		common: common, visitors: visitors, proxies: proxies,
		pick:   newPicker(common.ServerAddr, common.User),
		failed: make(chan error, 1),
	}
}

func (ts *tunnels) dialled(ok bool) {
	if ok {
		ts.dialsOK.Add(1)
	} else {
		ts.dialsFailed.Add(1)
	}
}

// start opens the first tunnel.
func (ts *tunnels) start(ctx context.Context) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t, err := ts.open(ctx, ts.proxies)
	if err != nil {
		return err
	}
	ts.cur = t
	return nil
}

// open starts a tunnel that publishes proxies. Each tunnel logs in under
// its own user, so the edge tells the proxies of an old and a new one apart.
func (ts *tunnels) open(ctx context.Context, proxies []v1.ProxyConfigurer) (*tunnel, error) {
	c := *ts.common
	if ts.gen > 0 {
		c.User = fmt.Sprintf("%s-%d", ts.common.User, ts.gen)
	}
	ts.gen++
	src := source.NewConfigSource()
	if err := src.ReplaceAll(proxies, ts.visitors); err != nil {
		return nil, err
	}
	t := &tunnel{set: ts, user: c.User, born: time.Now()}
	// No ConfigFilePath: an admin-API reload would replace the published
	// routes with the file's proxies, so it is refused instead.
	svc, err := client.NewService(client.ServiceOptions{
		Common: &c, ConfigSourceAggregator: source.NewAggregator(src), ConnectorCreator: t.connector,
	})
	if err != nil {
		return nil, err
	}
	t.svc = svc
	ctx, t.stop = context.WithCancel(ctx)
	go func() {
		err := svc.Run(ctx)
		if !t.retired.Load() {
			select {
			case ts.failed <- err:
			default:
			}
		}
	}()
	return t, nil
}

// publish replaces what the tunnel publishes.
func (ts *tunnels) publish(proxies []v1.ProxyConfigurer) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.proxies = proxies
	c := *ts.common
	c.User = ts.cur.user
	return ts.cur.svc.UpdateConfigSource(&c, proxies, ts.visitors)
}

// GetProxyStatus is the status of a proxy of the current tunnel.
func (ts *tunnels) GetProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	ts.mu.Lock()
	t := ts.cur
	ts.mu.Unlock()
	return t.svc.StatusExporter().GetProxyStatus(name)
}

// renewEvery renews the tunnel at about every age (within a fifth of it,
// so replicas started together do not renew together).
func (ts *tunnels) renewEvery(ctx context.Context, age time.Duration) {
	for {
		wait := age - age/5 + rand.N(2*age/5+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			ts.renew(ctx)
		}
	}
}

// renew opens a new tunnel and, once it publishes, retires the current
// one. A new tunnel that does not come up in time is dropped, and the
// current one stays.
func (ts *tunnels) renew(ctx context.Context) bool {
	ts.mu.Lock()
	proxies := ts.proxies
	t, err := ts.open(ctx, proxies)
	ts.mu.Unlock()
	if err == nil && !t.ready(ctx, proxies) {
		t.close()
		err = fmt.Errorf("it did not log in and publish within %s", renewReady)
	}
	if err != nil {
		ts.renewalsFailed.Add(1)
		log.Warnf("tunnel renewal: %v; the tunnel stays as it is", err)
		return false
	}
	ts.mu.Lock()
	old := ts.cur
	ts.cur = t
	ts.retiring = append(ts.retiring, old)
	// What was published while the new tunnel came up.
	c := *ts.common
	c.User = t.user
	if err := t.svc.UpdateConfigSource(&c, ts.proxies, ts.visitors); err != nil {
		log.Warnf("publish routes: %v", err)
	}
	ts.mu.Unlock()
	ts.renewalsOK.Add(1)
	server, _ := t.server.Load().(string)
	log.Infof("tunnel renewed (to %s); the old one closes when its requests have ended", server)
	go ts.retire(ctx, old)
	return true
}

// ready reports whether the tunnel has logged in and, when it has proxies
// to publish, the edge runs one.
func (t *tunnel) ready(ctx context.Context, proxies []v1.ProxyConfigurer) bool {
	deadline := time.After(renewReady)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if t.open.Load() {
			if len(proxies) == 0 {
				return true
			}
			for _, p := range proxies {
				if st, ok := t.svc.StatusExporter().GetProxyStatus(p.GetBaseConfig().Name); ok && st.Phase == proxy.ProxyPhaseRunning {
					return true
				}
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return false
		case <-tick.C:
		}
	}
}

// retire takes the tunnel out of the edge's choice, so it gets no new
// request, and closes it once nothing has been in flight for three looks,
// or when its connection ends by itself.
func (ts *tunnels) retire(ctx context.Context, t *tunnel) {
	c := *ts.common
	c.User = t.user
	if err := t.svc.UpdateConfigSource(&c, nil, nil); err != nil {
		log.Warnf("retire tunnel: %v", err)
	}
	tick := time.NewTicker(retireTick)
	defer tick.Stop()
	for idle := 0; idle < 3 && t.open.Load(); {
		select {
		case <-ctx.Done():
			idle = 3
		case <-tick.C:
			if t.streams.Load() == 0 {
				idle++
			} else {
				idle = 0
			}
		}
	}
	t.close()
	ts.mu.Lock()
	ts.retiring = slices.DeleteFunc(ts.retiring, func(o *tunnel) bool { return o == t })
	ts.mu.Unlock()
}

func (t *tunnel) close() {
	t.retired.Store(true)
	t.svc.Close()
	t.stop()
}

// writeMetrics writes the tunnel's metrics in Prometheus's text format.
func (ts *tunnels) writeMetrics(w io.Writer) {
	ts.mu.Lock()
	cur, retiring := ts.cur, slices.Clone(ts.retiring)
	ts.mu.Unlock()
	up, streams := 0, cur.streams.Load()
	if cur.open.Load() {
		up = 1
	}
	for _, t := range retiring {
		streams += t.streams.Load()
	}
	server, _ := cur.server.Load().(string)
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_up 1 while this replica's tunnel has its connection to the edge.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_up gauge")
	fmt.Fprintf(w, "fortresskube_tunnel_up %d\n", up)
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_info 1, with the address the tunnel dialled last as a label.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_info gauge")
	fmt.Fprintf(w, "fortresskube_tunnel_info{server=%q} 1\n", server)
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_age_seconds Seconds since the tunnel was opened (it is renewed at about -renew).")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_age_seconds gauge")
	fmt.Fprintf(w, "fortresskube_tunnel_age_seconds %.0f\n", time.Since(cur.born).Seconds())
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_streams Requests and TCP sessions this replica carries now, on its tunnel and on those it retires.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_streams gauge")
	fmt.Fprintf(w, "fortresskube_tunnel_streams %d\n", streams)
	fmt.Fprintln(w, "# HELP fortresskube_tunnels_retiring Old tunnels that still carry a request and take no new one.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnels_retiring gauge")
	fmt.Fprintf(w, "fortresskube_tunnels_retiring %d\n", len(retiring))
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_dials_total Dials to the edge, by result: ok, failed.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_dials_total counter")
	fmt.Fprintf(w, "fortresskube_tunnel_dials_total{result=\"ok\"} %d\n", ts.dialsOK.Load())
	fmt.Fprintf(w, "fortresskube_tunnel_dials_total{result=\"failed\"} %d\n", ts.dialsFailed.Load())
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_renewals_total Renewals of the tunnel, by result: ok, failed (the new tunnel did not come up, the old one stayed).")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_renewals_total counter")
	fmt.Fprintf(w, "fortresskube_tunnel_renewals_total{result=\"ok\"} %d\n", ts.renewalsOK.Load())
	fmt.Fprintf(w, "fortresskube_tunnel_renewals_total{result=\"failed\"} %d\n", ts.renewalsFailed.Load())
}
