package main

import (
	"context"
	"errors"
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
//   - the look (-renew): at a fixed interval the replica logs in a second
//     time, with nothing to publish, and a balancer in front of several
//     edges gives that login to one of them. The edge says how many
//     tunnels of the node it would then have, and the replica asks the
//     edge of its tunnel whether it may leave for that one. That edge
//     grants it only when it has more tunnels that serve than the other
//     would, and counts the tunnel as gone from then on: so a tunnel moves
//     only when the move spreads the node's tunnels more evenly, and an
//     edge never lets its last one go. On a grant the second login
//     publishes and becomes the tunnel; else it is closed, and nothing
//     has changed. An edge of 0.10.0 or older does not count: with one,
//     the second login becomes the tunnel without asking;
//   - the retirement: the tunnel a replica left takes no new request, and
//     closes when the requests and TCP sessions it carries have ended, or
//     when it is the oldest of more than maxRetiring. The edge keeps a
//     work connection for the next request for up to a minute, so that is
//     up to a minute after the last request.

// maxRetiring is how many retired tunnels a replica keeps while their
// streams last, a WebSocket of hours among them. Each is a login of the
// node on the edge, which bounds those (the frp fork's limits), so a move
// that would keep one more closes the oldest, with what it still carries:
// a stream lives through at least maxRetiring moves.
const maxRetiring = 4

// stayWait is how long the edge gets to hear that a tunnel it let go
// stays after all.
const stayWait = 5 * time.Second

var (
	// renewReady is how long a look gets, from its dial until the new
	// tunnel publishes.
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

	// conn is the connector whose connection to the edge is up, nil while
	// none is. frp makes a connector for each login, and at a reconnect
	// the old one's Close may come after the new one's Open.
	conn    atomic.Pointer[countingConnector]
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
	if err == nil {
		c.t.conn.Store(c)
	}
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
	c.t.conn.CompareAndSwap(c, nil)
	return c.Connector.Close()
}

// up reports whether the tunnel's connection to the edge is up.
func (t *tunnel) up() bool { return t.conn.Load() != nil }

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

	// login is a tunnel's login; tests stand in an edge that does not
	// count with it.
	login func(*tunnel) (runID string, peers int, ok bool)

	dialsOK, dialsFailed   atomic.Int64
	looks                  [lookResults]atomic.Int64
	tunnelsCut, streamsCut atomic.Int64
}

// lookResult is how a look ended.
type lookResult int

const (
	lookMoved   lookResult = iota // its edge let the tunnel go to another
	lookStayed                    // its edge kept it: no better spread
	lookOldEdge                   // moved without asking: an edge does not count
	lookFailed                    // the look or the move failed; the tunnel stays
	lookResults
)

func (r lookResult) String() string {
	return [...]string{"moved", "stayed", "old_edge", "failed"}[r]
}

func newTunnels(common *v1.ClientCommonConfig, proxies []v1.ProxyConfigurer, visitors []v1.VisitorConfigurer) *tunnels {
	return &tunnels{
		common: common, visitors: visitors, proxies: proxies,
		pick:   newPicker(common.ServerAddr, common.User),
		failed: make(chan error, 1),
		login:  (*tunnel).login,
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
	t, err := ts.open(ctx, ts.proxies, ts.visitors)
	if err != nil {
		return err
	}
	ts.cur = t
	return nil
}

// open starts a tunnel that publishes proxies. Each tunnel logs in under
// its own user, so the edge tells the proxies of an old and a new one apart.
func (ts *tunnels) open(ctx context.Context, proxies []v1.ProxyConfigurer, visitors []v1.VisitorConfigurer) (*tunnel, error) {
	c := *ts.common
	if ts.gen > 0 {
		c.User = fmt.Sprintf("%s-%d", ts.common.User, ts.gen)
	}
	ts.gen++
	src := source.NewConfigSource()
	if err := src.ReplaceAll(proxies, visitors); err != nil {
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
	return ts.publishOn(ts.cur, proxies, ts.visitors)
}

// publishOn replaces what t publishes.
func (ts *tunnels) publishOn(t *tunnel, proxies []v1.ProxyConfigurer, visitors []v1.VisitorConfigurer) error {
	c := *ts.common
	c.User = t.user
	return t.svc.UpdateConfigSource(&c, proxies, visitors)
}

// GetProxyStatus is the status of a proxy of the current tunnel.
func (ts *tunnels) GetProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	ts.mu.Lock()
	t := ts.cur
	ts.mu.Unlock()
	return t.svc.StatusExporter().GetProxyStatus(name)
}

// renewEvery looks for a better edge about every age (within a fifth of
// it, so replicas started together do not look together).
func (ts *tunnels) renewEvery(ctx context.Context, age time.Duration) {
	for {
		wait := age - age/5 + rand.N(2*age/5+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			ts.look(ctx)
		}
	}
}

// login is the tunnel's login at its edge: the run ID the edge gave it,
// and how many tunnels of the node the edge then counted, this one among
// them; 0 from an edge that does not count (0.10.0 or older). ok is false
// while the tunnel is not logged in.
func (t *tunnel) login() (runID string, peers int, ok bool) {
	return t.svc.Login()
}

// look logs in a second time, without proxies, and asks the edge of the
// current tunnel whether the tunnel may leave for the edge that login
// reached. On a grant the new login publishes what the current tunnel
// does and takes over; the current one retires, and the oldest retiring
// one past maxRetiring is closed. In every other case the new login is
// closed and the current tunnel stays as it is, and so do the retiring
// ones. With an edge that does not count, or no connection to ask on, the
// new login takes over without a question.
func (ts *tunnels) look(ctx context.Context) lookResult {
	ts.mu.Lock()
	cur := ts.cur
	t, err := ts.open(ctx, nil, nil)
	ts.mu.Unlock()
	if err != nil {
		return ts.looked(lookFailed, "%v", err)
	}
	wait, cancel := context.WithTimeout(ctx, renewReady)
	defer cancel()
	there, n, ok := ts.loggedIn(wait, t)
	if !ok {
		t.close()
		return ts.looked(lookFailed, "the second login did not come up within %s", renewReady)
	}

	result, asked := lookMoved, false
	_, here, up := ts.login(cur)
	switch {
	case !up:
		// No edge to ask, and none that would lose a tunnel.
	case n == 0 || here == 0:
		result = lookOldEdge
	default:
		granted, serving, err := cur.svc.Leave(wait, there, n)
		switch {
		case errors.Is(err, client.ErrLeaveUnknown):
			// The tunnel has logged in again meanwhile, at an old edge.
			result = lookOldEdge
		case err != nil:
			// The edge may have granted it all the same.
			ts.stay(ctx, cur)
			t.close()
			return ts.looked(lookFailed, "no answer from the tunnel's edge: %v", err)
		case !granted:
			t.close()
			return ts.looked(lookStayed, "%d of this node's tunnels serve at its edge, and the edge offered would have %d", serving, n)
		default:
			asked = true
		}
	}

	ts.mu.Lock()
	proxies := ts.proxies
	err = ts.publishOn(t, proxies, ts.visitors)
	ts.mu.Unlock()
	if err == nil && !t.ready(wait, proxies, cur) {
		err = fmt.Errorf("the new tunnel did not publish within %s", renewReady)
	}
	if err != nil {
		if asked {
			ts.stay(ctx, cur)
		}
		t.close()
		return ts.looked(lookFailed, "%v", err)
	}

	ts.mu.Lock()
	ts.cur = t
	ts.retiring = append(ts.retiring, cur)
	var cut []*tunnel
	for len(ts.retiring) > maxRetiring {
		cut = append(cut, ts.retiring[0])
		ts.retiring = ts.retiring[1:]
	}
	// What was published while the new tunnel came up.
	if err := ts.publishOn(t, ts.proxies, ts.visitors); err != nil {
		log.Warnf("publish routes: %v", err)
	}
	ts.mu.Unlock()
	go ts.retire(ctx, cur, retireTick)
	for _, o := range cut {
		if n := o.streams.Load(); n > 0 {
			ts.tunnelsCut.Add(1)
			ts.streamsCut.Add(n)
			log.Warnf("old tunnel closed with %d streams still on it: it outlived %d moves", n, maxRetiring)
		}
		o.close()
	}
	server, _ := t.server.Load().(string)
	if n == 0 {
		return ts.looked(result, "to %s", server)
	}
	return ts.looked(result, "to %s, as tunnel %d of this node at that edge", server, n)
}

// loggedIn waits for t's login, until ctx ends.
func (ts *tunnels) loggedIn(ctx context.Context, t *tunnel) (runID string, peers int, ok bool) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if runID, peers, ok = ts.login(t); ok {
			return runID, peers, true
		}
		select {
		case <-ctx.Done():
			return "", 0, false
		case <-tick.C:
		}
	}
}

// stay tells the edge of t that t does not leave after all, so the edge
// counts it again. An edge that does not hear it has lost the tunnel, and
// counts it anew when it logs in again.
func (ts *tunnels) stay(ctx context.Context, t *tunnel) {
	ctx, cancel := context.WithTimeout(ctx, stayWait)
	defer cancel()
	if err := t.svc.Stay(ctx); err != nil {
		log.Debugf("tunnel look: the tunnel's edge did not hear that it stays: %v", err)
	}
}

// looked counts a look's result and logs it, with what led to it.
func (ts *tunnels) looked(r lookResult, format string, args ...any) lookResult {
	ts.looks[r].Add(1)
	why := fmt.Sprintf(format, args...)
	switch r {
	case lookMoved:
		log.Infof("tunnel moved %s; the old one closes when its requests have ended", why)
	case lookOldEdge:
		log.Infof("tunnel moved %s, without asking: an edge of 0.10.0 or older does not count; the old one closes when its requests have ended", why)
	case lookStayed:
		log.Infof("tunnel stays: %s", why)
	default:
		log.Warnf("tunnel look: %s; the tunnel stays as it is", why)
	}
	return r
}

// ready reports whether, before ctx ends, the tunnel has logged in and,
// when it has proxies to publish, the edge runs one, and each that it runs
// for cur: a name the edge refuses the new tunnel (a limit of the node's)
// would otherwise go dark when cur retires, while one it refuses both is
// no reason to wait.
func (t *tunnel) ready(ctx context.Context, proxies []v1.ProxyConfigurer, cur *tunnel) bool {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if t.up() && (len(proxies) == 0 || t.runsAll(proxies, cur)) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

// runsAll reports whether t runs one of proxies, and each that cur runs.
func (t *tunnel) runsAll(proxies []v1.ProxyConfigurer, cur *tunnel) bool {
	one := false
	for _, p := range proxies {
		name := p.GetBaseConfig().Name
		switch {
		case t.runs(name):
			one = true
		case cur.runs(name):
			return false
		}
	}
	return one
}

func (t *tunnel) runs(name string) bool {
	st, ok := t.svc.StatusExporter().GetProxyStatus(name)
	return ok && st.Phase == proxy.ProxyPhaseRunning
}

// retire takes the tunnel out of the edge's choice, so it gets no new
// request, and closes it once nothing has been in flight for three looks,
// or when its connection ends by itself.
func (ts *tunnels) retire(ctx context.Context, t *tunnel, every time.Duration) {
	if err := ts.publishOn(t, nil, nil); err != nil {
		log.Warnf("retire tunnel: %v", err)
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for idle := 0; idle < 3 && t.up(); {
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
	if cur.up() {
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
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_age_seconds Seconds since the tunnel was opened (it stays until a look moves it, or the pod restarts).")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_age_seconds gauge")
	fmt.Fprintf(w, "fortresskube_tunnel_age_seconds %.0f\n", time.Since(cur.born).Seconds())
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_streams Requests and TCP sessions this replica carries now, on its tunnel and on those it retires.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_streams gauge")
	fmt.Fprintf(w, "fortresskube_tunnel_streams %d\n", streams)
	fmt.Fprintln(w, "# HELP fortresskube_tunnels_retiring Tunnels the replica left that still carry a request and take no new one.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnels_retiring gauge")
	fmt.Fprintf(w, "fortresskube_tunnels_retiring %d\n", len(retiring))
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_dials_total Dials to the edge, by result: ok, failed.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_dials_total counter")
	fmt.Fprintf(w, "fortresskube_tunnel_dials_total{result=\"ok\"} %d\n", ts.dialsOK.Load())
	fmt.Fprintf(w, "fortresskube_tunnel_dials_total{result=\"failed\"} %d\n", ts.dialsFailed.Load())
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_looks_total Looks for a better edge (one about every -renew), by result: moved (its edge let the tunnel go to an edge with fewer), "+
		"stayed (the move would not spread the node's tunnels more evenly), old_edge (moved without asking: an edge of 0.10.0 or older does not count), "+
		"failed (the second login or the move failed, the tunnel stayed).")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_looks_total counter")
	for r := range lookResults {
		fmt.Fprintf(w, "fortresskube_tunnel_looks_total{result=%q} %d\n", r.String(), ts.looks[r].Load())
	}
	fmt.Fprintln(w, "# HELP fortresskube_tunnels_cut_total Old tunnels closed by a move while they still carried streams.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnels_cut_total counter")
	fmt.Fprintf(w, "fortresskube_tunnels_cut_total %d\n", ts.tunnelsCut.Load())
	fmt.Fprintln(w, "# HELP fortresskube_tunnel_streams_cut_total Requests and TCP sessions ended by those closes.")
	fmt.Fprintln(w, "# TYPE fortresskube_tunnel_streams_cut_total counter")
	fmt.Fprintf(w, "fortresskube_tunnel_streams_cut_total %d\n", ts.streamsCut.Load())
}
