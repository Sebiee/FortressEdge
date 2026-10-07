package httpsvc

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	netpkg "github.com/fatedier/frp/pkg/util/net"

	"github.com/Sebiee/fortressedge/internal/metrics"
)

// A TCP route is a published name whose clients start with TLS and then
// speak a protocol of their own: PostgreSQL with direct TLS negotiation,
// Redis, AMQPS, LDAPS. The edge ends TLS on 443 with the name's
// certificate, as it does for an HTTP name, and forwards the decrypted
// bytes through the tunnel to the name's group. It does not read them.

// TCPRoute is a TCP route as frps holds it: the group (dark node) whose
// frpc serve it, the ALPN protocols they accept, and how to open a
// stream to one of them.
type TCPRoute struct {
	Group string
	ALPN  []string
	Dial  func(src net.Addr) (net.Conn, error)
}

// TCPRoutes finds a name's TCP route.
type TCPRoutes func(name string) (TCPRoute, bool)

// notTunnel is routes, but never for the tunnel name, whose connections
// need the HTTPS server's mutual TLS. frps refuses a proxy for it too.
func notTunnel(tunnel string, routes TCPRoutes) TCPRoutes {
	if routes == nil {
		return nil
	}
	tunnel = hostname(tunnel)
	return func(name string) (TCPRoute, bool) {
		if hostname(name) == tunnel {
			return TCPRoute{}, false
		}
		return routes(name)
	}
}

// helloTimeout bounds the wait for a ClientHello on 443, and a TCP
// route's handshake, as net/http's ReadHeaderTimeout bounds an HTTP one.
const helloTimeout = 10 * time.Second

// streamKeepAlive keeps a quiet session's NAT and firewall state, for the
// hours a database tool holds one, and finds a client that went away
// within about a minute.
var streamKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}

// Why a TCP route's connection ended as it did, as the metrics and the
// access log name it.
const (
	resultOK        = "ok"
	resultALPN      = "alpn_refused"   // the client offered none of the route's ALPN protocols
	resultPolicy    = "policy_refused" // tcp_connections_per_source
	resultNoBackend = "no_backend"     // no member of the group gave a stream
	resultTLS       = "tls_failed"     // the handshake failed otherwise
)

var resultNames = []string{resultOK, resultALPN, resultPolicy, resultNoBackend, resultTLS}

// How an ok connection closed.
const (
	closeClient       = "client"  // the client closed first, then the backend
	closeBackend      = "backend" // the other way round
	closeIdle         = "idle_timeout"
	closeClientError  = "client_error"
	closeBackendError = "backend_error"
	closeShutdown     = "shutdown"
)

// streams serves TCP routes' connections.
type streams struct {
	ctx    context.Context // ends when the edge shuts down
	routes TCPRoutes
	// tls is what an HTTP name's handshake gets, but ALPN: certificates,
	// versions, suites.
	tls   *tls.Config
	lim   *liveLimits
	vis   *visitors // nil: no strikes (tests)
	socks *sockets  // nil: keepalive as the listener set it (tests)
	st    *httpStats

	mu    sync.Mutex
	open  map[streamSource]int // per name and source, for tcp_connections_per_source
	stats map[string]*streamStats
}

type streamSource struct {
	name string
	src  netip.Prefix
}

// streamStats counts one TCP route's connections.
type streamStats struct {
	open, bytesIn, bytesOut atomic.Int64
	results                 sync.Map // result -> *atomic.Int64
}

func (s *streamStats) count(result string) {
	n, _ := s.results.LoadOrStore(result, new(atomic.Int64))
	n.(*atomic.Int64).Add(1)
}

func (s *streamStats) result(result string) int64 {
	if n, ok := s.results.Load(result); ok {
		return n.(*atomic.Int64).Load()
	}
	return 0
}

func newStreams(ctx context.Context, routes TCPRoutes, base *tls.Config, lim *liveLimits, vis *visitors, socks *sockets, st *httpStats) *streams {
	return &streams{
		ctx: ctx, routes: routes, tls: base, lim: lim, vis: vis, socks: socks, st: st,
		open: map[streamSource]int{}, stats: map[string]*streamStats{},
	}
}

func (s *streams) statsOf(name string) *streamStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats[name]
	if st == nil {
		st = &streamStats{}
		s.stats[name] = st
	}
	return st
}

// take serves c when hello names a TCP route, and reports whether it
// did. The ACME challenge for the name stays with the HTTP server, which
// answers it.
func (s *streams) take(c net.Conn, hello *tls.ClientHelloInfo) bool {
	if s == nil || s.routes == nil || wantsACMEALPN(hello) {
		return false
	}
	name := hostname(hello.ServerName)
	route, ok := s.routes(name)
	if !ok {
		return false
	}
	s.serve(c, name, hello.SupportedProtos, route)
	return true
}

// stream is one connection to a TCP route while the edge serves it.
type stream struct {
	id, name, group, alpn string
	ip                    netip.Addr
	start                 time.Time
	result, close         string
	in, out               int64 // client to backend, and back
	err                   error
}

func (s *streams) serve(c net.Conn, name string, offered []string, route TCPRoute) {
	ss := &stream{id: uuid.NewV7().String(), name: name, group: route.Group, start: time.Now(), ip: connIP(c)}
	defer s.finish(ss)
	defer c.Close()
	lim := s.lim.get()
	site := lim.Site(name, name)
	release, ok := s.admit(name, ss.ip, site.TCPConnsPerSource, lim)
	if !ok {
		ss.result = resultPolicy
		if s.vis != nil {
			s.vis.strike(visitorKey(ss.ip), "tcp_connections_per_source")
		}
		return
	}
	defer release()

	cfg := s.tls.Clone()
	cfg.GetConfigForClient = nil
	cfg.NextProtos = nil
	if get := cfg.GetCertificate; get != nil {
		// No certificate yet (an order that has not finished): closed
		// with no alert, as an HTTP name in that state is.
		cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			crt, err := get(hello)
			if err != nil {
				return nil, hideHandshake(hello, err)
			}
			return crt, nil
		}
	}
	if len(route.ALPN) > 0 {
		// The client's preference, among the route's protocols.
		i := slices.IndexFunc(offered, func(p string) bool { return slices.Contains(route.ALPN, p) })
		switch {
		case i >= 0:
			cfg.NextProtos = []string{offered[i]}
		case len(offered) == 0:
			// No ALPN extension to answer with no_application_protocol:
			// the connection closes before the handshake.
			ss.result = resultALPN
			return
		default:
			// Offered, none of them: crypto/tls fails the handshake with
			// no_application_protocol.
			cfg.NextProtos = slices.Clone(route.ALPN)
			ss.result = resultALPN
		}
	}
	tc := tls.Server(c, cfg)
	_ = c.SetDeadline(time.Now().Add(helloTimeout))
	if err := tc.HandshakeContext(s.ctx); err != nil || ss.result != "" {
		if ss.result == "" {
			ss.result, ss.err = resultTLS, err
		}
		return
	}
	_ = c.SetDeadline(time.Time{})
	ss.alpn = tc.ConnectionState().NegotiatedProtocol

	backend, err := route.Dial(c.RemoteAddr())
	if err != nil {
		ss.result, ss.err = resultNoBackend, err
		slog.Warn("tcp route: no backend", "site", name, "group", route.Group, "ip", ss.ip.String(), "err", err)
		return
	}
	if tcp := s.socks.tcpOf(c); tcp != nil {
		_ = tcp.SetKeepAliveConfig(streamKeepAlive)
	}
	st := s.statsOf(name)
	st.open.Add(1)
	defer st.open.Add(-1)
	ss.result = resultOK
	ss.in, ss.out, ss.close, ss.err = pipe(s.ctx, tc, backend, site.TCPIdleTimeout, func(in, out int) {
		st.bytesIn.Add(int64(in))
		st.bytesOut.Add(int64(out))
	})
}

// admit counts a connection from ip to name against most, unless ip is
// exempt, until release; false when ip already holds most.
func (s *streams) admit(name string, ip netip.Addr, most int, lim *edgeLimits) (release func(), ok bool) {
	if lim.exempted(ip) {
		most = 0
	}
	k := streamSource{name, visitorKey(ip)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if most > 0 && s.open[k] >= most {
		return nil, false
	}
	s.open[k]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.open[k]--; s.open[k] <= 0 {
				delete(s.open, k)
			}
		})
	}, true
}

// finish counts ss and writes its access log line, when the site's
// access log is on.
func (s *streams) finish(ss *stream) {
	s.statsOf(ss.name).count(ss.result)
	if ss.result != resultOK && ss.result != resultNoBackend && ss.err != nil {
		slog.Debug("tcp route: refused", "site", ss.name, "ip", ss.ip.String(), "result", ss.result, "err", ss.err)
	}
	acc := s.st.access.Load()
	if acc == nil || !s.lim.get().Site(ss.name, ss.name).AccessLog {
		return
	}
	elapsed := time.Since(ss.start)
	attrs := make([]slog.Attr, 0, 16)
	attrs = append(attrs,
		slog.String("id", ss.id),
		slog.String("ip", ss.ip.String()),
		slog.String("site", ss.name),
		slog.String("proto", "tcp"),
	)
	if ss.alpn != "" {
		attrs = append(attrs, slog.String("alpn", ss.alpn))
	}
	if ss.group != "" {
		attrs = append(attrs, slog.String("group", ss.group))
	}
	attrs = append(attrs, slog.String("result", ss.result))
	if ss.close != "" {
		attrs = append(attrs, slog.String("close", ss.close))
	}
	attrs = append(attrs,
		slog.Int64("in", ss.in),
		slog.Int64("out", ss.out),
		slog.Int64("ms", elapsed.Milliseconds()),
		slog.String("start", ss.start.UTC().Format(time.RFC3339Nano)),
		slog.Int64("us", elapsed.Microseconds()),
	)
	if ss.err != nil {
		attrs = append(attrs, slog.String("error", ss.err.Error()))
	}
	acc.LogAttrs(context.Background(), slog.LevelInfo, "", attrs...)
}

// pipe copies client to backend and backend to client until both
// directions end, or idle passes with no byte either way (0: never), or
// ctx ends. A direction that ends cleanly closes only its writing half on
// the other side: TLS's close_notify towards the client, a FIN through
// the tunnel towards the backend. moved is told of the bytes as they
// pass. It closes both, and says how they ended.
func pipe(ctx context.Context, client *tls.Conn, backend net.Conn, idle time.Duration, moved func(in, out int)) (in, out int64, how string, err error) {
	var (
		last  atomic.Int64 // when a byte last passed, either way
		mu    sync.Mutex
		ended []string // the directions that ended cleanly, in order
		once  sync.Once
		wg    sync.WaitGroup
	)
	last.Store(time.Now().UnixNano())
	end := func(h string, e error) {
		once.Do(func() {
			if ctx.Err() != nil {
				h, e = closeShutdown, nil
			}
			how, err = h, e
			_ = client.Close()
			_ = backend.Close()
		})
	}
	// copy moves src to dst. A read error is src's side's, a write
	// error dst's.
	copyDir := func(dst, src net.Conn, n *int64, srcSide, dstSide string, closeWrite func() error, count func(int)) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			k, rerr := src.Read(buf)
			if k > 0 {
				last.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:k]); werr != nil {
					end(dstSide+"_error", werr)
					return
				}
				*n += int64(k)
				count(k)
			}
			if rerr == nil {
				continue
			}
			if !errors.Is(rerr, io.EOF) {
				end(srcSide+"_error", rerr)
				return
			}
			if cerr := closeWrite(); cerr != nil {
				// No half-close on the way (a tunnel over plain
				// WebSocket): the whole connection goes.
				end(srcSide, nil)
				return
			}
			mu.Lock()
			ended = append(ended, srcSide)
			mu.Unlock()
			return
		}
	}
	wg.Add(2)
	go copyDir(backend, client, &in, "client", "backend", func() error { return netpkg.CloseWrite(backend) },
		func(k int) { moved(k, 0) })
	go copyDir(client, backend, &out, "backend", "client", client.CloseWrite, func(k int) { moved(0, k) })
	done := make(chan struct{})
	go func() {
		var tick <-chan time.Time
		var t *time.Timer
		if idle > 0 {
			t = time.NewTimer(idle)
			defer t.Stop()
			tick = t.C
		}
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				end(closeShutdown, nil)
				return
			case <-tick:
				quiet := time.Since(time.Unix(0, last.Load()))
				if quiet >= idle {
					end(closeIdle, nil)
					return
				}
				t.Reset(idle - quiet)
			}
		}
	}()
	wg.Wait()
	close(done)
	mu.Lock()
	first := closeClient
	if len(ended) > 0 {
		first = ended[0]
	}
	mu.Unlock()
	end(first, nil)
	return in, out, how, err
}

// connIP is the address c came from.
func connIP(c net.Conn) netip.Addr {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// tcpOf is the TCP socket under c, a connection accepted on a listener
// of s's.
func (s *sockets) tcpOf(c net.Conn) *net.TCPConn {
	if s == nil {
		return nil
	}
	tc, _ := s.m.Load(sockKey{c.LocalAddr().String(), c.RemoteAddr().String()})
	t, _ := tc.(*net.TCPConn)
	return t
}

func (s *streams) snapshot() map[string]map[string]int64 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	all := maps.Clone(s.stats)
	s.mu.Unlock()
	out := make(map[string]map[string]int64, len(all))
	for name, st := range all {
		m := map[string]int64{"open": st.open.Load(), "bytes_in": st.bytesIn.Load(), "bytes_out": st.bytesOut.Load()}
		for _, r := range resultNames {
			m[r] = st.result(r)
		}
		out[name] = m
	}
	return out
}

func (s *streams) writeMetrics(w *metrics.Writer) {
	if s == nil {
		return
	}
	s.mu.Lock()
	names := slices.Sorted(maps.Keys(s.stats))
	all := make([]*streamStats, len(names))
	for i, n := range names {
		all[i] = s.stats[n]
	}
	s.mu.Unlock()
	w.Family("fortressedge_tcp_route_connections", "gauge", "Connections to TCP routes open now, by site (the published name).")
	for i, st := range all {
		w.Int("fortressedge_tcp_route_connections", st.open.Load(), "site", names[i])
	}
	w.Family("fortressedge_tcp_route_connections_total", "counter",
		"Connections to TCP routes, by site and result: ok, alpn_refused, policy_refused, no_backend, tls_failed.")
	for i, st := range all {
		for _, r := range resultNames {
			if n := st.result(r); n > 0 {
				w.Int("fortressedge_tcp_route_connections_total", n, "site", names[i], "result", r)
			}
		}
	}
	w.Family("fortressedge_tcp_route_bytes_total", "counter",
		"Bytes TCP routes carried, by site and direction: in from the client, out to it.")
	for i, st := range all {
		w.Int("fortressedge_tcp_route_bytes_total", st.bytesIn.Load(), "site", names[i], "direction", "in")
		w.Int("fortressedge_tcp_route_bytes_total", st.bytesOut.Load(), "site", names[i], "direction", "out")
	}
}

// splitTLS hands take each connection whose ClientHello take wants, and
// the HTTPS server the rest, with the bytes the hello took put back. A
// connection that sends no ClientHello within helloTimeout, or not TLS,
// is closed, as the server's handshake would have.
func splitTLS(ln net.Listener, take func(net.Conn, *tls.ClientHelloInfo) bool) net.Listener {
	l := &splitListener{Listener: ln, take: take, conns: make(chan net.Conn), done: make(chan struct{})}
	go l.run()
	return l
}

type splitListener struct {
	net.Listener
	take  func(net.Conn, *tls.ClientHelloInfo) bool
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	err   error // why Accept returns no more, once done is closed
}

func (l *splitListener) run() {
	var delay time.Duration
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			// As net/http's Serve: a temporary error (out of file
			// descriptors) waits and tries again.
			if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(delay):
					continue
				case <-l.done:
					return
				}
			}
			l.stop(err)
			return
		}
		delay = 0
		go l.sort(c)
	}
}

func (l *splitListener) sort(c net.Conn) {
	hello, pc, err := peekHello(c)
	if err != nil {
		_ = c.Close()
		return
	}
	if l.take(pc, hello) {
		return
	}
	select {
	case l.conns <- pc:
	case <-l.done:
		_ = pc.Close()
	}
}

func (l *splitListener) stop(err error) {
	l.once.Do(func() {
		l.err = err
		close(l.done)
	})
}

func (l *splitListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, l.err
	}
}

func (l *splitListener) Close() error {
	l.stop(net.ErrClosed)
	return l.Listener.Close()
}

var errPeeked = errors.New("tls: hello read")

// peekHello reads c's ClientHello, and returns it with a connection that
// reads it again.
func peekHello(c net.Conn) (*tls.ClientHelloInfo, net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	defer c.SetReadDeadline(time.Time{})
	var buf bytes.Buffer
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnly{Conn: c, r: io.TeeReader(c, &buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = h
			return nil, errPeeked
		},
	}).Handshake()
	if hello == nil {
		return nil, nil, err
	}
	return hello, &replayConn{Conn: c, prefix: buf.Bytes()}, nil
}

// readOnly is c for reading a ClientHello: crypto/tls's alert for the
// handshake it gives up goes nowhere.
type readOnly struct {
	net.Conn
	r io.Reader
}

func (c readOnly) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c readOnly) Write(b []byte) (int, error) { return 0, errPeeked }
func (c readOnly) Close() error                { return nil }

// replayConn reads prefix, then the connection.
type replayConn struct {
	net.Conn
	prefix []byte
}

func (c *replayConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
