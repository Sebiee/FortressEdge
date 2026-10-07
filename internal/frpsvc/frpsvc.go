//go:build linux

package frpsvc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	frpmetrics "github.com/fatedier/frp/pkg/metrics"
	flog "github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server"
	"github.com/fatedier/frp/server/group"
	glog "github.com/fatedier/golib/log"
	"golang.org/x/net/websocket"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/logx"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// setup hands frp's logger and metrics to the edge's, once per process:
// both are frp globals.
var setup sync.Once

// QUIC is frps's public listener on UDP 443.
type QUIC struct {
	ClientCA    string // PEM file of the CA that signs dark-node certificates
	Certificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Verify runs after the client certificate chain verified; an error
	// refuses the connection.
	Verify func(tls.ConnectionState) error
}

// Options are how frps runs in the edge.
type Options struct {
	// QUIC, when set, opens frp control on public UDP 443.
	QUIC *QUIC
	// HeaderTimeout is how long a visitor's request waits for the
	// origin's response headers when the request does not say
	// (vhost.WithResponseHeaderTimeout), in whole seconds; 0 is frp's
	// default.
	HeaderTimeout time.Duration
	// OnDomain is told when a name gains its first route and loses its last.
	OnDomain func(domain string, added bool)
	// OnTCPDomain is the same for TCP routes (tcp-tls proxies).
	OnTCPDomain func(domain string, added bool)
	// Tunnel is the name dark nodes log in on: no proxy may have it.
	Tunnel string
	// OnProxyError gets each site request frps could not proxy.
	OnProxyError func(*http.Request, error)
	// Node names the dark node of a tunnel connection's verified client
	// certificate, for the per-node session count.
	Node func(tls.ConnectionState) string
}

// Frps is a running frps.
type Frps struct {
	// Control serves frp control's WebSocket, which httpsvc hands it
	// once it has checked the dark node's certificate: the upgraded
	// connection goes to frps in-process, not over loopback.
	Control http.Handler
	// Vhost is frps's site proxy, called in-process. The edge has already
	// parsed the request; it is not written to a port and parsed again.
	Vhost http.Handler
	// Stop shuts frps down.
	Stop func()

	svr *server.Service
}

// Start runs frps on loopback, and QUIC on public UDP 443 with opts.QUIC.
func Start(ctx context.Context, opts Options) (*Frps, error) {
	quic, headerTimeout := opts.QUIC, opts.HeaderTimeout
	setup.Do(func() {
		// frp's own lines use a different clock. Fold them into slog so
		// they cannot land in the middle of a console line.
		flog.Logger = glog.New(glog.WithOutput(logx.Forward("frp").Quiet(quietLine)), glog.WithLevel(glog.InfoLevel))
		frpmetrics.Add(tunnel)
	})
	cfg := &v1.ServerConfig{
		BindAddr:      config.FrpsBindAddr,
		BindPort:      config.FrpsTCPPort,
		QUICBindPort:  0,
		ProxyBindAddr: config.FrpsBindAddr,
		// frps builds its site proxy only with a vhost port. Sharing
		// BindPort keeps it on the muxer, which frp's Close shuts; httpsvc
		// calls the proxy in-process (Frps.Vhost) and sends it nothing here.
		VhostHTTPPort: config.FrpsTCPPort,
		// httpsvc terminates TLS and sets X-Forwarded-*.
		VhostHTTPBehindProxy: true,
		OnDomain:             opts.OnDomain,
		OnProxyError:         opts.OnProxyError,
		// TCP routes: httpsvc ends their TLS and dials the route.
		EnableTCPTLS:     true,
		OnTCPTLSDomain:   opts.OnTCPDomain,
		OnDomainConflict: tunnel.conflict,
		ReservedDomain:   reserved(opts.Tunnel),
		// A surplus work connection is a burst's leftover: counted, and
		// closed without the error frpc would log.
		OnWorkConnDiscarded: func() { tunnel.discards.Add(1) },
		// frp's own 404 page names frp. An empty one names nothing.
		Custom404Page: os.DevNull,
		// How long a visitor waits for the origin's response headers
		// (policy.yml's response_header_timeout). A stream whose headers
		// come with its first event, such as server-sent events, is cut
		// with a 504 if that event takes longer.
		VhostHTTPTimeout: int64(headerTimeout / time.Second),
		// A dark node's tunnels are one group: its connections, from as
		// many frpc as it runs, share its names, and no other node can
		// take them.
		Identity: func(c net.Conn) string {
			if n, ok := c.(*nodeConn); ok {
				return n.node
			}
			return ""
		},
		Auth: v1.AuthServerConfig{
			Method: "token",
		},
	}
	if quic != nil {
		// Public UDP 443. BindAddr stays 127.0.0.1, so TCP 7000 does not.
		cfg.QUICBindAddr = "0.0.0.0"
		cfg.QUICBindPort = config.FrpsQUICPort
		cfg.Transport.TLS.AllowPlaintext = true
		cfg.Transport.TLS.GetCertificate = quic.Certificate
		cfg.Transport.TLS.TrustedCaFile = quic.ClientCA
		cfg.Transport.TLS.VerifyConnection = quic.Verify
		cfg.OnQUICConn = func(cs tls.ConnectionState) func() { return tunnel.session(nodeName(opts.Node, cs)) }
		cfg.QUICIdentity = func(cs tls.ConnectionState) string { return nodeName(opts.Node, cs) }
	}
	if err := cfg.Complete(); err != nil {
		return nil, err
	}
	svr, err := server.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("frps: %w", err)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		svr.Run(runCtx)
	}()
	control := newConnListener()
	go svr.HandleListener(control, false)
	// Cancel the context Run honors, then Close once cancel is published so we
	// do not race Service.cancel, then wait until Run returns so ports are free.
	stop := func() {
		_ = control.Close()
		runCancel()
		_ = waitRun(context.Background(), 15*time.Second)
		_ = svr.Close()
		<-done
	}
	if err := wait(ctx, config.ControlAddr(), 15*time.Second); err != nil {
		stop()
		return nil, err
	}
	slog.Info("frps up", "control", config.ControlAddr(), "quic", cfg.QUICBindPort != 0,
		"response_header_timeout", time.Duration(cfg.VhostHTTPTimeout)*time.Second)
	return &Frps{Control: controlHandler(control, opts.Node), Vhost: trustVhost(svr.VhostHTTP()), Stop: stop, svr: svr}, nil
}

// quietLine is a frp line an operator does not need at info or warn: a
// visitor who left, and a response body cut short, which OnProxyError
// logs with the request it belongs to.
func quietLine(msg string) bool {
	return visitorLeft(msg) || strings.HasPrefix(msg, "httputil: ReverseProxy read error during body copy")
}

// visitorLeft matches frp's line for a request whose visitor went away
// (a reload, a closed tab, a stream closed) before the origin answered:
// the visitor's choice, not an error. frp logs it at warn.
func visitorLeft(msg string) bool {
	rest, ok := strings.CutPrefix(msg, "do http proxy request [host: ")
	return ok && strings.HasSuffix(rest, "] error: "+context.Canceled.Error())
}

// trustVhost tells frps the edge already set X-Forwarded-* from the visitor,
// so this process is not appended as another hop.
func trustVhost(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, vhost.TrustForwarded(r))
	})
}

// controlHandler upgrades frp control's WebSocket as frps's own listener
// does, then gives the connection to frps through ln and holds the
// request until frps closes it. node names the dark node, for the
// session count.
func controlHandler(ln *connListener, node func(tls.ConnectionState) string) http.Handler {
	return websocket.Handler(func(c *websocket.Conn) {
		var name string
		if r := c.Request(); r.TLS != nil {
			name = nodeName(node, *r.TLS)
			defer tunnel.session(name)()
		}
		// The tunnel is yamux, bytes: binary frames, as frps sends them.
		c.PayloadType = websocket.BinaryFrame
		closed := make(chan struct{})
		conn := netpkg.WrapCloseNotifyConn(newBatchConn(c), func(error) { close(closed) })
		if ln.push(&nodeConn{Conn: conn, node: name}) {
			<-closed
		}
	})
}

// nodeConn is a tunnel connection with its dark node's name, for frps's
// Identity.
type nodeConn struct {
	net.Conn
	node string
}

// batchConn gathers the writes that arrive while one is on the wire into
// the next. yamux writes each frame's header and body apart; on the
// WebSocket each write would be a frame, a TLS record and a syscall of
// its own. An idle connection writes at once, so batching adds no delay.
type batchConn struct {
	net.Conn
	mu      sync.Mutex
	cond    sync.Cond
	pending []byte // waiting for the writer
	spare   []byte // the last batch's buffer, for reuse
	err     error  // the write that failed; later writes return it
	closed  bool
	done    chan struct{} // closed when the writer stops
}

// maxBatch bounds pending: a Write waits while more than this is queued.
const maxBatch = 256 << 10

func newBatchConn(c net.Conn) *batchConn {
	b := &batchConn{Conn: c, done: make(chan struct{})}
	b.cond.L = &b.mu
	go b.writer()
	return b
}

func (b *batchConn) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.pending) > maxBatch && b.err == nil && !b.closed {
		b.cond.Wait()
	}
	if b.err != nil {
		return 0, b.err
	}
	if b.closed {
		return 0, net.ErrClosed
	}
	b.pending = append(b.pending, p...)
	b.cond.Broadcast()
	return len(p), nil
}

func (b *batchConn) writer() {
	defer close(b.done)
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		for len(b.pending) == 0 && !b.closed {
			b.cond.Wait()
		}
		if len(b.pending) == 0 {
			return // closed, and all written
		}
		batch := b.pending
		b.pending = b.spare[:0]
		b.mu.Unlock()
		_, err := b.Conn.Write(batch)
		b.mu.Lock()
		b.spare = batch
		b.cond.Broadcast() // room for waiting writers
		if err != nil {
			b.err = err
			return
		}
	}
}

// Close writes what is pending, for a second at most, then closes.
func (b *batchConn) Close() error {
	b.mu.Lock()
	b.closed = true
	b.cond.Broadcast()
	b.mu.Unlock()
	select {
	case <-b.done:
	case <-time.After(time.Second):
	}
	return b.Conn.Close()
}

// connListener is a net.Listener fed by push: connections that arrived
// elsewhere, for frps's HandleListener.
type connListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnListener() *connListener {
	return &connListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

// push hands c to Accept, or closes it when the listener is closed.
func (l *connListener) push(c net.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		_ = c.Close()
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: config.FrpsTCPPort}
}

// wait polls addr until frps accepts TCP or d elapses.
func wait(ctx context.Context, addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var err error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var c net.Conn
		c, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("wait %s: %w", addr, err)
}

// waitRun blocks until Service.Run has published cancel and Accept'd on the
// control port. Close reads cancel; calling it earlier races with Run.
func waitRun(ctx context.Context, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, err := net.DialTimeout("tcp", config.ControlAddr(), 200*time.Millisecond)
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			return fmt.Errorf("wait run: not TCP")
		}
		_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
		// Half-close so Accept+TLS-peek sees EOF and drops us immediately.
		_, _ = tc.Write([]byte("x"))
		_ = tc.CloseWrite()
		_, last = tc.Read(make([]byte, 1))
		tc.Close()
		if last != nil {
			if ne, ok := last.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// EOF/reset: HandleListener accepted — cancel is set.
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return fmt.Errorf("wait run %s: %w", config.ControlAddr(), last)
}

// tunnel counts what frps does for dark nodes. frps's metrics hook is a
// process global, so this is one too.
var tunnel = &tunnelStats{}

// tunnelStats is frps's ServerMetrics: logins and proxies, from frps;
// sessions, discards, and name conflicts, from the edge's hooks.
type tunnelStats struct {
	logins, clients, proxies, discards atomic.Int64

	mu        sync.Mutex
	sessions  map[string]int // open tunnel connections, by dark node
	conflicts map[conflict]int64
}

// conflict is a proxy refused because its name is the other kind's.
type conflict struct{ name, refused string }

// conflict is frps's OnDomainConflict: a name is an HTTP name or a TCP
// route, and the second claim to it is refused.
func (t *tunnelStats) conflict(domain, refused, holder string) {
	t.mu.Lock()
	if t.conflicts == nil {
		t.conflicts = map[conflict]int64{}
	}
	k := conflict{domain, refused}
	t.conflicts[k]++
	first := t.conflicts[k] == 1
	t.mu.Unlock()
	// frpc retries a refused proxy every half minute or so: the first
	// refusal is a warning, the rest are counted.
	lvl := slog.LevelDebug
	if first {
		lvl = slog.LevelWarn
	}
	slog.Log(context.Background(), lvl, "frps: name refused: it is already the other kind's",
		"name", domain, "refused", kindName(refused), "holder", kindName(holder))
}

// reserved refuses the tunnel name to every proxy: a TCP route for it
// would take dark nodes' and operators' connections, before their mutual
// TLS. Names compare as frps gives them, lower case, without a trailing
// dot.
func reserved(tunnel string) func(string) bool {
	tunnel = strings.TrimSuffix(strings.ToLower(tunnel), ".")
	return func(domain string) bool {
		return tunnel != "" && strings.TrimSuffix(domain, ".") == tunnel
	}
}

// kindName is the edge's name for a kind of proxy.
func kindName(kind string) string {
	if kind == group.DomainKindTCPTLS {
		return "tcp_route"
	}
	return kind
}

// TCPRoute is name's TCP route, if it has one.
func (f *Frps) TCPRoute(name string) (group.TCPTLSRoute, bool) {
	return f.svr.TCPTLSRoute(name)
}

func (t *tunnelStats) NewClient() {
	t.logins.Add(1)
	t.clients.Add(1)
}

func (t *tunnelStats) CloseClient()                            { t.clients.Add(-1) }
func (t *tunnelStats) NewProxy(_, _, _, _ string)              { t.proxies.Add(1) }
func (t *tunnelStats) CloseProxy(_, _ string)                  { t.proxies.Add(-1) }
func (*tunnelStats) OpenConnection(_, _ string)                {}
func (*tunnelStats) CloseConnection(_, _ string)               {}
func (*tunnelStats) AddTrafficIn(_ string, _ string, _ int64)  {}
func (*tunnelStats) AddTrafficOut(_ string, _ string, _ int64) {}

// session counts one open tunnel connection of node until done.
func (t *tunnelStats) session(node string) (done func()) {
	t.mu.Lock()
	if t.sessions == nil {
		t.sessions = map[string]int{}
	}
	t.sessions[node]++
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			if t.sessions[node]--; t.sessions[node] <= 0 {
				delete(t.sessions, node)
			}
			t.mu.Unlock()
		})
	}
}

func nodeName(node func(tls.ConnectionState) string, cs tls.ConnectionState) string {
	if node == nil {
		return ""
	}
	return node(cs)
}

// Groups counts each dark node's logged-in frpc: the members of its
// group, which share its names.
func (f *Frps) Groups() map[string]int {
	groups := f.svr.Clients()
	delete(groups, "") // none, outside tests: the edge admits dark nodes only
	return groups
}

// WriteMetrics writes the tunnel's metrics: dark nodes, logins, and the
// work connections that carry site requests.
func (f *Frps) WriteMetrics(w *metrics.Writer) {
	tunnel.mu.Lock()
	sessions := maps.Clone(tunnel.sessions)
	tunnel.mu.Unlock()
	w.Family("fortressedge_tunnel_clients", "gauge",
		"Open tunnel connections (WebSocket or QUIC), by the dark node's SPIFFE name (node/<name>).")
	for _, node := range slices.Sorted(maps.Keys(sessions)) {
		w.Int("fortressedge_tunnel_clients", int64(sessions[node]), "node", node)
	}
	groups := f.Groups()
	w.Family("fortressedge_tunnel_group_members", "gauge",
		"Logged-in frpc of each dark node, by its SPIFFE name (node/<name>): they share its names, and requests are spread across them.")
	for _, g := range slices.Sorted(maps.Keys(groups)) {
		w.Int("fortressedge_tunnel_group_members", int64(groups[g]), "group", g)
	}
	tunnel.mu.Lock()
	conflicts := maps.Clone(tunnel.conflicts)
	tunnel.mu.Unlock()
	w.Family("fortressedge_name_conflicts_total", "counter",
		"Proxies refused because their name is the other kind's, by name and the kind refused (http, tcp_route): a name is one or the other.")
	for _, c := range slices.SortedFunc(maps.Keys(conflicts), func(a, b conflict) int {
		return strings.Compare(a.name+" "+a.refused, b.name+" "+b.refused)
	}) {
		w.Int("fortressedge_name_conflicts_total", conflicts[c], "name", c.name, "refused", kindName(c.refused))
	}
	w.Family("fortressedge_tunnel_logins_total", "counter", "frpc logins frps accepted.")
	w.Int("fortressedge_tunnel_logins_total", tunnel.logins.Load())
	w.Family("fortressedge_tunnel_proxies", "gauge", "Proxies dark nodes have registered with frps now.")
	w.Int("fortressedge_tunnel_proxies", tunnel.proxies.Load())
	pooled, idle, active := f.svr.WorkConns()
	w.Family("fortressedge_work_connections", "gauge",
		"Work connections to dark nodes, by state: pooled (sent ahead by frpc), idle (kept after a request), active (carrying one).")
	w.Int("fortressedge_work_connections", int64(pooled), "state", "pooled")
	w.Int("fortressedge_work_connections", int64(idle), "state", "idle")
	w.Int("fortressedge_work_connections", int64(active), "state", "active")
	w.Family("fortressedge_work_connections_discarded_total", "counter",
		"Work connections frpc sent beyond its pool (transport.poolCount, at most 5, plus 10), closed unused.")
	w.Int("fortressedge_work_connections_discarded_total", tunnel.discards.Load())
}
