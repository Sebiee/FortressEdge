//go:build linux

package frpsvc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	flog "github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server"
	glog "github.com/fatedier/golib/log"
	"golang.org/x/net/websocket"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/logx"
)

var setLogger sync.Once

// QUIC is frps's public listener on UDP 443.
type QUIC struct {
	ClientCA    string // PEM file of the CA that signs dark-node certificates
	Certificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Verify runs after the client certificate chain verified; an error
	// refuses the connection.
	Verify func(tls.ConnectionState) error
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
}

// Start runs frps on loopback. A non-nil quic also opens QUIC on public
// UDP 443. headerTimeout is how long a visitor's request waits for the
// origin's response headers, in whole seconds; 0 is frp's default.
func Start(ctx context.Context, quic *QUIC, headerTimeout time.Duration, onDomain func(domain string, added bool)) (*Frps, error) {
	// frp's own lines use a different clock. Fold them into slog so they
	// cannot land in the middle of a console line.
	setLogger.Do(func() {
		flog.Logger = glog.New(glog.WithOutput(logx.Forward("frp").Quiet(visitorLeft)), glog.WithLevel(glog.InfoLevel))
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
		OnDomain:             onDomain,
		// frp's own 404 page names frp. An empty one names nothing.
		Custom404Page: os.DevNull,
		// How long a visitor waits for the origin's response headers
		// (policy.yml's response_header_timeout). A stream whose headers
		// come with its first event, such as server-sent events, is cut
		// with a 504 if that event takes longer.
		VhostHTTPTimeout: int64(headerTimeout / time.Second),
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
	return &Frps{Control: controlHandler(control), Vhost: trustVhost(svr.VhostHTTP()), Stop: stop}, nil
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
// request until frps closes it.
func controlHandler(ln *connListener) http.Handler {
	return websocket.Handler(func(c *websocket.Conn) {
		// The tunnel is yamux, bytes: binary frames, as frps sends them.
		c.PayloadType = websocket.BinaryFrame
		closed := make(chan struct{})
		if ln.push(netpkg.WrapCloseNotifyConn(newBatchConn(c), func(error) { close(closed) })) {
			<-closed
		}
	})
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
