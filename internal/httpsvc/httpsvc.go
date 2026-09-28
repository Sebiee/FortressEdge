package httpsvc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/logx"
	"github.com/Sebiee/fortressedge/internal/ops"
)

const drainTimeout = 30 * time.Second

// Handler sends the tunnel name to the ops API and frp control, and a host
// that routed reports to vhost, which is frps's site proxy in this process.
// Any other host gets no response at all. A nil routed passes every host
// to vhost. A nil lim uses the default limits; a nil control leaves frp
// control out.
func Handler(tunnel string, vhost, control, opsH http.Handler, st *httpStats, routed func(string) bool, lim *liveLimits) (http.Handler, error) {
	if vhost == nil {
		return nil, errors.New("nil vhost")
	}
	site := refuseMalformed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stampForwarded(r)
		vhost.ServeHTTP(w, r)
	}), st, lim)
	tunnel = strings.ToLower(tunnel)
	onTunnel := tunnelHandler(tunnel, opsH, control)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostname(r.Host)
		if tunnel != "" && host == tunnel {
			onTunnel.ServeHTTP(w, r)
			return
		}
		if routed != nil && !routed(host) {
			hide()
		}
		st.serveSite(site, host, w, r)
	}), nil
}

// tunnelHandler serves requests whose Host is the tunnel name: the ops API
// and the frp control WebSocket, both behind the tunnel's client cert. Only
// a dark-node identity may open frp control: an operator or log-reader
// certificate could otherwise register any hostname.
func tunnelHandler(tunnel string, opsH, control http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the tunnel's TLS server name asks for a client cert. A
		// connection that named a site has none, whatever its Host says.
		if r.TLS != nil && hostname(r.TLS.ServerName) != tunnel {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		if opsH != nil && strings.HasPrefix(r.URL.Path, config.OpsPathPrefix) {
			opsH.ServeHTTP(w, r)
			return
		}
		if control != nil && r.URL.Path == config.FrpWebsocketPath {
			if r.TLS != nil && NodeOnly(tunnel)(*r.TLS) != nil {
				slog.Warn("frp: not a dark node", "remote", r.RemoteAddr)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			control.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// NodeOnly accepts a verified client certificate only when it carries a
// dark-node identity of tunnel: spiffe://<tunnel>/node/<name>. It guards
// frp control on TCP 443 and, through frps, on QUIC.
func NodeOnly(tunnel string) func(tls.ConnectionState) error {
	tunnel = hostname(tunnel)
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("frp: no client certificate")
		}
		if role, _, ok := ca.Identify(cs.PeerCertificates[0], tunnel); !ok || role != ca.RoleNode {
			return errors.New("frp: not a dark-node certificate")
		}
		return nil
	}
}

// hide ends the request with no response: HTTP/1 closes the connection and
// HTTP/2 resets the stream. A name the edge does not serve learns nothing,
// not even a status code.
func hide() {
	panic(http.ErrAbortHandler)
}

// stampForwarded replaces forwarding headers a visitor can forge. The
// edge is the hop that saw the connection, so these are the ones the
// origin gets. frps, in this process, is told not to append itself.
//
// It also makes the target origin-form: frps sends an absolute-form one
// on as it came, like a forward proxy.
func stampForwarded(r *http.Request) {
	if r.URL.Host != "" || r.URL.Scheme != "" {
		r.URL.Scheme, r.URL.Host = "", ""
		r.RequestURI = r.URL.RequestURI()
	}
	h := r.Header
	for _, k := range forwarding {
		h.Del(k)
	}
	// A header named in Connection is hop-by-hop, and frps's proxy drops
	// it after this: a visitor could strip the ones the edge sets. Upgrade
	// and the rest stay for frps.
	if conn := h.Values("Connection"); len(conn) > 0 {
		var keep []string
		for _, v := range conn {
			for tok := range strings.SplitSeq(v, ",") {
				tok = strings.TrimSpace(tok)
				if tok != "" && !slices.Contains(stamped, http.CanonicalHeaderKey(tok)) {
					keep = append(keep, tok)
				}
			}
		}
		h.Del("Connection")
		if len(keep) > 0 {
			h.Set("Connection", strings.Join(keep, ", "))
		}
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		h.Set("X-Forwarded-For", ip)
		h.Set("X-Real-IP", ip)
	}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	h.Set("X-Forwarded-Proto", proto)
	h.Set("X-Forwarded-Host", r.Host)
}

// forwarding are the headers about the visitor that the edge sets on a
// site request, in canonical form; a visitor's own are dropped. stamped
// adds the request id serveSite set: none of them may be hop-by-hop.
var (
	forwarding = []string{
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-Ip", "Forwarded",
	}
	stamped = append(slices.Clone(forwarding), requestIDHeaderOut)
)

// Serve runs the HTTP and HTTPS servers until ctx ends. policy is the
// policy.yml cfg holds, as stored; apply stores and applies a new one.
func Serve(ctx context.Context, cfg config.Config, policy []byte, filt edgeFilter, domains *Domains, control, vhost http.Handler, apply ops.ApplyFunc, reboot func()) error {
	st := &httpStats{}
	if cfg.AccessLog {
		w, err := logx.OpenAccess(config.AccessLogDir, cfg.AccessLogMaxSize, cfg.AccessLogMaxFiles)
		if err != nil {
			return fmt.Errorf("access log: %w", err)
		}
		st.access = newAccessLog(w)
		slog.Info("access log on", "dir", config.AccessLogDir, "api", config.OpsAccessPath,
			"max_size_mib", cfg.AccessLogMaxSize>>20, "max_files", cfg.AccessLogMaxFiles)
	}
	track := newConns()
	logx.SetConnections(track.Len)
	lim := newLiveLimits(cfg.Limits, cfg.Exempt)
	vis := newVisitors(cfg.Tunnel, lim, filt, domains.Known)
	go vis.run(ctx)
	// The ops API rides the tunnel SNI's mTLS.
	oh := ops.New(cfg, policy, logx.BootID(), config.LogDir)
	oh.SetStatus(func() map[string]any { return statusExtra(st, filt, track, vis) })
	if apply != nil {
		oh.SetApply(func(b []byte) (ops.Outcome, error) {
			out, err := apply(b)
			if err == nil && !out.Reboot {
				oh.SetConfig(out.Cfg)
				vis.update(out.Cfg.Limits, out.Cfg.Exempt)
			}
			return out, err
		}, reboot)
	}
	slog.Info("ops api up", "logs", config.OpsLogsPath, "status", config.OpsStatusPath, "policy", config.OpsPolicyPath)
	// Sites are frps's proxy in this process. The request is already parsed.
	h, err := Handler(cfg.Tunnel, vhost, control, oh, st, domains.Routed, lim)
	if err != nil {
		return err
	}
	h = vis.limit(protect(h, st, lim))
	tlsCfg, err := tlsConfig(ctx, cfg, domains)
	if err != nil {
		return err
	}
	httpH := vis.limit(redirectHTTPS(domains.Known))
	logLimits(lim.get(), vis.maxConns)
	// Fixed while the servers run: a change to these reboots (config.BootLimits).
	servers := []*http.Server{newServer(":80", httpH, nil), newServer(":443", h, tlsCfg)}
	for _, s := range servers {
		s.MaxHeaderBytes = cfg.Limits.MaxHeaderBytes
		s.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: cfg.Limits.MaxHTTP2Streams}
	}
	return serve(ctx, servers, track, vis, drainTimeout)
}

// redirectHTTPS answers plain HTTP for the names HTTPS answers, and no
// other name.
func redirectHTTPS(known func(string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !known(r.Host) {
			hide()
		}
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

func newServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    config.DefaultLimits().MaxHeaderBytes,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: config.DefaultLimits().MaxHTTP2Streams},
		ErrorLog:          log.New(serverLog{}, "", 0),
		// net/http would answer "OPTIONS *" itself, for any Host, so a
		// scan of the address would get a 200. Routing decides instead.
		DisableGeneralOptionsHandler: true,
	}
}

// serverLog is net/http's own error log. A failed TLS handshake is what
// every scanner, and every name the edge does not serve, produces, so it
// is a debug line, not a console line.
type serverLog struct{}

func (serverLog) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	lvl := slog.LevelInfo
	if strings.HasPrefix(msg, "http: TLS handshake error") {
		lvl = slog.LevelDebug
	}
	slog.Log(context.Background(), lvl, msg, "src", "http")
	return len(p), nil
}

func serve(ctx context.Context, servers []*http.Server, track *conns, vis *visitors, drainFor time.Duration) error {
	errc := make(chan error, len(servers))
	for _, s := range servers {
		raw, err := net.Listen("tcp", s.Addr)
		if err != nil {
			drain(servers, track, drainFor)
			return err
		}
		ln := track.listen(vis.listen(raw))
		go func(s *http.Server, ln net.Listener) {
			if s.TLSConfig != nil {
				errc <- s.ServeTLS(tlsOnly{ln}, "", "")
				return
			}
			errc <- s.Serve(ln)
		}(s, ln)
	}
	slog.Info("fortressedge: listening")
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			drain(servers, track, drainFor)
			return err
		}
		return ctx.Err()
	case <-ctx.Done():
		slog.Info("fortressedge: draining connections")
		drain(servers, track, drainFor)
		return ctx.Err()
	}
}

func drain(servers []*http.Server, track *conns, d time.Duration) {
	sctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Go(func() { _ = s.Shutdown(sctx) })
	}
	wg.Wait()
	track.closeAll()
	for _, s := range servers {
		_ = s.Close()
	}
}

// tlsOnly closes a connection whose first byte does not start a TLS
// handshake record. net/http would otherwise answer plain HTTP on the TLS
// port with its own "Client sent an HTTP request to an HTTPS server" 400.
type tlsOnly struct{ net.Listener }

func (l tlsOnly) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsOnlyConn{Conn: c}, nil
}

type tlsOnlyConn struct {
	net.Conn
	checked bool // the TLS handshake reads from one goroutine
}

const recordTypeHandshake = 0x16

func (c *tlsOnlyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if !c.checked && n > 0 {
		c.checked = true
		if b[0] != recordTypeHandshake {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
	}
	return n, err
}

// conns is every open connection on the listeners, hijacked or not.
// net/http forgets a connection once a handler hijacks it (WebSockets,
// frp control), so drain closes what is left here, and the console and
// status count it.
type conns struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func newConns() *conns {
	return &conns{m: make(map[net.Conn]struct{})}
}

func (t *conns) listen(ln net.Listener) net.Listener { return trackedListener{ln, t} }

func (t *conns) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

func (t *conns) closeAll() {
	t.mu.Lock()
	all := make([]net.Conn, 0, len(t.m))
	for c := range t.m {
		all = append(all, c)
	}
	t.mu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
}

type trackedListener struct {
	net.Listener
	t *conns
}

func (l trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, t: l.t}
	l.t.mu.Lock()
	l.t.m[tc] = struct{}{}
	l.t.mu.Unlock()
	return tc, nil
}

type trackedConn struct {
	net.Conn
	t    *conns
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.t.mu.Lock()
		delete(c.t.m, c)
		c.t.mu.Unlock()
	})
	return c.Conn.Close()
}

func tlsConfig(ctx context.Context, cfg config.Config, domains *Domains) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.ClientCA) {
		return nil, errors.New("client_ca: no certificates")
	}
	magic, err := domains.acme(ctx, cfg)
	if err != nil {
		return nil, err
	}
	base := magic.TLSConfig()
	base.GetCertificate = domains.certificate
	base.NextProtos = append([]string{"h2", "http/1.1"}, base.NextProtos...)
	return requireTunnelCert(base, pool, cfg.Tunnel, domains.Known), nil
}

// requireTunnelCert wraps base so the tunnel SNI — and only it — requires a
// client cert and speaks plain http/1.1 (frps websocket). Site
// hosts and ACME TLS-ALPN-01 handshakes pass through unchanged. A server
// name that known rejects, or no server name, closes the connection before
// any byte is sent: no certificate, no alert.
func requireTunnelCert(base *tls.Config, pool *x509.CertPool, tunnel string, known func(string) bool) *tls.Config {
	tunnel = hostname(tunnel)
	orig := base.GetConfigForClient
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if !known(hello.ServerName) {
			return nil, hideHandshake(hello, errors.New("tls: unknown server name"))
		}
		if wantsACMEALPN(hello) {
			if orig != nil {
				return orig(hello)
			}
			return nil, nil
		}
		cur := base
		if orig != nil {
			c, err := orig(hello)
			if err != nil {
				return nil, err
			}
			if c != nil {
				cur = c
			}
		}
		out := cur.Clone()
		out.GetConfigForClient = nil
		if get := out.GetCertificate; get != nil {
			// A known name can still lack a certificate: a wildcard route
			// under ACME, or an order that has not finished.
			out.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				c, err := get(hello)
				if err != nil {
					return nil, hideHandshake(hello, err)
				}
				return c, nil
			}
		}
		if hostname(hello.ServerName) != tunnel {
			return out, nil
		}
		out.ClientAuth = tls.RequireAndVerifyClientCert
		out.ClientCAs = pool
		out.NextProtos = []string{"http/1.1"}
		return out, nil
	}
	return base
}

// hideHandshake closes the connection under a handshake that is about to
// fail, so crypto/tls has nowhere to write its alert.
func hideHandshake(hello *tls.ClientHelloInfo, err error) error {
	if hello.Conn != nil {
		_ = hello.Conn.Close()
	}
	return err
}

func wantsACMEALPN(hello *tls.ClientHelloInfo) bool {
	return len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == "acme-tls/1"
}

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// acmeConfig is certmagic with its own cache and storage. The cache's
// timer checks every managed certificate each renew_interval. There is no
// on-demand issuance: Domains decides which names are managed.
func acmeConfig(cfg config.Config) (*certmagic.Config, *certmagic.Cache, error) {
	if err := os.MkdirAll(config.CertsDir, 0o700); err != nil {
		return nil, nil, err
	}
	// ACME lifecycle events (issuance, renewal, failures) are edge-relevant;
	// they go through slog like our own logs.
	logger := logx.Zap()
	// Cache maintenance asks GetConfigForCert which config manages a cert.
	// certmagic's default cache answers with certmagic.Default, which has
	// another storage, CA, and trust roots.
	cacheOpts := certmagic.CacheOptions{
		Logger:             logger,
		RenewCheckInterval: cfg.RenewInterval,
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return nil, errors.New("acme: config not ready")
		},
	}
	cache := certmagic.NewCache(cacheOpts)
	magic := certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: config.CertsDir},
		Logger:  logger,
	})
	cacheOpts.GetConfigForCert = func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil }
	cache.SetOptions(cacheOpts)
	issuer := certmagic.ACMEIssuer{CA: cfg.ACME, Agreed: true, DisableHTTPChallenge: true, Logger: logger}
	if len(cfg.ACMECA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.ACMECA) {
			return nil, nil, fmt.Errorf("acme_ca: no certificates")
		}
		// Replaces the system roots for the directory connection only.
		issuer.TrustedRoots = pool
	}
	acme := certmagic.NewACMEIssuer(magic, issuer)
	magic.Issuers = []certmagic.Issuer{acme}
	return magic, cache, nil
}

// QUICCertificate is what frps presents on UDP 443, and only to the tunnel
// name: a probe naming anything else gets no certificate. It is the
// certmagic config TCP 443 uses, so both present the same certificate and
// a renewal on either is used by the other's next handshake.
func QUICCertificate(ctx context.Context, cfg config.Config, domains *Domains) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	tunnel := hostname(cfg.Tunnel)
	magic, err := domains.acme(ctx, cfg)
	if err != nil {
		return nil, err
	}
	get := magic.GetCertificate
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hostname(hello.ServerName) != tunnel {
			return nil, fmt.Errorf("quic: %q is not the tunnel name", hello.ServerName)
		}
		return get(hello)
	}, nil
}
