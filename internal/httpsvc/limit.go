package httpsvc

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"
	"golang.org/x/time/rate"

	"github.com/Sebiee/fortressedge/internal/config"
)

// Per-visitor limits (config.Limits). A visitor is a source address:
// IPv4 /32, IPv6 /64 (one user usually holds a whole /64). They stop one
// source from flooding the edge; per-route and per-user limits belong to
// the gateway behind the dark node.
// A refused connection or request is a strike. More than ban_after
// strikes within ban_window, counted from the first, and the source is
// banned in XDP for ban.
const (
	visitorIdle = 5 * time.Minute // forget a quiet visitor after this
	// A refused source is logged once per noticeEvery, and the log gets
	// about ten such lines a minute in all, so a flood cannot fill it.
	noticeEvery = time.Minute
)

// liveLimits are the limits and exempt sources in force. A config change
// swaps them while the edge runs; every check reads the current ones.
type liveLimits struct{ p atomic.Pointer[edgeLimits] }

type edgeLimits struct {
	config.Limits
	Exempt []netip.Prefix
}

func newLiveLimits(lim config.Limits, exempt []netip.Prefix) *liveLimits {
	l := &liveLimits{}
	l.set(lim, exempt)
	return l
}

func (l *liveLimits) set(lim config.Limits, exempt []netip.Prefix) {
	l.p.Store(&edgeLimits{lim, slices.Clone(exempt)})
}

// get returns the limits in force; the defaults for a nil l (tests).
func (l *liveLimits) get() *edgeLimits {
	if l == nil {
		return &edgeLimits{Limits: config.DefaultLimits()}
	}
	return l.p.Load()
}

func (e *edgeLimits) exempted(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsValid() || slices.ContainsFunc(e.Exempt, func(p netip.Prefix) bool { return p.Contains(a) })
}

// visitors enforces the per-visitor limits and the global connection cap.
type visitors struct {
	mu     sync.Mutex
	m      map[netip.Prefix]*visitor
	lim    *liveLimits
	filt   edgeFilter
	tunnel string
	// known is the names the edge serves. A rejected request for any
	// other name gets no response, like every request for it.
	known    func(string) bool
	maxConns int // per listener, all sources together
	notices  *rate.Limiter

	rateLimited, connLimited, bans atomic.Int64
}

type visitor struct {
	req     *rate.Limiter
	strikes int
	since   time.Time // of the first strike in this window
	conns   int
	seen    time.Time
	banned  time.Time // until
	noticed time.Time
}

func newVisitors(tunnel string, lim *liveLimits, filt edgeFilter, known func(string) bool) *visitors {
	n := lim.get().MaxConns // fixed: netutil.LimitListener cannot be resized
	if n <= 0 {
		n = maxConns()
	}
	return &visitors{
		m:        make(map[netip.Prefix]*visitor),
		lim:      lim,
		filt:     filt,
		tunnel:   hostname(tunnel),
		known:    known,
		maxConns: n,
		notices:  rate.NewLimiter(rate.Every(6*time.Second), 10),
	}
}

func visitorKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// update puts new limits in force. Each visitor keeps its tokens; they
// refill at the new rate, up to the new burst.
func (v *visitors) update(lim config.Limits, exempt []netip.Prefix) {
	v.lim.set(lim, exempt)
	now := time.Now()
	v.mu.Lock()
	for _, vis := range v.m {
		vis.req.SetLimitAt(now, rate.Limit(lim.RequestsPerSecond))
		vis.req.SetBurstAt(now, lim.RequestBurst)
	}
	v.mu.Unlock()
	logLimits(v.lim.get(), v.maxConns)
}

func logLimits(l *edgeLimits, maxConns int) {
	slog.Info("visitor limits",
		"connections_per_source", l.ConnsPerSource, "requests_per_second", l.RequestsPerSecond,
		"request_burst", l.RequestBurst, "ban", l.Ban, "ban_after", l.BanAfter, "ban_window", l.BanWindow,
		"max_uri_size", l.MaxURIBytes,
		"max_body_size", l.MaxBodyBytes, "max_connections", maxConns, "exempt", len(l.Exempt))
}

// get returns k's visitor, creating it. Caller holds v.mu.
func (v *visitors) get(k netip.Prefix, now time.Time) *visitor {
	vis := v.m[k]
	if vis == nil {
		lim := v.lim.get()
		vis = &visitor{req: rate.NewLimiter(rate.Limit(lim.RequestsPerSecond), lim.RequestBurst)}
		v.m[k] = vis
	}
	vis.seen = now
	return vis
}

// strike counts one rejection against k, by the limit named by, and bans
// k in XDP once it has too many (unless bans are off).
func (v *visitors) strike(k netip.Prefix, by string) {
	now := time.Now()
	lim := v.lim.get()
	banFor := lim.Ban
	v.mu.Lock()
	vis := v.get(k, now)
	notice := now.Sub(vis.noticed) >= noticeEvery
	if notice {
		vis.noticed = now
	}
	if now.Sub(vis.since) > lim.BanWindow {
		vis.since, vis.strikes = now, 0
	}
	vis.strikes++
	ban := banFor > 0 && vis.strikes > lim.BanAfter && !now.Before(vis.banned)
	if ban {
		vis.banned = now.Add(banFor)
		vis.strikes = 0
	}
	v.mu.Unlock()
	if notice && v.notices.Allow() {
		slog.Warn("edge: source refused", "src", k, "by", by,
			"hint", "raise limits in fortress.yml, or add the source to exempt")
	}
	if !ban {
		return
	}
	v.bans.Add(1)
	slog.Warn("edge: source banned", "src", k, "for", banFor)
	if v.filt != nil {
		if err := v.filt.Ban(k.Addr(), banFor); err != nil {
			slog.Warn("edge: ban failed", "src", k, "err", err)
		}
	}
}

// limit rejects a request over its visitor's rate with 429. Requests on
// the tunnel name with a verified client certificate (dark nodes,
// operators) and exempt sources are never limited.
func (v *visitors) limit(h http.Handler) http.Handler {
	if v == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lim := v.lim.get()
		a := clientIP(r)
		if lim.RequestsPerSecond <= 0 || v.trusted(r) || lim.exempted(a) {
			h.ServeHTTP(w, r)
			return
		}
		k := visitorKey(a)
		now := time.Now()
		v.mu.Lock()
		ok := v.get(k, now).req.AllowN(now, 1)
		v.mu.Unlock()
		if ok {
			h.ServeHTTP(w, r)
			return
		}
		v.rateLimited.Add(1)
		v.strike(k, "requests_per_second")
		if v.known != nil && !v.known(r.Host) {
			hide()
		}
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
}

func (v *visitors) trusted(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && hostname(r.TLS.ServerName) == v.tunnel
}

// listen caps ln at maxConns connections, then closes a connection whose
// visitor already has connections_per_source open, before any byte is read.
func (v *visitors) listen(ln net.Listener) net.Listener {
	if v == nil {
		return ln
	}
	return visitorListener{netutil.LimitListener(ln, v.maxConns), v}
}

type visitorListener struct {
	net.Listener
	v *visitors
}

func (l visitorListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if c = l.v.admit(c); c != nil {
			return c, nil
		}
	}
}

// admit returns c, counted against its visitor, or nil after closing it.
// Every connection is counted, so the count is right when the limit or
// exempt changes while it is open.
func (v *visitors) admit(c net.Conn) net.Conn {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return c
	}
	lim := v.lim.get()
	most := lim.ConnsPerSource
	if lim.exempted(ap.Addr()) {
		most = 0
	}
	k := visitorKey(ap.Addr())
	v.mu.Lock()
	vis := v.get(k, time.Now())
	full := most > 0 && vis.conns >= most
	if !full {
		vis.conns++
	}
	v.mu.Unlock()
	if full {
		_ = c.Close()
		v.connLimited.Add(1)
		v.strike(k, "connections_per_source")
		return nil
	}
	return &visitorConn{Conn: c, v: v, k: k}
}

type visitorConn struct {
	net.Conn
	v    *visitors
	k    netip.Prefix
	once sync.Once
}

func (c *visitorConn) Close() error {
	c.once.Do(func() {
		c.v.mu.Lock()
		if vis := c.v.m[c.k]; vis != nil {
			vis.conns--
			vis.seen = time.Now()
		}
		c.v.mu.Unlock()
	})
	return c.Conn.Close()
}

// run forgets visitors that have been quiet for visitorIdle, until ctx ends.
func (v *visitors) run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			v.sweep(now)
		}
	}
}

func (v *visitors) sweep(now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, vis := range v.m {
		if vis.conns == 0 && now.Sub(vis.seen) > visitorIdle && now.After(vis.banned) {
			delete(v.m, k)
		}
	}
}

func (v *visitors) stats() map[string]any {
	v.mu.Lock()
	n := len(v.m)
	v.mu.Unlock()
	lim := v.lim.get()
	return map[string]any{
		"visitors":          n,
		"http_rate_limited": v.rateLimited.Load(),
		"conn_limited":      v.connLimited.Load(),
		"bans":              v.bans.Load(),
		// What is in force, so a refusal can be explained without the config.
		"limits": map[string]any{
			"connections_per_source":     lim.ConnsPerSource,
			"requests_per_second":        lim.RequestsPerSecond,
			"request_burst":              lim.RequestBurst,
			"new_connections_per_second": lim.NewConnsPerSecond,
			"new_connection_burst":       lim.NewConnBurst,
			"ban":                        lim.Ban.String(),
			"ban_after":                  lim.BanAfter,
			"ban_window":                 lim.BanWindow.String(),
			"max_connections":            v.maxConns,
			"max_header_size":            lim.MaxHeaderBytes,
			"max_uri_size":               lim.MaxURIBytes,
			"max_body_size":              lim.MaxBodyBytes,
			"max_http2_streams":          lim.MaxHTTP2Streams,
			"exempt":                     len(lim.Exempt),
		},
	}
}

// maxConns sizes the global connection cap from memory: about 64 KiB per
// connection (TLS buffers, goroutines, the loopback leg to frps) leaves
// room for everything else.
// ponytail: an estimate; measure with test/perf on the smallest VM you deploy.
func maxConns() int {
	const perConn = 64 << 10
	n := int(memTotal() / perConn)
	return min(max(n, 1024), 32768)
}

// memTotal is MemTotal from /proc/meminfo, or 0 when it cannot be read.
func memTotal() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			return kb << 10
		}
	}
	return 0
}
