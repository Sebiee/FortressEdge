package httpsvc

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// sockets finds the TCP socket under a request, through TLS and the
// listener's wrappers, for the options only frp control's connection
// gets. A connection is in it while it is open.
type sockets struct {
	m sync.Map // sockKey -> *net.TCPConn
	// deadTimeout is policy.yml's tunnel_dead_timeout, for the tunnels
	// that connect from now on.
	deadTimeout atomic.Int64
}

func (s *sockets) setDeadTimeout(d time.Duration) { s.deadTimeout.Store(int64(d)) }

type sockKey struct{ local, remote string }

func (s *sockets) listen(ln net.Listener) net.Listener { return socketListener{ln, s} }

type socketListener struct {
	net.Listener
	s *sockets
}

func (l socketListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return c, nil
	}
	k := sockKey{tc.LocalAddr().String(), tc.RemoteAddr().String()}
	l.s.m.Store(k, tc)
	return &socketConn{TCPConn: tc, key: k, s: l.s}, nil
}

type socketConn struct {
	*net.TCPConn
	key  sockKey
	s    *sockets
	once sync.Once
}

func (c *socketConn) Close() error {
	c.once.Do(func() { c.s.m.CompareAndDelete(c.key, c.TCPConn) })
	return c.TCPConn.Close()
}

type socketsKey struct{}

// handler lets the handlers under h find their requests' sockets.
func (s *sockets) handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), socketsKey{}, s)))
	})
}

// socketOf is the TCP socket r came on, or nil.
func socketOf(r *http.Request) *net.TCPConn {
	s, _ := r.Context().Value(socketsKey{}).(*sockets)
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if s == nil || local == nil {
		return nil
	}
	tc, _ := s.m.Load(sockKey{local.String(), r.RemoteAddr})
	c, _ := tc.(*net.TCPConn)
	return c
}

// keepTunnelAlive has the kernel drop r's connection, frp control's,
// after tunnel_dead_timeout without an acknowledgment from the dark node:
// keepalive probes go out after a second of silence, every second, and
// data unacknowledged that long ends it too (TCP_USER_TIMEOUT). A lost
// frpc then leaves its group in seconds, not at frps's heartbeat
// timeout, and its share of requests goes to the others.
func keepTunnelAlive(r *http.Request) error {
	tc := socketOf(r)
	if tc == nil {
		return nil // not on a listener of serve's: tests
	}
	s, _ := r.Context().Value(socketsKey{}).(*sockets)
	d := time.Duration(s.deadTimeout.Load())
	if d <= 0 {
		return nil
	}
	if err := tc.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable: true, Idle: time.Second, Interval: time.Second, Count: max(1, int(d/time.Second)),
	}); err != nil {
		return err
	}
	return setUserTimeout(tc, d)
}
