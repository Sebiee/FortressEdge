package httpsvc

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// setUserTimeout bounds how long sent data may stay unacknowledged, keepalive
// probes included (TCP_USER_TIMEOUT).
func setUserTimeout(tc *net.TCPConn, d time.Duration) error {
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d/time.Millisecond))
	}); err != nil {
		return err
	}
	return serr
}
