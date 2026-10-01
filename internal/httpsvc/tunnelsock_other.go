//go:build !linux

package httpsvc

import (
	"net"
	"time"
)

func setUserTimeout(*net.TCPConn, time.Duration) error { return nil }
