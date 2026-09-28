//go:build linux

package clock

import (
	"time"

	"golang.org/x/sys/unix"
)

func apply(t time.Time) error {
	ts := unix.NsecToTimespec(t.UnixNano())
	return unix.ClockSettime(unix.CLOCK_REALTIME, &ts)
}
