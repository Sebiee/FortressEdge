//go:build !linux

package clock

import "time"

func apply(time.Time) error { return nil }
