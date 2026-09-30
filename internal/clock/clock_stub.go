//go:build !linux

package clock

import "time"

type systemClock struct{}

func (systemClock) step(time.Duration) error                     { return nil }
func (systemClock) slew(time.Duration, int, time.Duration) error { return nil }
func (systemClock) frequencyPPM() float64                        { return 0 }
func (systemClock) setFrequencyPPM(float64) error                { return nil }
func (systemClock) slewOnce(time.Duration) error                 { return nil }
