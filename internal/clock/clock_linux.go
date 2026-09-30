//go:build linux

package clock

import (
	"time"

	"golang.org/x/sys/unix"
)

// systemClock is CLOCK_REALTIME and the kernel's NTP discipline.
type systemClock struct{}

// step sets the clock d later (earlier for a negative d), and drops any
// offset the kernel was still slewing: it was measured against the old time.
func (systemClock) step(d time.Duration) error {
	ts := unix.NsecToTimespec(time.Now().Add(d).UnixNano())
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return err
	}
	tx := unix.Timex{Modes: unix.ADJ_OFFSET | unix.ADJ_NANO}
	_, err := unix.Adjtimex(&tx)
	return err
}

// slew hands the kernel's PLL an offset, as ntpd does: the kernel slews it
// away over about four poll intervals, and folds it into the frequency it
// has learned, so the next offset is smaller. Its time constant is the
// poll exponent, as ntpd sets it. Clearing STA_UNSYNC marks the clock
// synchronized, and the kernel then keeps the RTC in step too.
func (systemClock) slew(offset time.Duration, pollExp int, maxErr time.Duration) error {
	tx := unix.Timex{
		Modes: unix.ADJ_OFFSET | unix.ADJ_STATUS | unix.ADJ_NANO | unix.ADJ_TIMECONST |
			unix.ADJ_MAXERROR | unix.ADJ_ESTERROR,
		Offset:   offset.Nanoseconds(),
		Status:   unix.STA_PLL,
		Constant: int64(pollExp),
		Maxerror: (offset.Abs() + maxErr).Microseconds(),
		Esterror: offset.Abs().Microseconds(),
	}
	_, err := unix.Adjtimex(&tx)
	return err
}

// slewOnce slews offset at the kernel's fixed rate, 0.5 ms a second,
// apart from the PLL: adjtime's mode.
func (systemClock) slewOnce(offset time.Duration) error {
	tx := unix.Timex{Modes: unix.ADJ_OFFSET_SINGLESHOT, Offset: offset.Microseconds()}
	_, err := unix.Adjtimex(&tx)
	return err
}

// setFrequencyPPM sets the frequency correction outright, in the kernel's
// units: parts per million, scaled by 2^16.
func (systemClock) setFrequencyPPM(ppm float64) error {
	tx := unix.Timex{Modes: unix.ADJ_FREQUENCY, Freq: int64(ppm * 65536)}
	_, err := unix.Adjtimex(&tx)
	return err
}

// frequencyPPM is the frequency correction the kernel applies now.
func (systemClock) frequencyPPM() float64 {
	var tx unix.Timex
	if _, err := unix.Adjtimex(&tx); err != nil {
		return 0
	}
	return float64(tx.Freq) / 65536
}
