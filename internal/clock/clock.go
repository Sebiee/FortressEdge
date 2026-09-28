package clock

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/beevik/ntp"
)

// Sync sets the system clock from an NTP server (host or host:port).
func Sync(ctx context.Context, server string) error {
	t, err := query(ctx, server)
	if err != nil {
		return err
	}
	offset := time.Until(t)
	if err := apply(t); err != nil {
		return err
	}
	slog.Info("clock synced", "server", server, "offset", offset.Round(time.Millisecond))
	return nil
}

// query returns the time according to server, corrected for round-trip
// delay and validated (stratum, dispersion, kiss-of-death). Each try is one
// UDP packet, so it retries until ctx ends: a lost packet must not fail the
// boot. Each try resolves server again, which moves between pool members.
func query(ctx context.Context, server string) (time.Time, error) {
	const try = 2 * time.Second
	for {
		timeout := try
		if deadline, ok := ctx.Deadline(); ok {
			timeout = min(try, time.Until(deadline))
		}
		resp, err := ntp.QueryWithOptions(server, ntp.QueryOptions{Timeout: timeout})
		if err == nil {
			err = resp.Validate()
		}
		if err == nil {
			return time.Now().Add(resp.ClockOffset), nil
		}
		select {
		case <-ctx.Done():
			return time.Time{}, fmt.Errorf("ntp %s: %w", server, err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}
