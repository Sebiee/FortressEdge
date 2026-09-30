// Package clock keeps the system clock on NTP time. Boot steps it once, so
// certificates and ACME start from a sane clock. Then the clock polls its
// servers every 64s, lengthening to 1024s while the offset stays small.
// It first measures the clock's frequency error, as ntpd does without a
// drift file: ten minutes of offsets left alone, whose slope the kernel is
// told to correct, and the offset they built up slewed away on the side,
// as adjtime does, so the PLL never takes it for a frequency error. From
// then on each offset goes to the kernel's NTP
// discipline (the PLL ntpd drives through adjtimex), which slews it away
// and follows the frequency as it wanders, so time never jumps. The PLL
// alone would take hours to learn a frequency error of a few ppm, and
// the clock would drift milliseconds meanwhile. Only a large
// offset is stepped, and backwards only when the clock is more than a
// second ahead, which normal running never is.
//
// Each poll takes a burst of samples from every server and keeps each
// server's fastest one, whose offset the round trip distorts least. The
// servers must then agree: a majority whose offsets, within each one's
// root distance, overlap. A server that answers nothing, or answers a
// time the others do not share, moves nothing.
package clock

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"

	"github.com/Sebiee/fortressedge/internal/metrics"
)

const (
	// burst is how many samples a poll takes from each server, gap apart:
	// ntpd servers answer a client that asks more often than every 2s
	// with a kiss of death.
	burst        = 4
	burstGap     = 2 * time.Second
	queryTimeout = 2 * time.Second

	// The poll interval is 2^pollExp seconds.
	minPollExp = 6  // 64s
	maxPollExp = 10 // 1024s
	// steadyPolls in a row within steadyOffset lengthen the interval;
	// an offset past unsteadyOffset shortens it to the least.
	steadyPolls    = 4
	steadyOffset   = 500 * time.Microsecond
	unsteadyOffset = 2 * time.Millisecond

	// stepAhead is the offset past which the clock is stepped forward
	// instead of slewed; stepBack, the offset back. The kernel slews up
	// to half a second a poll, so anything less than stepBack is slewed.
	stepAhead = 128 * time.Millisecond
	stepBack  = time.Second

	// A correction that leaves the next poll's offset past settleWarn,
	// and silence from every server for silentWarn, are warnings.
	settleWarn = 10 * time.Millisecond
	silentWarn = 30 * time.Minute

	// freqWindow is how long the offsets are measured, uncorrected, for
	// the frequency error; at least freqSamples of them. maxFreq bounds
	// the correction, as the kernel does.
	freqWindow  = 10 * time.Minute
	freqSamples = 5
	maxFreqPPM  = 500

	// poolMembers is how many addresses of a pool name are sources.
	poolMembers = 4
	// minDistance floors a server's root distance, so two honest servers
	// a few hundred microseconds apart on a fast LAN still overlap.
	minDistance = time.Millisecond
)

// Clock is the edge's NTP client. New makes one; Sync steps the clock
// once, and Run keeps it in step until its context ends.
type Clock struct {
	servers []string // as configured: host or host:port
	network string   // "ip4", "ip6", or "ip": the addresses the edge can reach

	// The world, which tests replace.
	query  func(addr string) (*ntp.Response, error)
	lookup func(ctx context.Context, network, host string) ([]net.IP, error)
	kern   kernel
	gap    time.Duration // between a burst's samples
	sleep  func(ctx context.Context, d time.Duration) bool
	now    func() time.Time

	mu sync.Mutex
	st state
}

// state is what the clock reports: status, metrics, and the loop's own.
type state struct {
	offset    time.Duration // the last poll's, as measured before its correction
	syncedAt  time.Time     // the last poll the servers agreed on
	server    string        // the agreeing server with the least root distance
	stratum   uint8
	steps     int64
	pollExp   int
	steady    int     // polls in a row within steadyOffset
	corrected bool    // the last poll slewed: the next one checks it took
	freqSet   bool    // the frequency error is measured and corrected
	freqPts   []point // the offsets measured for it
	queries   map[queryKey]int64
	rtt       map[string]time.Duration // each server's fastest sample in the last poll
	rejected  map[string]int64         // polls that found a server off from the others
	off       map[string]bool          // servers the last poll found off: warned once
	warnedAt  time.Time                // the last "no server answered" warning
}

type queryKey struct{ server, result string }

// point is one offset, and when it was measured.
type point struct {
	at     time.Time
	offset time.Duration
}

// kernel is the system clock: step sets it, slew hands the kernel's
// discipline an offset to slew away over the poll interval, slewOnce
// slews an offset at a fixed rate apart from the discipline, and
// setFrequencyPPM sets the frequency correction outright.
type kernel interface {
	step(d time.Duration) error
	slew(offset time.Duration, pollExp int, maxErr time.Duration) error
	slewOnce(offset time.Duration) error
	frequencyPPM() float64
	setFrequencyPPM(ppm float64) error
}

// New is a clock for servers (host or host:port; pool.ntp.org and its
// subdomains are pools, whose first addresses are servers of their own).
// network is "ip4" or "ip6" for an edge with one family, else "ip".
func New(servers []string, network string) *Clock {
	return &Clock{
		servers: servers,
		network: network,
		query: func(addr string) (*ntp.Response, error) {
			return ntp.QueryWithOptions(addr, ntp.QueryOptions{Timeout: queryTimeout})
		},
		lookup: net.DefaultResolver.LookupIP,
		kern:   systemClock{},
		gap:    burstGap,
		sleep:  sleepCtx,
		now:    time.Now,
		st: state{
			pollExp:  minPollExp,
			queries:  map[queryKey]int64{},
			rtt:      map[string]time.Duration{},
			rejected: map[string]int64{},
			off:      map[string]bool{},
		},
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Sync steps the clock to the servers' time, retrying each second until
// they agree or ctx ends. It is boot's: one sample a server, for speed.
func (c *Clock) Sync(ctx context.Context) error {
	for {
		sel, err := c.poll(ctx, 1)
		if err == nil {
			if err := c.kern.step(sel.offset); err != nil {
				return fmt.Errorf("clock: step: %w", err)
			}
			c.record(sel, time.Now())
			slog.Info("clock synced", "server", sel.server, "offset", sel.offset.Round(time.Microsecond),
				"servers", len(c.servers))
			return nil
		}
		if !c.sleep(ctx, time.Second) {
			return fmt.Errorf("clock: %w", err)
		}
	}
}

// Run polls and corrects the clock until ctx ends.
func (c *Clock) Run(ctx context.Context) {
	for c.sleep(ctx, c.interval()) {
		sel, err := c.poll(ctx, burst)
		if err != nil {
			c.silent(err)
			continue
		}
		c.correct(sel)
	}
}

func (c *Clock) interval() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Second << c.st.pollExp
}

// What a correction is, for an offset measured while running.
type action int

const (
	slew action = iota
	step
)

// decide steps a clock more than stepAhead behind or stepBack ahead, and
// slews anything less, so a clock only a little ahead never goes back.
func decide(offset time.Duration) action {
	if offset > stepAhead || offset < -stepBack {
		return step
	}
	return slew
}

// nextPollExp lengthens the interval after steadyPolls in a row within
// steadyOffset, and drops to the least on an offset past unsteadyOffset.
func nextPollExp(exp, steady int, offset time.Duration) (int, int) {
	switch a := offset.Abs(); {
	case a > unsteadyOffset:
		return minPollExp, 0
	case a > steadyOffset:
		return exp, 0
	}
	if steady++; steady >= steadyPolls && exp < maxPollExp {
		return exp + 1, 0
	}
	return exp, steady
}

// correct applies one poll's offset.
func (c *Clock) correct(sel selection) {
	if decide(sel.offset) == slew {
		switch c.measureFrequency(sel) {
		case measuring:
			c.record(sel, c.now())
			return
		case measured:
			// What built up while measuring goes on the side: fed to the
			// PLL, it would move the frequency just set.
			if err := c.kern.slewOnce(sel.offset); err != nil {
				slog.Error("clock: slew", "offset", sel.offset, "err", err)
			}
			c.record(sel, c.now())
			c.mu.Lock()
			c.st.corrected = true
			c.mu.Unlock()
			return
		}
	}
	c.mu.Lock()
	wasCorrected := c.st.corrected
	exp, steady := nextPollExp(c.st.pollExp, c.st.steady, sel.offset)
	c.mu.Unlock()
	if wasCorrected && sel.offset.Abs() > settleWarn {
		slog.Warn("clock: still off after a correction", "offset", sel.offset.Round(time.Microsecond), "server", sel.server)
	}
	corrected := false
	switch decide(sel.offset) {
	case step:
		if err := c.kern.step(sel.offset); err != nil {
			slog.Error("clock: step", "offset", sel.offset, "err", err)
			return
		}
		exp, steady = minPollExp, 0
		slog.Warn("clock: stepped", "offset", sel.offset.Round(time.Microsecond), "server", sel.server)
		c.mu.Lock()
		c.st.steps++
		c.st.freqPts = nil // measured across the step: start again
		c.mu.Unlock()
	case slew:
		if err := c.kern.slew(sel.offset, exp, sel.distance); err != nil {
			slog.Error("clock: slew", "offset", sel.offset, "err", err)
			return
		}
		corrected = true
	}
	c.record(sel, c.now())
	c.mu.Lock()
	c.st.pollExp, c.st.steady, c.st.corrected = exp, steady, corrected
	c.mu.Unlock()
	slog.Debug("clock: poll", "offset", sel.offset.Round(time.Microsecond), "server", sel.server,
		"next", time.Second<<exp, "frequency_ppm", c.kern.frequencyPPM())
}

// Where the frequency measurement stands after a poll.
type phase int

const (
	measuring phase = iota // collecting offsets: leave the clock alone
	measured               // done with this poll: set, and the backlog to slew
	tracking               // done before: the PLL follows
)

// measureFrequency collects offsets until freqWindow of them are in, then
// sets the kernel's frequency correction from their slope.
func (c *Clock) measureFrequency(sel selection) phase {
	c.mu.Lock()
	if c.st.freqSet {
		c.mu.Unlock()
		return tracking
	}
	c.st.freqPts = append(c.st.freqPts, point{c.now(), sel.offset})
	pts := slices.Clone(c.st.freqPts)
	c.mu.Unlock()
	if len(pts) < freqSamples || pts[len(pts)-1].at.Sub(pts[0].at) < freqWindow {
		return measuring
	}
	ppm := max(min(c.kern.frequencyPPM()+slopePPM(pts), maxFreqPPM), -maxFreqPPM)
	if err := c.kern.setFrequencyPPM(ppm); err != nil {
		slog.Error("clock: set frequency", "ppm", ppm, "err", err)
		return measuring
	}
	slog.Info("clock: frequency measured", "correction_ppm", ppm, "over", pts[len(pts)-1].at.Sub(pts[0].at).Round(time.Second))
	c.mu.Lock()
	c.st.freqSet, c.st.freqPts = true, nil
	c.mu.Unlock()
	return measured
}

// slopePPM is the least-squares slope of the offsets over time, in parts
// per million: how much faster the servers' time runs than the clock.
func slopePPM(pts []point) float64 {
	var st, so, stt, sto float64
	for _, p := range pts {
		t, o := p.at.Sub(pts[0].at).Seconds(), p.offset.Seconds()
		st, so, stt, sto = st+t, so+o, stt+t*t, sto+t*o
	}
	n := float64(len(pts))
	den := n*stt - st*st
	if den == 0 {
		return 0
	}
	return (n*sto - st*so) / den * 1e6
}

func (c *Clock) record(sel selection, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st.offset, c.st.syncedAt, c.st.server, c.st.stratum = sel.offset, at, sel.server, sel.stratum
}

// silent notes a poll the servers did not settle: nothing moves, and after
// silentWarn without a sync, a warning every silentWarn.
func (c *Clock) silent(err error) {
	now := time.Now()
	c.mu.Lock()
	since := now.Sub(c.st.syncedAt)
	warn := since > silentWarn && now.Sub(c.st.warnedAt) > silentWarn
	if warn {
		c.st.warnedAt = now
	}
	c.mu.Unlock()
	if warn {
		slog.Warn("clock: no agreeing NTP answer; the clock runs on its learned frequency",
			"since", since.Round(time.Second), "err", err)
	} else {
		slog.Debug("clock: poll", "err", err)
	}
}

// selection is one poll's verdict.
type selection struct {
	offset   time.Duration // to add to the clock
	distance time.Duration // the system peer's root distance: the error bound
	server   string        // the system peer: the agreeing server with the least distance
	stratum  uint8
}

// source is one server a poll asks: a configured name, and the address
// behind it, so a burst stays on one machine.
type source struct{ name, addr string }

// candidate is a source's fastest valid sample of a poll.
type candidate struct {
	source
	resp *ntp.Response
}

func (c candidate) distance() time.Duration { return max(c.resp.RootDistance, minDistance) }

var errNoAgreement = errors.New("no majority of the servers agree")

// poll takes samples from every source and returns what the majority
// agrees on.
func (c *Clock) poll(ctx context.Context, samples int) (selection, error) {
	srcs, n := c.sources(ctx)
	var (
		mu    sync.Mutex
		cands []candidate
		wg    sync.WaitGroup
	)
	for _, s := range srcs {
		wg.Go(func() {
			if r := c.measure(ctx, s, samples); r != nil {
				mu.Lock()
				cands = append(cands, candidate{s, r})
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	c.mu.Lock()
	for _, cand := range cands {
		c.st.rtt[cand.name] = cand.resp.RTT
	}
	c.mu.Unlock()
	agree, off, ok := intersect(cands, n)
	c.falsetickers(agree, off)
	if !ok {
		return selection{}, fmt.Errorf("%w: %d of %d answered", errNoAgreement, len(cands), n)
	}
	return combine(agree), nil
}

// falsetickers counts the servers a poll found off, and logs a server
// once when it starts to disagree and once when it agrees again.
func (c *Clock) falsetickers(agree, off []candidate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cand := range off {
		c.st.rejected[cand.name]++
		if !c.st.off[cand.name] {
			c.st.off[cand.name] = true
			slog.Warn("clock: a server disagrees with the others; ignored", "server", cand.name, "addr", cand.addr,
				"offset", cand.resp.ClockOffset.Round(time.Microsecond))
		}
	}
	for _, cand := range agree {
		if c.st.off[cand.name] {
			delete(c.st.off, cand.name)
			slog.Info("clock: a server agrees with the others again", "server", cand.name)
		}
	}
}

// sources resolves the configured servers. n is how many there are,
// answering or not, which is what a majority is counted of.
func (c *Clock) sources(ctx context.Context) (srcs []source, n int) {
	for _, s := range c.servers {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host, port = s, "123"
		}
		pool := host == "pool.ntp.org" || strings.HasSuffix(host, ".pool.ntp.org")
		ips, err := c.resolve(ctx, host)
		if err != nil || len(ips) == 0 {
			n++
			c.count(s, "dns")
			continue
		}
		if !pool {
			ips = ips[:1]
		}
		for _, ip := range ips[:min(len(ips), poolMembers)] {
			srcs = append(srcs, source{s, net.JoinHostPort(ip.String(), port)})
			n++
		}
	}
	return srcs, n
}

func (c *Clock) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	return c.lookup(ctx, c.network, host)
}

// measure takes samples from s, gap apart, and returns the valid one with
// the least round trip, or nil.
func (c *Clock) measure(ctx context.Context, s source, samples int) *ntp.Response {
	var best *ntp.Response
	for i := range samples {
		if i > 0 && !c.sleep(ctx, c.gap) {
			break
		}
		r, err := c.query(s.addr)
		switch {
		case err != nil:
			c.count(s.name, "error")
		case r.Validate() != nil:
			c.count(s.name, "invalid")
		default:
			c.count(s.name, "ok")
			if best == nil || r.RTT < best.RTT {
				best = r
			}
		}
	}
	return best
}

func (c *Clock) count(server, result string) {
	c.mu.Lock()
	c.st.queries[queryKey{server, result}]++
	c.mu.Unlock()
}

// intersect is Marzullo's algorithm, as NTP's selection uses it: each
// candidate says the true time is within its root distance of its offset,
// and the truth is where the most of those intervals overlap. The
// candidates whose interval reaches that region agree; the rest are
// falsetickers. ok needs a majority of all n sources, so a lone answer
// from one of three servers moves nothing.
func intersect(cands []candidate, n int) (agree, off []candidate, ok bool) {
	type edge struct {
		at    time.Duration
		start bool
	}
	edges := make([]edge, 0, 2*len(cands))
	for _, c := range cands {
		d := c.distance()
		edges = append(edges, edge{c.resp.ClockOffset - d, true}, edge{c.resp.ClockOffset + d, false})
	}
	// Starts before ends at the same point: touching intervals overlap.
	slices.SortFunc(edges, func(a, b edge) int {
		if a.at != b.at {
			return cmp.Compare(a.at, b.at)
		}
		if a.start == b.start {
			return 0
		}
		if a.start {
			return -1
		}
		return 1
	})
	best, count := 0, 0
	var lo, hi time.Duration
	for i, e := range edges {
		if e.start {
			if count++; count > best {
				best, lo, hi = count, e.at, edges[i+1].at
			}
		} else {
			count--
		}
	}
	for _, c := range cands {
		d := c.distance()
		if c.resp.ClockOffset-d <= hi && c.resp.ClockOffset+d >= lo {
			agree = append(agree, c)
		} else {
			off = append(off, c)
		}
	}
	return agree, off, len(agree) > 0 && len(agree) >= n/2+1
}

// combine averages the agreeing offsets, each weighted by the inverse of
// its root distance, and names the one with the least distance.
func combine(agree []candidate) selection {
	var sum, weights float64
	peer := agree[0]
	for _, c := range agree {
		w := 1 / c.distance().Seconds()
		sum += w * c.resp.ClockOffset.Seconds()
		weights += w
		if c.distance() < peer.distance() {
			peer = c
		}
	}
	return selection{
		offset:   time.Duration(sum / weights * float64(time.Second)),
		distance: peer.distance(),
		server:   peer.name,
		stratum:  peer.resp.Stratum,
	}
}

// Status is the clock for /~!ops/status.
func (c *Clock) Status() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := map[string]any{
		"offset":        c.st.offset.Seconds(),
		"server":        c.st.server,
		"stratum":       c.st.stratum,
		"poll":          (time.Second << c.st.pollExp).String(),
		"steps":         c.st.steps,
		"frequency_ppm": c.kern.frequencyPPM(),
		// false for freqWindow after boot, while the offsets are left alone
		"frequency_measured": c.st.freqSet,
	}
	if !c.st.syncedAt.IsZero() {
		m["synced_at"] = c.st.syncedAt.UTC().Format(time.RFC3339)
	}
	return m
}

// WriteMetrics writes the clock's metrics.
func (c *Clock) WriteMetrics(w *metrics.Writer) {
	c.mu.Lock()
	st := c.st
	st.queries, st.rtt, st.rejected = maps.Clone(c.st.queries), maps.Clone(c.st.rtt), maps.Clone(c.st.rejected)
	c.mu.Unlock()
	w.Family("fortressedge_clock_offset_seconds", "gauge",
		"The clock's offset from the NTP servers' time at the last poll, before its correction: positive when behind.")
	w.Sample("fortressedge_clock_offset_seconds", st.offset.Seconds())
	w.Family("fortressedge_clock_sync_timestamp_seconds", "gauge", "When the servers last agreed on the time, in Unix seconds.")
	if !st.syncedAt.IsZero() {
		w.Sample("fortressedge_clock_sync_timestamp_seconds", float64(st.syncedAt.UnixMilli())/1e3)
	}
	w.Family("fortressedge_clock_steps_total", "counter", "Times the clock was stepped after boot's, instead of slewed.")
	w.Int("fortressedge_clock_steps_total", st.steps)
	w.Family("fortressedge_clock_poll_seconds", "gauge", "The interval between polls now: 64s, up to 1024s while the offset stays small.")
	w.Int("fortressedge_clock_poll_seconds", 1<<st.pollExp)
	w.Family("fortressedge_clock_frequency_ppm", "gauge", "The frequency correction the kernel's discipline has learned, in parts per million.")
	w.Sample("fortressedge_clock_frequency_ppm", c.kern.frequencyPPM())
	w.Family("fortressedge_clock_stratum", "gauge", "The stratum of the server the clock follows most closely.")
	if st.server != "" {
		w.Int("fortressedge_clock_stratum", int64(st.stratum), "server", st.server)
	}
	w.Family("fortressedge_ntp_queries_total", "counter", "NTP queries by server and result: ok, error (no answer), invalid, dns.")
	keys := slices.SortedFunc(maps.Keys(st.queries), func(a, b queryKey) int {
		return cmp.Or(strings.Compare(a.server, b.server), strings.Compare(a.result, b.result))
	})
	for _, k := range keys {
		w.Int("fortressedge_ntp_queries_total", st.queries[k], "server", k.server, "result", k.result)
	}
	w.Family("fortressedge_ntp_round_trip_seconds", "gauge", "Each server's least round trip in its last poll.")
	for _, s := range slices.Sorted(maps.Keys(st.rtt)) {
		w.Sample("fortressedge_ntp_round_trip_seconds", st.rtt[s].Seconds(), "server", s)
	}
	w.Family("fortressedge_ntp_falsetickers_total", "counter", "Polls in which a server's time disagreed with the others', and was ignored.")
	for _, s := range slices.Sorted(maps.Keys(st.rejected)) {
		w.Int("fortressedge_ntp_falsetickers_total", st.rejected[s], "server", s)
	}
}
