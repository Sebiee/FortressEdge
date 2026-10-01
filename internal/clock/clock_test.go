package clock

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/ntp"

	"github.com/Sebiee/fortressedge/internal/metrics"
)

// answer is a valid NTPv4 answer: the clock is offset behind the server,
// measured over a round trip of rtt.
func answer(offset, rtt time.Duration) *ntp.Response {
	now := time.Now()
	return &ntp.Response{
		ClockOffset: offset, RTT: rtt, Version: 4, Stratum: 1,
		Time: now, ReferenceTime: now, RootDistance: rtt / 2,
	}
}

// fakeKernel records what the clock was told to do.
type fakeKernel struct {
	mu    sync.Mutex
	steps []time.Duration
	slews []time.Duration
	exps  []int
	freq  float64
	once  []time.Duration
}

func (k *fakeKernel) slewOnce(d time.Duration) error {
	k.once = append(k.once, d)
	return nil
}

func (k *fakeKernel) step(d time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.steps = append(k.steps, d)
	return nil
}

func (k *fakeKernel) slew(d time.Duration, exp int, _ time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.slews = append(k.slews, d)
	k.exps = append(k.exps, exp)
	return nil
}

func (k *fakeKernel) frequencyPPM() float64 { return k.freq }

func (k *fakeKernel) setFrequencyPPM(ppm float64) error {
	k.freq = ppm
	return nil
}

// servers answers each address with its func, called with the sample's
// number within the poll's burst (0, 1, ...).
type servers map[string]func(i int) (*ntp.Response, error)

// testClock is a clock for names, each resolving to one address,
// 192.0.2.<index+1>, which srv answers, with no wait between samples.
func testClock(names []string, srv servers) (*Clock, *fakeKernel) {
	c := New(names, "ip4")
	k := &fakeKernel{}
	c.kern = k
	c.gap = 0
	c.sleep = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	c.lookup = func(_ context.Context, _, host string) ([]net.IP, error) {
		for i, n := range names {
			if n == host {
				return []net.IP{net.IPv4(192, 0, 2, byte(i+1))}, nil
			}
		}
		return nil, errors.New("no such host")
	}
	var mu sync.Mutex
	seen := map[string]int{}
	c.query = func(addr string) (*ntp.Response, error) {
		mu.Lock()
		i := seen[addr]
		seen[addr]++
		mu.Unlock()
		f, ok := srv[addr]
		if !ok {
			return nil, errors.New("i/o timeout")
		}
		return f(i)
	}
	return c, k
}

func steady(offset, rtt time.Duration) func(int) (*ntp.Response, error) {
	return func(int) (*ntp.Response, error) { return answer(offset, rtt), nil }
}

var metas = []string{"ntp11.metas.ch", "ntp12.metas.ch", "ntp13.metas.ch"}

func near(got, want, tol time.Duration) bool { return (got - want).Abs() <= tol }

// Of each server's burst, the fastest sample counts: a slow one's offset
// carries its path's asymmetry.
func TestPollKeepsTheFastestSample(t *testing.T) {
	burstOf := func(i int) (*ntp.Response, error) {
		return []*ntp.Response{
			answer(9*time.Millisecond, 40*time.Millisecond),
			answer(2*time.Millisecond, 3*time.Millisecond),
			answer(-7*time.Millisecond, 30*time.Millisecond),
			answer(6*time.Millisecond, 25*time.Millisecond),
		}[i], nil
	}
	c, _ := testClock(metas, servers{"192.0.2.1:123": burstOf, "192.0.2.2:123": burstOf, "192.0.2.3:123": burstOf})
	sel, err := c.poll(context.Background(), burst)
	if err != nil {
		t.Fatal(err)
	}
	if !near(sel.offset, 2*time.Millisecond, 10*time.Microsecond) {
		t.Fatalf("offset %s, want the 3ms round trip's 2ms", sel.offset)
	}
	if c.st.rtt["ntp12.metas.ch"] != 3*time.Millisecond || c.st.queries[queryKey{"ntp11.metas.ch", "ok"}] != 4 {
		t.Fatalf("rtt %v queries %v", c.st.rtt, c.st.queries)
	}
}

// A server whose time the others do not share moves nothing, and is named.
func TestPollIgnoresAFalseticker(t *testing.T) {
	c, _ := testClock(metas, servers{
		"192.0.2.1:123": steady(1*time.Millisecond, 4*time.Millisecond),
		"192.0.2.2:123": steady(500*time.Millisecond, 4*time.Millisecond),
		"192.0.2.3:123": steady(1200*time.Microsecond, 4*time.Millisecond),
	})
	sel, err := c.poll(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !near(sel.offset, 1100*time.Microsecond, 150*time.Microsecond) {
		t.Fatalf("offset %s: the falseticker counted", sel.offset)
	}
	if c.st.rejected["ntp12.metas.ch"] != 1 || c.st.rejected["ntp11.metas.ch"] != 0 {
		t.Fatalf("rejected %v", c.st.rejected)
	}
}

// Without a majority of the configured servers agreeing, nothing is
// decided: one answer of three, or two that disagree.
func TestPollNeedsAMajority(t *testing.T) {
	for name, srv := range map[string]servers{
		"one of three answers": {"192.0.2.2:123": steady(80*time.Millisecond, 4*time.Millisecond)},
		"two answer, apart": {
			"192.0.2.1:123": steady(0, 4*time.Millisecond),
			"192.0.2.2:123": steady(300*time.Millisecond, 4*time.Millisecond),
		},
		"all invalid": {
			"192.0.2.1:123": func(int) (*ntp.Response, error) {
				r := answer(0, time.Millisecond)
				r.Stratum = 0 // a kiss of death
				return r, nil
			},
			"192.0.2.2:123": func(int) (*ntp.Response, error) {
				r := answer(0, time.Millisecond)
				r.Leap = ntp.LeapNotInSync
				return r, nil
			},
		},
	} {
		c, _ := testClock(metas, srv)
		if _, err := c.poll(context.Background(), burst); !errors.Is(err, errNoAgreement) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Two of three answering and agreeing are a majority.
	c, _ := testClock(metas, servers{
		"192.0.2.1:123": steady(3*time.Millisecond, 4*time.Millisecond),
		"192.0.2.3:123": steady(3*time.Millisecond, 4*time.Millisecond),
	})
	if _, err := c.poll(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if c.st.queries[queryKey{"ntp12.metas.ch", "error"}] != 1 {
		t.Fatalf("queries %v", c.st.queries)
	}
}

// One server configured is followed alone; a pool name's addresses are
// servers of their own, and must agree like any.
func TestPollSourcesOneServerAndAPool(t *testing.T) {
	c, _ := testClock([]string{"10.0.2.2:4123"}, servers{"10.0.2.2:4123": steady(time.Second, time.Millisecond)})
	if sel, err := c.poll(context.Background(), 1); err != nil || sel.server != "10.0.2.2:4123" || !near(sel.offset, time.Second, time.Microsecond) {
		t.Fatalf("%+v %v", sel, err)
	}

	c, _ = testClock([]string{"pool.ntp.org"}, servers{
		"198.51.100.1:123": steady(2*time.Millisecond, 5*time.Millisecond),
		"198.51.100.2:123": steady(2*time.Millisecond, 5*time.Millisecond),
		"198.51.100.3:123": steady(2*time.Millisecond, 5*time.Millisecond),
		"198.51.100.4:123": steady(-900*time.Millisecond, 5*time.Millisecond),
	})
	c.lookup = func(context.Context, string, string) ([]net.IP, error) {
		var ips []net.IP
		for i := range 6 {
			ips = append(ips, net.IPv4(198, 51, 100, byte(i+1)))
		}
		return ips, nil
	}
	srcs, n := c.sources(context.Background())
	if n != poolMembers || len(srcs) != poolMembers || srcs[3].name != "pool.ntp.org" {
		t.Fatalf("sources %v of %d", srcs, n)
	}
	if sel, err := c.poll(context.Background(), 1); err != nil || !near(sel.offset, 2*time.Millisecond, time.Microsecond) {
		t.Fatalf("pool: %+v %v", sel, err)
	}
}

func TestDecide(t *testing.T) {
	for _, tc := range []struct {
		offset time.Duration
		want   action
	}{
		{0, slew},
		{3 * time.Millisecond, slew},
		{stepAhead, slew},
		{stepAhead + time.Millisecond, step},
		{-300 * time.Millisecond, slew}, // ahead: slewed back, never stepped
		{-stepBack, slew},
		{-stepBack - time.Millisecond, step},
	} {
		if got := decide(tc.offset); got != tc.want {
			t.Errorf("decide(%s) = %v, want %v", tc.offset, got, tc.want)
		}
	}
}

func TestNextPollExp(t *testing.T) {
	exp, steady := minPollExp, 0
	for range steadyPolls * 10 {
		exp, steady = nextPollExp(exp, steady, 300*time.Microsecond)
	}
	if exp != maxPollExp {
		t.Fatalf("steady offsets reached 2^%d", exp)
	}
	if exp, _ = nextPollExp(exp, 0, 2*time.Millisecond); exp != maxPollExp {
		t.Fatalf("a middling offset moved the interval to 2^%d", exp)
	}
	if exp, _ = nextPollExp(exp, 3, -6*time.Millisecond); exp != minPollExp {
		t.Fatalf("an unsteady offset left the interval at 2^%d", exp)
	}
}

// Boot steps once the servers agree, retrying past lost answers.
func TestSyncSteps(t *testing.T) {
	c, k := testClock([]string{"ntp11.metas.ch"}, servers{"192.0.2.1:123": func(i int) (*ntp.Response, error) {
		if i < 2 {
			return nil, errors.New("i/o timeout")
		}
		return answer(-40*time.Second, 2*time.Millisecond), nil
	}})
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(k.steps) != 1 || k.steps[0] != -40*time.Second || len(k.slews) != 0 {
		t.Fatalf("steps %v slews %v", k.steps, k.slews)
	}
	if st := c.Status(); st["server"] != "ntp11.metas.ch" || st["synced_at"] == nil {
		t.Fatalf("status %v", st)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c, k = testClock(metas, servers{})
	c.sleep = sleepCtx
	if err := c.Sync(ctx); !errors.Is(err, errNoAgreement) || len(k.steps) != 0 {
		t.Fatalf("no servers: %v, steps %v", err, k.steps)
	}
}

// Running, a poll's offset is slewed at the interval's time constant, and
// stepped only when large.
func TestCorrect(t *testing.T) {
	c, k := testClock(metas, nil)
	c.st.freqSet = true
	for _, off := range []time.Duration{
		3 * time.Millisecond, -300 * time.Millisecond, 200 * time.Millisecond, -2 * time.Second,
	} {
		c.correct(selection{offset: off, server: "ntp11.metas.ch", distance: time.Millisecond})
	}
	want := []time.Duration{3 * time.Millisecond, -300 * time.Millisecond}
	if len(k.slews) != 2 || k.slews[0] != want[0] || k.slews[1] != want[1] {
		t.Fatalf("slews %v, want %v", k.slews, want)
	}
	if len(k.steps) != 2 || k.steps[0] != 200*time.Millisecond || k.steps[1] != -2*time.Second || c.st.steps != 2 {
		t.Fatalf("steps %v", k.steps)
	}
	if c.st.pollExp != minPollExp || k.exps[0] != minPollExp {
		t.Fatalf("poll 2^%d, time constants %v", c.st.pollExp, k.exps)
	}
}

// Until freqWindow of offsets are in, the clock is left alone; then the
// kernel is told the frequency error their slope shows, and the offset
// is slewed. A step starts the measurement again.
func TestFrequencyPhase(t *testing.T) {
	c, k := testClock(metas, nil)
	k.freq = 2
	start := time.Now()
	at := start
	c.now = func() time.Time { return at }
	// 7 ppm slow, with a little noise: 7µs more offset a second.
	noise := []time.Duration{40, -60, 10, 70, -30, 0, 50, -20, -40, 30, 10}
	for i := range 11 {
		at = start.Add(time.Duration(i) * 64 * time.Second)
		off := time.Duration(7*64*i)*time.Microsecond + noise[i]*time.Microsecond
		c.correct(selection{offset: off, server: "ntp11.metas.ch", distance: time.Millisecond})
		if len(k.once) > 0 {
			if i < 9 { // 9 × 64s < 10 minutes
				t.Fatalf("slewed at poll %d, before the frequency was measured", i)
			}
			break
		}
	}
	if !c.st.freqSet || math.Abs(k.freq-9) > 0.5 {
		t.Fatalf("frequency %.2f ppm, want about 2+7", k.freq)
	}
	// The backlog is slewed apart from the PLL; the next offset is the PLL's.
	if len(k.once) != 1 || len(k.slews) != 0 || len(k.steps) != 0 {
		t.Fatalf("once %v slews %v steps %v", k.once, k.slews, k.steps)
	}
	c.correct(selection{offset: 200 * time.Microsecond})
	if len(k.slews) != 1 {
		t.Fatalf("after: slews %v", k.slews)
	}

	c, k = testClock(metas, nil)
	c.now = func() time.Time { return at }
	c.correct(selection{offset: time.Millisecond})
	c.correct(selection{offset: 300 * time.Millisecond})
	if len(k.steps) != 1 || len(c.st.freqPts) != 0 {
		t.Fatalf("a step kept %d points", len(c.st.freqPts))
	}
}

func TestWriteMetrics(t *testing.T) {
	c, _ := testClock(metas, servers{
		"192.0.2.1:123": steady(time.Millisecond, 4*time.Millisecond),
		"192.0.2.2:123": steady(time.Millisecond, 6*time.Millisecond),
	})
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	w := metrics.NewWriter(&b)
	c.WriteMetrics(w)
	w.Flush()
	for _, want := range []string{
		"fortressedge_clock_offset_seconds 0.001\n",
		"fortressedge_clock_sync_timestamp_seconds ",
		"fortressedge_clock_steps_total 0\n",
		"fortressedge_clock_boot_step_seconds 0.001\n",
		"fortressedge_clock_poll_seconds 64\n",
		`fortressedge_clock_stratum{server="ntp11.metas.ch"} 1`,
		`fortressedge_ntp_queries_total{server="ntp11.metas.ch",result="ok"} 1`,
		`fortressedge_ntp_round_trip_seconds{server="ntp12.metas.ch"} 0.006`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("no %q in\n%s", want, b.String())
		}
	}
}

// Boot decides once a majority has answered and agrees, without waiting
// for a server whose answer is lost; one that has not answered is asked
// again soon, and one that has is not asked again.
func TestSyncDoesNotWaitForStragglers(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	c, k := testClock(metas, servers{
		"192.0.2.1:123": steady(2*time.Millisecond, 3*time.Millisecond),
		"192.0.2.2:123": func(i int) (*ntp.Response, error) {
			mu.Lock()
			asked["ntp12"]++
			mu.Unlock()
			if i == 0 { // the first answer is lost
				return nil, errors.New("i/o timeout")
			}
			return answer(2*time.Millisecond, 3*time.Millisecond), nil
		},
		"192.0.2.3:123": func(int) (*ntp.Response, error) {
			time.Sleep(queryTimeout) // never answers within the timeout
			return nil, errors.New("i/o timeout")
		},
	})
	start := time.Now()
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %s: boot waited for a silent server", took)
	}
	if len(k.steps) != 1 || !near(k.steps[0], 2*time.Millisecond, time.Microsecond) {
		t.Fatalf("steps %v", k.steps)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked["ntp12"] != 2 {
		t.Fatalf("ntp12 asked %d times, want 2: once lost, once again", asked["ntp12"])
	}
	if n := c.st.queries[queryKey{"ntp11.metas.ch", "ok"}]; n != 1 {
		t.Fatalf("ntp11, which answered, asked %d times", n)
	}
}
