//go:build e2e

package e2e

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

var (
	perfFiles = flag.Int("perf-files", 0, "TestPerfGuard replays the first this many files of open-appsec's "+
		"legitimate set; 0 skips it (make perf-guard sets it)")
	perfRate   = flag.Float64("perf-rate", 1000, "requests a second the perf guard sends: low enough for a 2-core runner")
	perfRounds = flag.Int("perf-rounds", 5, "times the perf guard boots and measures each build")
	perfBase   = flag.String("base-iso", "", "the bench ISO of the commit to compare with; "+
		"empty compares allocations with testdata/perf-baseline.json only")
	perfCPUTol   = flag.Float64("perf-cpu-tolerance", 0.20, "how much more CPU a request may cost than with -base-iso")
	perfAllocTol = flag.Float64("perf-alloc-tolerance", 0.10, "how many more allocations and bytes a request may cost")
	perfMemTol   = flag.Float64("perf-mem-tolerance", 0.15, "how much more memory (peak RSS) the edge may hold")
)

const perfBaseline = "perf-baseline.json"

// edgeCost is what the edge process spent per request in one replay, and
// the latency the visitors saw.
type edgeCost struct {
	CPUMicros  float64 `json:"cpu_us"`
	Allocs     float64 `json:"allocs"`
	AllocBytes float64 `json:"alloc_bytes"`
	GCPer1k    float64 `json:"gc_per_1k"`
	P50        float64 `json:"p50_ms"`
	P99        float64 `json:"p99_ms"`
	Requests   int     `json:"requests"`
	// Memory: the most the edge process held (VmHWM, boot included), which
	// the guard holds to its tolerance, and the heap its last GC kept,
	// which depends on the requests in flight then: information only.
	RSSPeakMiB  float64 `json:"rss_peak_mib"`
	HeapLiveMiB float64 `json:"heap_live_mib"`
}

// TestPerfGuard is how CI keeps the edge from getting slower. Throughput
// on a 2-core runner measures the runner, so this measures work instead:
// at a fixed request rate that runner sustains, what each request costs
// the edge process in CPU and allocations (an edge built with -tags pprof
// serves both), and the most memory the edge held (peak RSS). With
// -base-iso it boots the base commit's build and this
// one back to back, -perf-rounds times, and fails when a request here
// costs more CPU or allocations, or the edge holds more memory, than the
// tolerances allow. CPU is
// the median of each round's ratio of this build to the base, since the
// runner's noise drifts but hits a round's two builds alike; allocations
// and memory are the median of each build's rounds. Those hardly vary
// between machines, so they are also held to testdata/perf-baseline.json,
// which -update-baselines rewrites.
func TestPerfGuard(t *testing.T) {
	if *perfFiles <= 0 {
		t.Skip("make perf-guard runs it")
	}
	p := filepath.Join(*openAppSec, "legitimate.zip")
	require.Equal(t, readSums(t, oasSums)["legitimate.zip"], fileSum(t, p), "%s is not the dataset the baseline was made from", p)
	z, err := zip.OpenReader(p)
	require.NoError(t, err)
	defer z.Close()

	type build struct {
		name, iso string
		costs     []edgeCost
		off       bool
	}
	builds := []*build{{name: "head"}}
	if *perfBase != "" {
		builds = append(builds, &build{name: "base", iso: *perfBase})
	}
	for round := range *perfRounds {
		order := slices.Clone(builds)
		if round%2 == 1 {
			slices.Reverse(order) // neither build always goes first
		}
		for _, b := range order {
			if b.off {
				continue
			}
			t.Run(fmt.Sprintf("%s-%d", b.name, round+1), func(t *testing.T) {
				c, err := measureEdge(t, b.iso, z)
				if errors.Is(err, errNoMetrics) && b.name == "base" {
					t.Logf("the base build has no metrics route; comparing with %s only", perfBaseline)
					b.off = true
					return
				}
				require.NoError(t, err)
				t.Logf("%s: %.0f µs CPU, %.0f allocations, %.1f KiB a request; peak RSS %.1f MiB, live heap %.1f MiB; p50 %.1f ms, p99 %.1f ms",
					b.name, c.CPUMicros, c.Allocs, c.AllocBytes/1024, c.RSSPeakMiB, c.HeapLiveMiB, c.P50, c.P99)
				b.costs = append(b.costs, c)
			})
		}
	}
	require.NotEmpty(t, builds[0].costs, "no measurement of this build")
	head := typical(builds[0].costs)
	report := map[string]any{"run": newRunInfo(), "rate": *perfRate, "files": *perfFiles, "head": head, "head_rounds": builds[0].costs}
	rows := [][]string{costRow("this commit", head)}
	var base *edgeCost
	cpuRatio := 1.0
	if len(builds) > 1 && len(builds[1].costs) > 0 {
		b := typical(builds[1].costs)
		base = &b
		report["base"], report["base_rounds"] = b, builds[1].costs
		cpuRatio = pairedRatio(builds[0].costs, builds[1].costs)
		report["cpu_ratio"] = cpuRatio
		rows = append(rows, costRow("base", b), []string{"change", fmt.Sprintf("%+.1f%%", 100*(cpuRatio-1)),
			pct(head.Allocs, b.Allocs), pct(head.AllocBytes, b.AllocBytes), "", pct(head.RSSPeakMiB, b.RSSPeakMiB),
			pct(head.HeapLiveMiB, b.HeapLiveMiB), "", ""})
	}
	dir := reports(t)
	writeJSON(t, dir, "perf-guard.json", report)
	md := fmt.Sprintf("### Perf guard\n\n%d files of open-appsec's legitimate set at %.0f requests a second, %d rounds, "+
		"what each request costs the edge process (medians; CPU change: median of the rounds' ratios). Fails over +%.0f%% CPU or "+
		"+%.0f%% allocations or +%.0f%% memory against the base.\n\n", *perfFiles, *perfRate, *perfRounds, 100**perfCPUTol,
		100**perfAllocTol, 100**perfMemTol) +
		markdown([]string{"build", "CPU µs", "allocations", "KiB allocated", "GC per 1k", "peak RSS MiB", "live heap MiB",
			"p50 ms", "p99 ms"}, rows)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "perf-guard-summary.md"), []byte(md), 0o644))

	if base != nil {
		assert.LessOrEqual(t, cpuRatio, 1+*perfCPUTol, "CPU a request, this build to the base (median of the rounds)")
		assert.LessOrEqual(t, head.Allocs, base.Allocs*(1+*perfAllocTol), "allocations a request, against the base")
		assert.LessOrEqual(t, head.AllocBytes, base.AllocBytes*(1+*perfAllocTol), "bytes allocated a request, against the base")
		if base.RSSPeakMiB > 0 { // a base from before the memory guard reports none
			assert.LessOrEqual(t, head.RSSPeakMiB, base.RSSPeakMiB*(1+*perfMemTol), "peak RSS, MiB, against the base")
		}
	}
	want := map[string]float64{"files": float64(*perfFiles), "allocs": head.Allocs, "alloc_bytes": head.AllocBytes,
		"rss_peak_mib": head.RSSPeakMiB}
	if *updateBench {
		writeJSON(t, "testdata", perfBaseline, want)
		t.Logf("wrote testdata/%s", perfBaseline)
		return
	}
	var got map[string]float64
	require.NoError(t, json.Unmarshal(lab.Read(t, perfBaseline), &got), "no baseline yet: make perf-guard E2E_ARGS=-update-baselines")
	if got["files"] != float64(*perfFiles) {
		t.Logf("%s is for %v files, not %d: not compared", perfBaseline, got["files"], *perfFiles)
		return
	}
	assert.LessOrEqual(t, head.Allocs, got["allocs"]*(1+*perfAllocTol), "allocations a request, against %s", perfBaseline)
	assert.LessOrEqual(t, head.AllocBytes, got["alloc_bytes"]*(1+*perfAllocTol), "bytes allocated a request, against %s", perfBaseline)
	assert.LessOrEqual(t, head.RSSPeakMiB, got["rss_peak_mib"]*(1+*perfMemTol), "peak RSS, MiB, against %s", perfBaseline)
}

var errNoMetrics = errors.New("no metrics route")

// measureEdge boots iso (empty: the suite's -iso) as the bench does and
// replays the first -perf-files files at -perf-rate, reading the edge's
// counters just before and after.
func measureEdge(t *testing.T, iso string, z *zip.ReadCloser) (edgeCost, error) {
	sz := benchSize()
	sz.iso = iso
	origin := newWireOrigin(t, false)
	e := newEdge(t, sz, oasHost, origin)
	before, err := edgeMetrics(e)
	if err != nil {
		return edgeCost{}, err
	}
	res, sb := replayOAS(t, z, "legitimate", oasDialer(t, e), replayOpts{files: *perfFiles, workers: *benchWorkers, rate: *perfRate})
	after, err := edgeMetrics(e)
	if err != nil {
		return edgeCost{}, err
	}
	for _, r := range res {
		if r.Outcome == "problems" || r.Outcome == "silent" {
			return edgeCost{}, fmt.Errorf("%s %s: %s", r.Outcome, r.Sent, r.Got)
		}
	}
	assert.Zero(t, origin.bad.Load(), "requests reached the site malformed: %s", origin.problems())
	n := float64(sb.Requests)
	return edgeCost{
		CPUMicros:  float64(after["cpu_ns"]-before["cpu_ns"]) / 1e3 / n,
		Allocs:     float64(after["alloc_objects"]-before["alloc_objects"]) / n,
		AllocBytes: float64(after["alloc_bytes"]-before["alloc_bytes"]) / n,
		GCPer1k:    float64(after["gc_cycles"]-before["gc_cycles"]) * 1000 / n,
		P50:        sb.Latency.P50, P99: sb.Latency.P99, Requests: sb.Requests,
		RSSPeakMiB:  float64(after["rss_peak_bytes"]) / (1 << 20),
		HeapLiveMiB: float64(after["heap_live_bytes"]) / (1 << 20),
	}, nil
}

// edgeMetrics reads the bench build's counters (internal/ops/pprof.go).
func edgeMetrics(e *edge) (map[string]uint64, error) {
	resp, body, err := lab.Get(e.ops, lab.OpsURL+"pprof/metrics")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoMetrics
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics: %s", resp.Status)
	}
	var m map[string]uint64
	return m, json.Unmarshal([]byte(body), &m)
}

// pairedRatio is the median, over rounds, of head's CPU a request to
// base's in the same round.
func pairedRatio(head, base []edgeCost) float64 {
	var r []float64
	for i := range min(len(head), len(base)) {
		r = append(r, head[i].CPUMicros/base[i].CPUMicros)
	}
	slices.Sort(r)
	return r[len(r)/2]
}

// typical is the rounds' median cost.
func typical(cs []edgeCost) edgeCost {
	med := func(f func(edgeCost) float64) float64 {
		v := make([]float64, len(cs))
		for i, c := range cs {
			v[i] = f(c)
		}
		slices.Sort(v)
		return v[len(v)/2]
	}
	var out edgeCost
	for _, c := range cs {
		out.Requests += c.Requests
	}
	out.CPUMicros = med(func(c edgeCost) float64 { return c.CPUMicros })
	out.Allocs = med(func(c edgeCost) float64 { return c.Allocs })
	out.AllocBytes = med(func(c edgeCost) float64 { return c.AllocBytes })
	out.GCPer1k = med(func(c edgeCost) float64 { return c.GCPer1k })
	out.P50 = med(func(c edgeCost) float64 { return c.P50 })
	out.P99 = med(func(c edgeCost) float64 { return c.P99 })
	out.RSSPeakMiB = med(func(c edgeCost) float64 { return c.RSSPeakMiB })
	out.HeapLiveMiB = med(func(c edgeCost) float64 { return c.HeapLiveMiB })
	return out
}

func costRow(name string, c edgeCost) []string {
	return []string{name, fmt.Sprintf("%.0f", c.CPUMicros), fmt.Sprintf("%.0f", c.Allocs),
		fmt.Sprintf("%.1f", c.AllocBytes/1024), fmt.Sprintf("%.2f", c.GCPer1k),
		fmt.Sprintf("%.1f", c.RSSPeakMiB), fmt.Sprintf("%.1f", c.HeapLiveMiB), fmt.Sprintf("%.1f", c.P50), fmt.Sprintf("%.1f", c.P99)}
}

func pct(now, was float64) string {
	return fmt.Sprintf("%+.1f%%", 100*(now/was-1))
}
