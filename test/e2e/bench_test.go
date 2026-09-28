//go:build e2e

package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"

	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// The WAF bench: TestOpenAppSec and TestGoTestWAF replay attack and
// legitimate traffic through an edge VM larger than the system tests
// use, and write what they measured to -bench. make waf-bench runs them
// on their own, without -race, so the numbers are the edge's.
var (
	benchDir = flag.String("bench", "", "directory for the WAF bench's reports; "+
		"empty is each test's artifact directory")
	benchCPUs    = flag.Int("vm-cpus", 2, "vCPUs of the WAF bench's edge VM")
	benchMemMiB  = flag.Int("vm-mem", 2048, "memory of the WAF bench's edge VM, in MiB")
	benchWorkers = flag.Int("workers", 32, "connections the open-appsec replay sends over")
	benchCommit  = flag.String("commit", "", "the commit under test, for the reports")
	benchTunnel  = flag.String("tunnel", "wss", "how the bench's dark node reaches the edge: wss or quic")
	updateBench  = flag.Bool("update-baselines", false, "rewrite testdata/*-baseline.json from this run")
)

// benchSize is the bench's edge VM: -vm-cpus and -vm-mem, on the -tap
// device when there is one (make waf-bench runs in os/netns.sh).
func benchSize() edgeSize {
	return edgeSize{cpus: *benchCPUs, memMiB: *benchMemMiB, tap: lab.Tap(), tunnel: *benchTunnel}
}

// benchNet names the VM's network, for the reports: numbers from
// different networks do not compare.
func benchNet() string {
	if !lab.Tap() {
		return "user"
	}
	if unix.Access("/dev/vhost-net", unix.W_OK) == nil {
		return "tap+vhost"
	}
	return "tap"
}

var benchCeiling = flag.Duration("ceiling", 0, "how long TestCeiling measures each protocol; 0 skips it")

// TestCeiling is the lab's reference for TestOpenAppSec: how many requests
// a second the bench's edge VM answers when it proxies nothing. An edge
// built with -tags pprof answers /~!ops/pprof/null itself, so this is TLS
// and net/http on the VM over -workers connections, HTTP/1.1 then HTTP/2.
func TestCeiling(t *testing.T) {
	if *benchCeiling <= 0 {
		t.Skip("make waf-bench WAF_RUN=TestCeiling E2E_ARGS=-ceiling=20s")
	}
	e := newEdge(t, benchSize(), oasHost, newWireOrigin(t, false))
	for _, h2 := range []bool{false, true} {
		tr := e.ops.Transport.(*http.Transport).Clone()
		tr.MaxIdleConnsPerHost, tr.MaxConnsPerHost = *benchWorkers, *benchWorkers
		tr.ForceAttemptHTTP2 = h2
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		c := &http.Client{Transport: tr, Timeout: lab.Attempt}
		var n atomic.Int64
		var proto atomic.Value
		deadline := time.Now().Add(*benchCeiling)
		var wg sync.WaitGroup
		for range *benchWorkers {
			wg.Go(func() {
				for time.Now().Before(deadline) {
					resp, err := c.Get(lab.OpsURL + "pprof/null")
					if err != nil {
						t.Error(err)
						return
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Errorf("status %d: only a bench ISO (-tags pprof) answers", resp.StatusCode)
						return
					}
					proto.Store(resp.Proto)
					n.Add(1)
				}
			})
		}
		wg.Wait()
		t.Logf("%v: %.0f requests a second answered by the edge itself, %d connections",
			proto.Load(), float64(n.Load())/benchCeiling.Seconds(), *benchWorkers)
	}
}

// reports is where t writes its reports.
func reports(t *testing.T) string {
	t.Helper()
	if *benchDir == "" {
		return t.ArtifactDir()
	}
	require.NoError(t, os.MkdirAll(*benchDir, 0o755))
	return *benchDir
}

// writeJSON writes v, indented, to dir/name.
func writeJSON(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644))
}

// baseline compares got with testdata/name, or rewrites that file with
// -update-baselines. A difference fails the test: the edge now treats
// this traffic differently, which a change should mean to do.
func baseline(t *testing.T, name string, got any) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateBench {
		writeJSON(t, "testdata", name, got)
		t.Logf("wrote %s", path)
		return
	}
	b, err := json.Marshal(got)
	require.NoError(t, err)
	var gotAny, want any
	require.NoError(t, json.Unmarshal(b, &gotAny))
	require.NoError(t, json.Unmarshal(lab.Read(t, name), &want), "no %s yet: make waf-bench E2E_ARGS=-update-baselines", path)
	assert.Equal(t, want, gotAny, "outcomes differ from %s; if the change is meant, "+
		"make waf-bench E2E_ARGS=-update-baselines rewrites it", path)
}

// runInfo describes the run, so reports from different workflow runs
// compare like with like.
type runInfo struct {
	Schema   int       `json:"schema"`
	Time     time.Time `json:"time"`
	Commit   string    `json:"commit,omitempty"`
	Go       string    `json:"go"`
	HostCPUs int       `json:"host_cpus"`
	HostCPU  string    `json:"host_cpu"`
	Accel    string    `json:"accel"`
	VMCPUs   int       `json:"vm_cpus"`
	VMMemMiB int       `json:"vm_mem_mib"`
	// Net is the VM's network: user (QEMU's user-mode network), tap, or
	// tap+vhost.
	Net string `json:"net"`
	// Tunnel is the dark node's: wss or quic.
	Tunnel string `json:"tunnel"`
}

func newRunInfo() runInfo {
	model := ""
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for l := range strings.Lines(string(b)) {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
				model = strings.TrimSpace(v)
				break
			}
		}
	}
	return runInfo{Schema: 1, Time: time.Now().UTC(), Commit: *benchCommit, Go: runtime.Version(),
		HostCPUs: runtime.NumCPU(), HostCPU: model, Accel: lab.Accel(), VMCPUs: *benchCPUs, VMMemMiB: *benchMemMiB,
		Net: benchNet(), Tunnel: *benchTunnel}
}

// edgeStatus is the edge's /~!ops/status, as JSON.
func edgeStatus(t *testing.T, e *edge) json.RawMessage {
	t.Helper()
	resp, body, err := lab.Get(e.ops, lab.OpsURL+"status")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	return json.RawMessage(body)
}

// profileEdge waits wait, then takes a 2-second execution trace of the
// edge, a CPU profile for d, and a heap profile, into dir as edge.trace,
// edge-cpu.pprof and edge-heap.pprof.
// Only an edge built with -tags pprof (make bench-iso) serves them; for
// another it logs why there are none. The channel closes when it is done.
//
//	go tool pprof -top out/waf-bench/edge-cpu.pprof
func profileEdge(t *testing.T, e *edge, dir string, wait, d time.Duration) <-chan struct{} {
	done := make(chan struct{})
	c := &http.Client{Transport: e.ops.Transport, Timeout: d + lab.Attempt}
	save := func(path, name string) {
		resp, err := c.Get(lab.OpsURL + path)
		if err != nil {
			t.Logf("%s: %v", name, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Logf("%s: %s; only a bench ISO (-tags pprof) has profiles", name, resp.Status)
			return
		}
		var b bytes.Buffer
		if _, err := io.Copy(&b, resp.Body); err == nil {
			err = os.WriteFile(filepath.Join(dir, name), b.Bytes(), 0o644)
		}
		if err != nil {
			t.Logf("%s: %v", name, err)
		}
	}
	go func() {
		defer close(done)
		select {
		case <-time.After(wait):
		case <-t.Context().Done():
			return
		}
		// Where requests wait rather than run: go tool trace -pprof=sched.
		save("pprof/trace?seconds=2", "edge.trace")
		save(fmt.Sprintf("pprof/profile?seconds=%d", int(d.Seconds())), "edge-cpu.pprof")
		save("pprof/heap", "edge-heap.pprof")
	}()
	return done
}

// latency summarizes request durations in milliseconds.
type latency struct {
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P99  float64 `json:"p99"`
	P999 float64 `json:"p999"`
	Max  float64 `json:"max"`
}

func summarize(ms []float64) latency {
	if len(ms) == 0 {
		return latency{}
	}
	slices.Sort(ms)
	at := func(q float64) float64 { return ms[min(len(ms)-1, int(q*float64(len(ms))))] }
	return latency{P50: at(0.50), P90: at(0.90), P99: at(0.99), P999: at(0.999), Max: ms[len(ms)-1]}
}

// connectProxy is an HTTP CONNECT proxy that sends every tunnel to addr,
// whatever host it names. A tool that resolves names itself reaches the
// edge through it with a site's name, as TLS server name and Host.
func connectProxy(t *testing.T, addr string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var open []net.Conn
	keep := func(c ...net.Conn) {
		mu.Lock()
		open = append(open, c...)
		mu.Unlock()
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.DialTimeout("tcp", addr, lab.Attempt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		down, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			up.Close()
			return
		}
		keep(up, down)
		if n := brw.Reader.Buffered(); n > 0 {
			b, _ := brw.Reader.Peek(n)
			up.Write(b)
		}
		go func() { io.Copy(up, down); up.Close() }()
		io.Copy(down, up)
		down.Close()
	})}
	go srv.Serve(l)
	t.Cleanup(func() {
		srv.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			c.Close()
		}
	})
	return "http://" + l.Addr().String()
}

// markdown renders rows as a GitHub table, for the workflow's summary.
func markdown(head []string, rows [][]string) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "| %s |\n|%s\n", strings.Join(head, " | "), strings.Repeat(" --- |", len(head)))
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s |\n", strings.Join(r, " | "))
	}
	return b.String()
}
