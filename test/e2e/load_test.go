//go:build e2e

package e2e

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptrace"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

var loadFor = flag.Duration("load", 0, "how long each TestLoad run lasts; 0 skips it (make load sets it)")

// TestLoad measures what one edge VM (1 vCPU, as lab.BootEdge makes it)
// serves through each tunnel: small requests per second with their
// latency, and download throughput. The limits are off, so this is the
// edge's capacity, not its limits. The load comes from this host through
// QEMU's user-mode network, which costs something too: a real NIC does
// better. It reports numbers and fails only when nothing gets through.
func TestLoad(t *testing.T) {
	if *loadFor <= 0 {
		t.Skip("make load runs it")
	}
	e := lab.BootEdge(t, lab.EdgeOptions{
		Policy: "limits:\n  requests_per_second: 0\n  connections_per_source: 0\n  new_connections_per_second: 0\n"})
	vm, web, ops, caFile := e.VM, e.Web, e.Ops, e.Roots
	lab.Ctl(t, "ca", "client", e.PKI, ca.ID(lab.Tunnel, ca.RoleNode, "node2"))
	node1Crt, node1Key := e.Cert(ca.RoleNode, "node1")
	node2Crt, node2Key := e.Cert(ca.RoleNode, "node2")

	blob := make([]byte, 1<<20)
	rand.Read(blob)
	small := lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	large := lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(blob) }))
	for _, n := range []struct{ proto, crt, key string }{{"wss", node1Crt, node1Key}, {"quic", node2Crt, node2Key}} {
		vm.Publish(t, n.proto, caFile, n.crt, n.key, small, "small-"+n.proto+".example.com")
		vm.Publish(t, n.proto, caFile, n.crt, n.key, large, "blob-"+n.proto+".example.com")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			for _, site := range []string{"small-", "blob-"} {
				resp, _, err := lab.Get(web, "https://"+site+n.proto+".example.com/")
				require.NoError(c, err)
				assert.Equal(c, http.StatusOK, resp.StatusCode)
			}
		}, lab.Until(t), lab.Tick)
	}

	before, hostBefore := kernelTCP(t, ops), hostListenOverflows()
	t.Logf("each run lasts %s", *loadFor)
	t.Logf("%-6s %-9s %5s %10s %8s %8s %10s  %s", "tunnel", "http", "conc", "req/s", "p50", "p99", "MB/s", "errors")
	for _, tunnel := range []string{"wss", "quic"} {
		for _, run := range []struct {
			http string
			conc int
			blob bool
		}{
			{"h2", 10, false}, {"h2", 50, false}, {"http/1.1", 10, false}, {"http/1.1", 50, false}, {"h2", 10, true},
		} {
			site := "small-" + tunnel
			if run.blob {
				site = "blob-" + tunnel
			}
			r := load(web, run.http, run.conc, "https://"+site+".example.com/", *loadFor)
			assert.Positive(t, r.ok, "%s %s: nothing got through: %v", tunnel, run.http, r.errors)
			t.Logf("%-6s %-9s %5d %10.0f %8s %8s %10.1f  %s", tunnel, run.http, run.conc, r.perSecond(), r.p(0.5), r.p(0.99),
				float64(r.bytes)/(1<<20)/loadFor.Seconds(), r.errorSummary())
		}
	}
	edgeSide(t, ops)
	after := kernelTCP(t, ops)
	var moved []string
	for _, k := range slices.Sorted(maps.Keys(after)) {
		moved = append(moved, fmt.Sprintf("%s=%.0f", k, after[k]-before[k]))
	}
	t.Logf("edge kernel TCP during the runs: %s", strings.Join(moved, " "))
	// QEMU forwards the lab's ports from a listening socket on this host.
	// When many connections open at once its accept queue overflows, and
	// those connections are reset before they reach the edge.
	t.Logf("host accept queue overflows during the runs (QEMU's forwarding, not the edge): %d",
		hostListenOverflows()-hostBefore)
}

// hostListenOverflows is this host's TcpExt ListenOverflows.
func hostListenOverflows() int64 {
	b, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i++ {
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(names) == 0 || names[0] != "TcpExt:" || len(names) != len(values) {
			continue
		}
		if j := slices.Index(names, "ListenOverflows"); j > 0 {
			n, _ := strconv.ParseInt(values[j], 10, 64)
			return n
		}
	}
	return 0
}

func kernelTCP(t *testing.T, ops *http.Client) map[string]float64 {
	_, body, err := lab.Get(ops, lab.OpsURL+"status")
	require.NoError(t, err)
	var st struct {
		Kernel map[string]float64 `json:"kernel_tcp"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &st))
	return st.Kernel
}

// edgeSide logs what the edge saw: drop counters that moved, and its own
// warnings and errors, grouped. A client error with nothing here happened
// between the two (QEMU's network, the host).
func edgeSide(t *testing.T, ops *http.Client) {
	_, body, err := lab.Get(ops, lab.OpsURL+"status")
	require.NoError(t, err)
	var st map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &st))
	var moved []string
	for _, k := range slices.Sorted(maps.Keys(st)) {
		if n, ok := st[k].(float64); ok && n > 0 && (strings.Contains(k, "drop") || strings.Contains(k, "limited") ||
			strings.Contains(k, "bad_gateway") || strings.Contains(k, "rejected") || k == "bans") {
			moved = append(moved, fmt.Sprintf("%s=%.0f", k, n))
		}
	}
	t.Logf("edge counters: %s", strings.Join(append(moved, "(others 0)"), " "))

	_, body, err = lab.Get(ops, lab.OpsURL+"logs")
	require.NoError(t, err)
	seen := map[string]int{}
	for line := range strings.Lines(body) {
		if !strings.Contains(line, "level=WARN") && !strings.Contains(line, "level=ERROR") {
			continue
		}
		msg := line
		if i := strings.Index(line, "msg="); i >= 0 {
			msg = line[i:]
		}
		if len(msg) > 120 {
			msg = msg[:120]
		}
		seen[strings.TrimSpace(msg)]++
	}
	if len(seen) == 0 {
		t.Logf("edge log: no warnings or errors")
	}
	for _, msg := range slices.Sorted(maps.Keys(seen)) {
		t.Logf("edge log: %dx %s", seen[msg], msg)
	}
}

type loadResult struct {
	ok, bytes int64
	latency   []time.Duration
	errors    map[string]int
	took      time.Duration
}

func (r loadResult) perSecond() float64 { return float64(r.ok) / r.took.Seconds() }

func (r loadResult) p(q float64) time.Duration {
	if len(r.latency) == 0 {
		return 0
	}
	return r.latency[int(float64(len(r.latency)-1)*q)].Round(time.Millisecond)
}

func (r loadResult) errorSummary() string {
	if len(r.errors) == 0 {
		return "-"
	}
	var parts []string
	for _, msg := range slices.Sorted(maps.Keys(r.errors)) {
		parts = append(parts, fmt.Sprintf("%dx %s", r.errors[msg], msg))
	}
	return strings.Join(parts, "; ")
}

// load sends GETs to url from conc workers for d over one client, and
// counts what came back whole.
func load(base *http.Client, proto string, conc int, url string, d time.Duration) loadResult {
	tr := base.Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = proto == "h2"
	if proto != "h2" {
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		tr.MaxConnsPerHost = conc
		tr.MaxIdleConnsPerHost = conc
	}
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	defer tr.CloseIdleConnections()

	var ok, bytes atomic.Int64
	var mu sync.Mutex
	r := loadResult{errors: map[string]int{}}
	fail := func(msg string) {
		mu.Lock()
		r.errors[msg]++
		mu.Unlock()
	}
	start := time.Now()
	end := start.Add(d)
	var wg sync.WaitGroup
	for range conc {
		wg.Go(func() {
			var mine []time.Duration
			for time.Now().Before(end) {
				s := time.Now()
				// Where a failure happened: on a new or a reused connection,
				// before or after its TLS handshake.
				var reused, handshake bool
				req, _ := http.NewRequest(http.MethodGet, url, nil)
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
					GotConn:          func(i httptrace.GotConnInfo) { reused = i.Reused },
					TLSHandshakeDone: func(_ tls.ConnectionState, err error) { handshake = err == nil },
				}))
				resp, err := c.Do(req)
				if err != nil {
					where := "new conn, in handshake"
					switch {
					case reused:
						where = "reused conn"
					case handshake:
						where = "new conn, after handshake"
					}
					when := "later"
					if s.Sub(start) < time.Second {
						when = "first second"
					}
					fail(where + ", " + when + ": " + shortErr(err))
					continue
				}
				n, err := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				switch {
				case err != nil:
					fail("body: " + shortErr(err))
				case resp.StatusCode != http.StatusOK:
					fail(resp.Status)
				default:
					ok.Add(1)
					bytes.Add(n)
					mine = append(mine, time.Since(s))
				}
			}
			mu.Lock()
			r.latency = append(r.latency, mine...)
			mu.Unlock()
		})
	}
	wg.Wait()
	r.took = time.Since(start)
	r.ok, r.bytes = ok.Load(), bytes.Load()
	slices.Sort(r.latency)
	return r
}

// shortErr drops the URL and addresses, so the same failure groups.
func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}
