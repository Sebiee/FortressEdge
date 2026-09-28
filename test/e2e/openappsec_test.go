//go:build e2e

package e2e

import (
	"archive/zip"
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

var (
	openAppSec = flag.String("openappsec", "", "directory holding the open-appsec WAF comparison datasets, "+
		"legitimate.zip and malicious.zip; empty skips TestOpenAppSec (make waf-bench sets it)")
	oasFiles = flag.Int("oas-files", 0, "replay only the first this many files of each set, for a "+
		"quick measurement (about 1,500 requests a file); the outcomes are then not held to the "+
		"baseline. 0 is all")
)

const (
	oasHost = "oas.example.com"
	oasSums = "testdata/openappsec.sha256"
)

// TestOpenAppSec replays open-appsec's WAF comparison datasets through an
// edge to a wireOrigin: 1,040,242 legitimate requests recorded from 185
// real websites, and 73,924 attacks in seven categories (command
// execution, Log4Shell, Shellshock, SQL injection, path traversal, XSS,
// XXE). What reaches the site must be clean, and what became of each
// class is pinned in testdata/openappsec-baseline.json: the edge has no
// WAF yet, so it passes attacks on, and a WAF will move those numbers
// while leaving the legitimate ones be. It also measures the edge:
// requests per second, bytes, and latency for each set, in
// openappsec-bench.json.
func TestOpenAppSec(t *testing.T) {
	if *openAppSec == "" {
		t.Skip("make waf-bench runs it")
	}
	sets := []string{"legitimate", "malicious"}
	sums := readSums(t, oasSums)
	zips := map[string]*zip.ReadCloser{}
	for _, set := range sets {
		p := filepath.Join(*openAppSec, set+".zip")
		require.Equal(t, sums[set+".zip"], fileSum(t, p), "%s is not the file the baseline was made from", p)
		z, err := zip.OpenReader(p)
		require.NoError(t, err)
		t.Cleanup(func() { z.Close() })
		zips[set] = z
	}

	origin := newWireOrigin(t, false)
	e := newEdge(t, benchSize(), oasHost, origin)
	dial := oasDialer(t, e)

	dir := reports(t)
	outcomes := map[string]map[string]int{}
	var odd []oasResult // what was not forwarded as sent
	bench := struct {
		runInfo
		Workers int                       `json:"workers"`
		Sets    map[string]oasSetBench    `json:"sets"`
		Edge    json.RawMessage           `json:"edge_status"`
		Origin  map[string]int64          `json:"origin"`
		Classes map[string]map[string]int `json:"outcomes"`
	}{runInfo: newRunInfo(), Workers: *benchWorkers, Sets: map[string]oasSetBench{}}
	// Profiles of the legitimate set in full swing, even with -oas-files.
	profiled := profileEdge(t, e, dir, 10*time.Second, 20*time.Second)
	for _, set := range sets {
		res, sb := replayOAS(t, zips[set], set, dial, replayOpts{files: *oasFiles, workers: *benchWorkers})
		bench.Sets[set] = sb
		t.Logf("%-10s %d requests in %.1fs: %.0f/s, %.1f MiB/s sent, latency ms p50 %.1f p99 %.1f max %.0f, %d not answered",
			set, sb.Requests, sb.Seconds, sb.RPS, sb.SentMiBps, sb.Latency.P50, sb.Latency.P99, sb.Latency.Max, sb.Silent)
		for _, r := range res {
			if outcomes[r.Class] == nil {
				outcomes[r.Class] = map[string]int{}
			}
			outcomes[r.Class][r.Outcome]++
			if r.Outcome != "forwarded" {
				odd = append(odd, r)
			}
		}
	}
	<-profiled
	bench.Edge = edgeStatus(t, e)
	bench.Origin = map[string]int64{"requests": origin.seq.Load(), "bad": origin.bad.Load(), "partial": origin.partial.Load()}
	bench.Classes = outcomes
	writeJSON(t, dir, "openappsec-bench.json", bench)
	writeOdd(t, filepath.Join(dir, "openappsec-outcomes.jsonl"), odd)
	writeOASSummary(t, filepath.Join(dir, "openappsec-summary.md"), bench.runInfo, bench.Workers, bench.Sets, outcomes)
	for _, class := range slices.Sorted(maps.Keys(outcomes)) {
		t.Logf("%-22s %s", class, summary(outcomes[class]))
	}

	assert.Zero(t, origin.bad.Load(), "requests reached the site malformed: %s", origin.problems())
	for class, o := range outcomes {
		assert.Zero(t, o["problems"], "%s: requests reached the site malformed; see openappsec-outcomes.jsonl", class)
	}
	if *oasFiles > 0 {
		t.Logf("-oas-files=%d: outcomes not held to the baseline", *oasFiles)
		return
	}
	baseline(t, "openappsec-baseline.json", outcomes)
}

// oasRecord is one request of the datasets, as the open-appsec tool
// sends it: method, origin-form URL, headers, and body.
type oasRecord struct {
	Method  string         `json:"method"`
	URL     string         `json:"url"`
	Headers map[string]any `json:"headers"`
	Data    string         `json:"data"`
}

// oasJob is a record made into an HTTP/1.1 request for the site: its
// Host, a Content-Length counted again, and none of the connection's own
// headers (Connection, Transfer-Encoding and the like, and HTTP/2's
// pseudo-headers), since the replay keeps its connections.
type oasJob struct {
	class, file    string
	n              int
	method, target string
	bodySum        string
	raw            []byte
}

// oasResult is what became of one request. Outcome is "forwarded" (the
// site got it as sent), "altered" (the site got another method, target
// or body), "refused <status>" (the edge answered, not the site),
// "silent" (no response), or "problems" (the site got a request the
// strict grammar objects to).
type oasResult struct {
	Class   string `json:"class"`
	File    string `json:"file"`
	N       int    `json:"n"`
	Outcome string `json:"outcome"`
	Status  int    `json:"status,omitempty"`
	Sent    string `json:"sent,omitempty"`
	Got     string `json:"got,omitempty"`
}

// oasSetBench is what one set measured.
type oasSetBench struct {
	Requests   int     `json:"requests"`
	Seconds    float64 `json:"seconds"`
	RPS        float64 `json:"requests_per_second"`
	SentBytes  int64   `json:"sent_bytes"`
	RecvBytes  int64   `json:"received_bytes"`
	SentMiBps  float64 `json:"sent_mib_per_second"`
	Latency    latency `json:"latency_ms"`
	Silent     int     `json:"not_answered"`
	Reconnects int     `json:"reconnects"`
	// Retries are requests sent again after a new connection was reset
	// before any answer, which QEMU's user-mode network does to a burst.
	Retries int `json:"retries"`
	// HostCPUs is how many of the host's CPUs this test process (the load
	// generator, the dark node and the site) kept busy on average. Near
	// runInfo.HostCPUs, the host was the limit, not the edge.
	HostCPUs float64 `json:"host_cpus_busy"`
}

// hopHeaders are the headers of the connection a record was captured
// on, which the replay's own connection replaces.
var hopHeaders = map[string]bool{
	"host": true, "content-length": true, "connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
}

func buildOAS(r oasRecord, class, file string, n int) oasJob {
	var w bytes.Buffer
	fmt.Fprintf(&w, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, r.URL, oasHost)
	for _, k := range slices.Sorted(maps.Keys(r.Headers)) {
		if strings.HasPrefix(k, ":") || hopHeaders[strings.ToLower(k)] {
			continue
		}
		v, ok := r.Headers[k].(string)
		if !ok {
			v = fmt.Sprint(r.Headers[k])
		}
		fmt.Fprintf(&w, "%s: %s\r\n", k, v)
	}
	body := []byte(r.Data)
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		if len(body) > 0 {
			fmt.Fprintf(&w, "Content-Length: %d\r\n", len(body))
		}
	default:
		fmt.Fprintf(&w, "Content-Length: %d\r\n", len(body))
	}
	w.WriteString("\r\n")
	w.Write(body)
	sum := sha256.Sum256(body)
	return oasJob{class: class, file: file, n: n, method: r.Method, target: r.URL,
		bodySum: hex.EncodeToString(sum[:]), raw: w.Bytes()}
}

// streamOAS decodes one dataset file, a JSON array of records, a record
// at a time: the largest file is 700 MB.
func streamOAS(f *zip.File, fn func(n int, r oasRecord)) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(rc, 1<<20))
	if _, err := dec.Token(); err != nil {
		return err
	}
	for n := 0; dec.More(); n++ {
		var r oasRecord
		if err := dec.Decode(&r); err != nil {
			return fmt.Errorf("record %d: %w", n, err)
		}
		fn(n, r)
	}
	return nil
}

// oasDialer dials the replay's site on e: TLS, HTTP/1.1.
func oasDialer(t *testing.T, e *edge) func() (net.Conn, error) {
	t.Helper()
	pool, err := ca.LoadPool(e.caFile)
	require.NoError(t, err)
	return func() (net.Conn, error) {
		return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: lab.Attempt},
			Config: &tls.Config{ServerName: oasHost, RootCAs: pool, NextProtos: []string{"http/1.1"}}}).
			DialContext(t.Context(), "tcp", net.JoinHostPort(e.vm.Addr, strconv.Itoa(e.vm.HTTPS)))
	}
}

// replayOpts is how replayOAS replays a set.
type replayOpts struct {
	files   int     // the first this many files, the same each run; 0 is all
	workers int     // connections, each kept open while the edge keeps it
	rate    float64 // requests a second at most, all connections together; 0 is as fast as it goes
}

// replayOAS sends the records of z as o says and returns each request's
// outcome and what the set measured.
func replayOAS(t *testing.T, z *zip.ReadCloser, set string, dial func() (net.Conn, error), o replayOpts) ([]oasResult, oasSetBench) {
	t.Helper()
	var files []*zip.File
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, ".json") {
			files = append(files, f)
		}
	}
	require.NotEmpty(t, files)
	// The same files each run, whole, so runs compare: requests differ a
	// lot in size from one site to the next.
	if o.files > 0 && o.files < len(files) {
		files = files[:o.files]
	}
	jobs := make(chan oasJob, 4*o.workers)
	var decodeErr error
	var once sync.Once
	go func() {
		defer close(jobs)
		// Decoding is most of the host's work; one file per decoder.
		next := make(chan *zip.File)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				for f := range next {
					class := set
					if set == "malicious" {
						class = "malicious/" + strings.TrimSuffix(path.Base(f.Name), ".json")
					}
					err := streamOAS(f, func(n int, r oasRecord) {
						jobs <- buildOAS(r, class, path.Base(f.Name), n)
					})
					if err != nil {
						once.Do(func() { decodeErr = fmt.Errorf("%s: %w", f.Name, err) })
					}
				}
			})
		}
		for _, f := range files {
			next <- f
		}
		close(next)
		wg.Wait()
	}()

	type worker struct {
		res        []oasResult
		ms         []float64
		sent, recv int64
		silent     int
		reconnects int
		retries    int
	}
	ws := make([]*worker, o.workers)
	var pace *rate.Limiter
	if o.rate > 0 {
		pace = rate.NewLimiter(rate.Limit(o.rate), 1)
	}
	var wg sync.WaitGroup
	start := time.Now()
	cpuStart := processCPU()
	var done atomic.Int64
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				n := done.Load()
				t.Logf("%s: %d requests in %s, %.0f/s", set, n, time.Since(start).Round(time.Second),
					float64(n)/time.Since(start).Seconds())
			}
		}
	}()
	for i := range ws {
		w := &worker{}
		ws[i] = w
		wg.Go(func() {
			var c net.Conn
			var br *bufio.Reader
			fresh := false // c has carried no request yet
			defer func() {
				if c != nil {
					c.Close()
				}
			}()
			for j := range jobs {
				if pace != nil && pace.Wait(t.Context()) != nil {
					return
				}
				if c == nil {
					var err error
					if c, err = dial(); err != nil {
						w.res = append(w.res, oasResult{Class: j.class, File: j.file, N: j.n, Outcome: "silent", Got: err.Error()})
						w.silent++
						continue
					}
					br = bufio.NewReaderSize(&countReader{r: c, n: &w.recv}, 64<<10)
					w.reconnects++
					fresh = true
				}
				wasFresh := fresh
				fresh = false
				began := time.Now()
				r, keep := sendOAS(c, br, j)
				if r.Outcome == "silent" && wasFresh {
					// A new connection reset before any answer: QEMU's
					// user-mode network does that to a burst of them.
					// Once more on another; the edge refusing it stays silent.
					if rc, err := dial(); err == nil {
						w.retries++
						began = time.Now()
						r, _ = sendOAS(rc, bufio.NewReader(&countReader{r: rc, n: &w.recv}), j)
						rc.Close()
					}
					keep = false
				}
				w.ms = append(w.ms, float64(time.Since(began).Microseconds())/1000)
				w.sent += int64(len(j.raw))
				if r.Outcome == "silent" {
					w.silent++
				}
				w.res = append(w.res, r)
				done.Add(1)
				if !keep {
					c.Close()
					c = nil
				}
			}
		})
	}
	wg.Wait()
	took := time.Since(start)
	hostCPUs := (processCPU() - cpuStart).Seconds() / took.Seconds()
	require.NoError(t, decodeErr)

	var res []oasResult
	var ms []float64
	sb := oasSetBench{Seconds: took.Seconds()}
	for _, w := range ws {
		res = append(res, w.res...)
		ms = append(ms, w.ms...)
		sb.SentBytes += w.sent
		sb.RecvBytes += w.recv
		sb.Silent += w.silent
		sb.Reconnects += w.reconnects
		sb.Retries += w.retries
	}
	sb.Requests = len(res)
	sb.RPS = float64(sb.Requests) / took.Seconds()
	sb.SentMiBps = float64(sb.SentBytes) / (1 << 20) / took.Seconds()
	sb.HostCPUs = hostCPUs
	sb.Latency = summarize(ms)
	slices.SortFunc(res, func(a, b oasResult) int {
		return cmp.Or(strings.Compare(a.File, b.File), a.N-b.N)
	})
	return res, sb
}

// sendOAS sends j on c and reads the response. keep is false when c
// cannot carry another request.
func sendOAS(c net.Conn, br *bufio.Reader, j oasJob) (res oasResult, keep bool) {
	res = oasResult{Class: j.class, File: j.file, N: j.n, Sent: j.method + " " + clipString(j.target)}
	c.SetDeadline(time.Now().Add(lab.Attempt))
	if _, err := c.Write(j.raw); err != nil {
		res.Outcome, res.Got = "silent", err.Error()
		return res, false
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: j.method})
	if err != nil {
		res.Outcome, res.Got = "silent", err.Error()
		return res, false
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	keep = err == nil && !resp.Close
	res.Status = resp.StatusCode
	if h := resp.Header.Get(replyHeader); h != "" && len(body) == 0 {
		body, _ = base64.StdEncoding.DecodeString(h) // HEAD
	}
	var rep reply
	if json.Unmarshal(body, &rep) != nil || rep.Seq == 0 {
		// The edge answered, not the site.
		res.Outcome = "refused " + strconv.Itoa(resp.StatusCode)
		return res, keep
	}
	switch {
	case len(rep.Problems) > 0:
		res.Outcome, res.Got = "problems", strings.Join(rep.Problems, "; ")
	case rep.Method == j.method && rep.URI == j.target && rep.BodySHA == j.bodySum:
		res.Outcome, res.Sent = "forwarded", ""
	default:
		res.Outcome, res.Got = "altered", rep.Method+" "+clipString(rep.URI)
		if rep.BodySHA != j.bodySum {
			res.Got += " (body changed)"
		}
	}
	return res, keep
}

// processCPU is the CPU time this process has used, user and system.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// countReader counts the bytes read through it into *n.
type countReader struct {
	r io.Reader
	n *int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	return n, err
}

func clipString(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// writeOdd writes rs as JSON lines to path.
func writeOdd(t *testing.T, path string, rs []oasResult) {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, r := range rs {
		enc.Encode(r)
	}
	require.NoError(t, os.WriteFile(path, b.Bytes(), 0o644))
}

func writeOASSummary(t *testing.T, path string, ri runInfo, workers int, sets map[string]oasSetBench, outcomes map[string]map[string]int) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "### open-appsec replay\n\nEdge VM: %d vCPU, %d MiB (%s, %s network). Host: %d CPUs, %s. %d connections. Commit %s.\n\n",
		ri.VMCPUs, ri.VMMemMiB, ri.Accel, ri.Net, ri.HostCPUs, ri.HostCPU, workers, cmp.Or(ri.Commit, "unknown"))
	var rows [][]string
	for _, set := range slices.Sorted(maps.Keys(sets)) {
		s := sets[set]
		rows = append(rows, []string{set, strconv.Itoa(s.Requests), fmt.Sprintf("%.1f", s.Seconds), fmt.Sprintf("%.0f", s.RPS),
			fmt.Sprintf("%.1f", s.SentMiBps), fmt.Sprintf("%.1f", s.Latency.P50), fmt.Sprintf("%.1f", s.Latency.P99),
			fmt.Sprintf("%.0f", s.Latency.Max), strconv.Itoa(s.Silent), strconv.Itoa(s.Retries), fmt.Sprintf("%.1f of %d", s.HostCPUs, ri.HostCPUs)})
	}
	b.WriteString(markdown([]string{"set", "requests", "seconds", "req/s", "MiB/s sent", "p50 ms", "p99 ms", "max ms", "not answered", "retried", "host CPUs busy"}, rows))
	b.WriteString("\n")
	rows = nil
	for _, class := range slices.Sorted(maps.Keys(outcomes)) {
		rows = append(rows, []string{class, summary(outcomes[class])})
	}
	b.WriteString(markdown([]string{"class", "outcomes"}, rows))
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o644))
}

// readSums reads a sha256sum file from testdata: file name to hash.
func readSums(t *testing.T, name string) map[string]string {
	t.Helper()
	sums := map[string]string{}
	for l := range strings.Lines(string(lab.Read(t, filepath.Base(name)))) {
		if sum, file, ok := strings.Cut(strings.TrimSpace(l), "  "); ok {
			sums[file] = sum
		}
	}
	return sums
}

// fileSum is the SHA-256 of the file at p.
func fileSum(t *testing.T, p string) string {
	t.Helper()
	f, err := os.Open(p)
	require.NoError(t, err, "make waf-bench fetches the datasets")
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// summary is outcomes as "total N: forwarded N, ...", most common first.
func summary(outcomes map[string]int) string {
	keys := slices.Collect(maps.Keys(outcomes))
	slices.SortFunc(keys, func(a, b string) int {
		return cmp.Or(outcomes[b]-outcomes[a], strings.Compare(a, b))
	})
	total := 0
	parts := make([]string, len(keys))
	for i, k := range keys {
		total += outcomes[k]
		parts[i] = fmt.Sprintf("%s %d", k, outcomes[k])
	}
	return fmt.Sprintf("total %d: %s", total, strings.Join(parts, ", "))
}
