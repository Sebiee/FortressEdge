// Package ops serves the operator API on the tunnel SNI: this boot's logs
// with resume cursors, a status summary, and the policy. The TLS layer
// has already verified the client certificate against the client CA; here
// its SPIFFE role decides what it may do. Operators (ops/<name>) may do
// everything; log readers (logs/<name>) may read logs, status, and the
// policy; dark nodes (node/<name>) may do nothing.
package ops

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/logx"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// bootPrefix starts the first line logx writes into every log file: the
// file's id, which scopes cursors to that file. The edge's log uses the
// boot id; the access log adds a sequence number when it rotates.
const bootPrefix = "# boot "

// A cursor is a resume token: "<file-id>:<byte-offset>". Byte offsets make
// refetches idempotent; the file id makes rotation detectable, so a
// shipper can drain previous.log before moving on to current.log.
type cursor struct {
	boot string
	off  int64
}

func (c cursor) String() string { return c.boot + ":" + strconv.FormatInt(c.off, 10) }

func parseCursor(s string) (cursor, error) {
	boot, off, ok := strings.Cut(s, ":")
	if !ok {
		return cursor{}, fmt.Errorf("cursor: want <boot-id>:<offset>")
	}
	n, err := strconv.ParseInt(off, 10, 64)
	if err != nil || n < 0 {
		return cursor{}, fmt.Errorf("cursor: bad offset")
	}
	return cursor{boot, n}, nil
}

// A Step puts one part of a policy in force, such as XDP's block list or
// the visitor limits. It changes nothing when it fails, and running it
// with the policy that was in force undoes it.
type Step func(config.Policy) error

// Apply is how a PUT puts a policy in force and keeps it.
type Apply struct {
	Steps []Step
	// Store keeps the body on the data disk, once every step succeeded.
	Store func(policy []byte) error
	// Reboot runs after the response is flushed, for a policy that changes
	// a limit the servers fix when they start.
	Reboot func()
}

// maxPolicy bounds a policy.yml body: a block list of some ten thousand
// prefixes.
const maxPolicy = 1 << 20

type Handler struct {
	mu     sync.RWMutex
	cfg    config.Config // its policy is the one in force
	policy []byte        // policy.yml as stored; nil before the first apply
	bootID string
	dir    string
	extra  func() map[string]any
	// boot is the policy the edge started with, whose boot limits the
	// servers keep until they restart.
	boot config.Policy
	// degraded says why part of the stored policy is not in force; empty
	// when all of it is.
	degraded []string
	// metrics writes the edge's metrics; the ops API adds its own.
	metrics func(*metrics.Writer)
	apply   Apply
	// applyMu keeps a PUT's compare, apply, and swap of policy together.
	applyMu sync.Mutex
}

// New serves cfg's logs and status. policy is the policy.yml cfg was
// parsed with, as stored.
func New(cfg config.Config, policy []byte, bootID, dir string) *Handler {
	return &Handler{cfg: cfg, policy: policy, boot: cfg.Policy, bootID: bootID, dir: dir}
}

func (h *Handler) SetStatus(fn func() map[string]any) { h.extra = fn }

// SetMetrics registers what /~!ops/metrics writes after the build and
// boot time.
func (h *Handler) SetMetrics(fn func(*metrics.Writer)) { h.metrics = fn }

// SetApply registers the policy PUT.
func (h *Handler) SetApply(a Apply) { h.apply = a }

// SetDegraded records what boot could not put in force of the stored
// policy, and why. A policy put through the API is in force whole, and
// clears it.
func (h *Handler) SetDegraded(reasons []string) {
	h.mu.Lock()
	h.degraded = slices.Clone(reasons)
	h.mu.Unlock()
}

// degradedNow is SetDegraded's reasons, and those a failed put added.
func (h *Handler) degradedNow() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]string{}, h.degraded...)
}

func (h *Handler) config() config.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// route is one endpoint: the roles that may call it, and whether it is a
// read the location's collector answers for all its edges (policy.yml's
// collector) unless the caller asks for this edge itself (?self).
type route struct {
	roles    []ca.Role
	serve    func(h *Handler, w http.ResponseWriter, r *http.Request)
	location bool
}

var (
	readers   = []ca.Role{ca.RoleOps, ca.RoleLogs}
	operators = []ca.Role{ca.RoleOps}
)

// routes is keyed by method and path, as "GET /~!ops/status".
var routes = map[string]route{
	"GET " + config.OpsStatusPath:  {readers, (*Handler).status, true},
	"GET " + config.OpsMetricsPath: {readers, (*Handler).serveMetrics, true},
	"GET " + config.OpsLogsPath:    {readers, (*Handler).logs, true},
	"GET " + config.OpsAccessPath:  {readers, (*Handler).access, true},
	"GET " + config.OpsPolicyPath:  {readers, (*Handler).getPolicy, false},
	"PUT " + config.OpsPolicyPath:  {operators, (*Handler).putPolicy, false},
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	role, id := h.caller(r)
	rt, ok := routes[r.Method+" "+r.URL.Path]
	if role != ca.RoleOps && role != ca.RoleLogs || ok && !slices.Contains(rt.roles, role) {
		slog.Warn("ops: forbidden", "id", id, "method", r.Method, "path", r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !ok {
		allow := methods(r.URL.Path)
		if len(allow) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		http.Error(w, strings.Join(allow, " or ")+" only", http.StatusMethodNotAllowed)
		return
	}
	if rt.location && !r.URL.Query().Has(config.OpsSelf) {
		if addr := h.config().CollectorAddr(); addr != "" {
			forward(w, r, addr, id)
			return
		}
	}
	rt.serve(h, w, r.WithContext(withCaller(r.Context(), id)))
}

// collector reaches the location's collector, on the edges' own network.
var collector = &http.Client{Transport: &http.Transport{
	DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	ResponseHeaderTimeout: 15 * time.Second,
	MaxIdleConnsPerHost:   4,
}}

// forward passes a read on to the location's collector and returns its
// answer: the status, metrics or logs of every edge of the location. The
// caller's certificate was checked here; the collector gets its SPIFFE ID.
// A collector that does not answer is a 502: this edge's own answer would
// pass for the location's.
func forward(w http.ResponseWriter, r *http.Request, addr, id string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+addr+r.URL.RequestURI(), nil)
	if err == nil {
		req.Header.Set("X-Fortress-Caller", id)
		var resp *http.Response
		if resp, err = collector.Do(req); err == nil {
			defer resp.Body.Close()
			for _, k := range []string{"Content-Type", "X-Log-Cursor", "X-Log-Gap"} {
				if v := resp.Header.Get(k); v != "" {
					w.Header().Set(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
	}
	slog.Warn("ops: the collector does not answer", "collector", addr, "path", r.URL.Path, "err", err)
	http.Error(w, "ops: the collector does not answer; add ?"+config.OpsSelf+" for this edge alone", http.StatusBadGateway)
}

// methods lists the methods path has a route for.
func methods(path string) []string {
	var out []string
	for k := range routes {
		if m, p, _ := strings.Cut(k, " "); p == path {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}

// caller is the role and SPIFFE ID of the request's client certificate.
// The role is empty for anything that is not an identity of this tunnel.
// The CN is display-only and never consulted.
func (h *Handler) caller(r *http.Request) (ca.Role, string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ""
	}
	cert := r.TLS.PeerCertificates[0]
	id := ""
	if len(cert.URIs) > 0 {
		id = cert.URIs[0].String()
	}
	role, _, ok := ca.Identify(cert, h.config().Tunnel)
	if !ok {
		return "", id
	}
	return role, id
}

type callerKey struct{}

func withCaller(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, callerKey{}, id)
}

func callerOf(r *http.Request) string {
	id, _ := r.Context().Value(callerKey{}).(string)
	return id
}

// getPolicy returns policy.yml as the last PUT stored it: empty on an edge
// nobody applied a policy to, which runs the defaults.
func (h *Handler) getPolicy(w http.ResponseWriter, _ *http.Request) {
	h.mu.RLock()
	b := h.policy
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("ETag", config.PolicyETag(b))
	_, _ = w.Write(b)
}

// putPolicy replaces the policy whole, in order: it is checked, put in
// force, stored, and only then shown. A failure at any step leaves the
// previous policy in force, stored, and shown, so the disk never holds a
// policy the edge refused, and the next boot never meets one. A policy
// that changes a boot limit goes the same way, then reboots. The same
// body again changes nothing, so a pipeline can PUT on every run.
func (h *Handler) putPolicy(w http.ResponseWriter, r *http.Request) {
	if h.apply.Store == nil {
		http.NotFound(w, r)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPolicy))
	if err != nil {
		http.Error(w, fmt.Sprintf("policy: %v", err), http.StatusRequestEntityTooLarge)
		return
	}
	h.applyMu.Lock()
	defer h.applyMu.Unlock()
	h.mu.RLock()
	// A degraded edge runs less than it stored: the same body is applied.
	same := len(h.degraded) == 0 && bytes.Equal(b, h.policy) && (b != nil) == (h.policy != nil)
	prev := h.cfg.Policy
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if same {
		w.Header().Set("ETag", config.PolicyETag(b))
		io.WriteString(w, "fortressedge: policy unchanged\n")
		return
	}
	p, err := config.ParsePolicy(b)
	code := http.StatusBadRequest
	if err == nil {
		code = http.StatusInternalServerError
		err = h.put(p, prev, b)
	}
	reboot := err == nil && p.RebootFrom(h.boot)
	slog.Info("ops: policy put", "id", callerOf(r), "etag", config.PolicyETag(b), "err", err, "reboot", reboot)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	h.mu.Lock()
	h.cfg.Policy = p
	h.policy = b
	h.degraded = nil
	h.mu.Unlock()
	w.Header().Set("ETag", config.PolicyETag(b))
	if reboot {
		io.WriteString(w, "fortressedge: policy stored, rebooting to apply it\n")
	} else {
		io.WriteString(w, "fortressedge: policy applied\n")
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	if reboot && h.apply.Reboot != nil {
		h.apply.Reboot()
	}
}

// put runs the steps that put p in force, in order, then stores body.
// When one fails, or the store does, it runs the steps that ran again with
// prev, newest first. A step that cannot be undone leaves the edge
// degraded.
func (h *Handler) put(p, prev config.Policy, body []byte) error {
	steps := h.apply.Steps
	ran := 0
	var err error
	for ; ran < len(steps); ran++ {
		if err = steps[ran](p); err != nil {
			break
		}
	}
	if err == nil {
		if err = h.apply.Store(body); err == nil {
			return nil
		}
	}
	for _, step := range slices.Backward(steps[:ran]) {
		if uerr := step(prev); uerr != nil {
			err = fmt.Errorf("%w; restoring the previous policy: %w", err, uerr)
			h.mu.Lock()
			h.degraded = append(h.degraded, "restoring the policy in force after a refused one: "+uerr.Error())
			h.mu.Unlock()
		}
	}
	return err
}

// errCursor is a cursor query that does not parse.
var errCursor = errors.New("cursor")

// open returns the log file a cursor query names in dir, and where to
// start. live marks current.log, still being written (never ship its
// partial last line). next is the id of the file to read after this one:
// its own for current.log, else the next newer file's. gap means the
// cursor's file is gone: lines were lost, so we restart at current.log's
// beginning and say so. "oldest" names the oldest file kept, from its start.
func (h *Handler) open(dir, q string) (f *os.File, next string, off int64, live, gap bool, err error) {
	var c cursor
	if q != "" && q != "now" && q != "oldest" {
		if c, err = parseCursor(q); err != nil {
			return nil, "", 0, false, false, fmt.Errorf("%w: %v", errCursor, err)
		}
	}
	cur, err := os.Open(filepath.Join(dir, "current.log"))
	if err != nil {
		return nil, "", 0, false, false, err
	}
	id := fileID(cur)
	if id == "" && dir == h.dir {
		id = h.bootID // a log from before markers
	}
	if q == "" || q == "now" || c.boot == id {
		return cur, id, c.off, true, false, nil
	}
	// Older files, newest first: the edge's log keeps previous.log, the
	// access log up to access_log_max_files.
	newer := id
	rotated := logx.Rotated(dir)
	for i, p := range rotated {
		old, err := os.Open(p)
		if err != nil {
			continue
		}
		oid := fileID(old)
		if oid == c.boot && q != "oldest" || q == "oldest" && i == len(rotated)-1 {
			_ = cur.Close()
			return old, newer, c.off, false, false, nil
		}
		_ = old.Close()
		newer = oid
	}
	if q == "oldest" {
		return cur, id, 0, true, false, nil // no older file: the current one is the oldest
	}
	return cur, id, 0, true, true, nil
}

func (h *Handler) logs(w http.ResponseWriter, r *http.Request) {
	h.serveLog(w, r, h.dir, false)
}

// access serves the access log. Its lines are JSON records already, so
// it is always NDJSON, without the file marker.
func (h *Handler) access(w http.ResponseWriter, r *http.Request) {
	h.serveLog(w, r, filepath.Join(h.dir, "access"), true)
}

func (h *Handler) serveLog(w http.ResponseWriter, r *http.Request, dir string, records bool) {
	q := r.URL.Query()
	cq := q.Get("cursor")
	f, next, off, live, gap, err := h.open(dir, cq)
	if errors.Is(err, errCursor) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "ops: log unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	size := fileSize(f)
	end := size
	if live {
		end = lastNewlineEnd(f, size)
	}
	if cq == "now" || off > end {
		off = end // "now" is measured after open, so the empty body is exact
	}
	if records {
		off = max(off, markerEnd(f))
	}
	// The resume token. An older file is frozen, so serving it to its end
	// means the next poll continues at the start of the next newer one.
	resume := cursor{next, 0}
	if live {
		resume = cursor{next, end}
	}

	wrap := !records && q.Get("format") == "ndjson"
	if records || wrap {
		w.Header().Set("Content-Type", "application/x-ndjson")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	if gap {
		w.Header().Set("X-Log-Gap", "true")
	}
	w.Header().Set("X-Log-Cursor", resume.String())
	// The file these bytes are from: a copier that asked for the oldest
	// file, or was sent the current one after a gap, cannot tell otherwise.
	if from := fileID(f); from != "" {
		w.Header().Set("X-Log-File", from)
	} else if live {
		w.Header().Set("X-Log-File", next)
	}
	serveRange(w, f, off, end, wrap)
	off = end

	if !q.Has("follow") {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	fl.Flush()
	// Caught up on an older file: ship each newer one, then follow the live one.
	for !live {
		_ = f.Close()
		if f, next, off, live, _, err = h.open(dir, cursor{next, 0}.String()); err != nil {
			f = nil
			return
		}
		if records {
			off = max(off, markerEnd(f))
		}
		if !live {
			serveRange(w, f, off, fileSize(f), wrap)
			fl.Flush()
		}
	}
	h.tail(w, r, filepath.Join(dir, "current.log"), &f, off, wrap, records, fl)
}

// tail polls the live log and ships new complete lines until the client
// hangs up. The edge's log rotates only at boot, and the process exits
// with it. The access log also rotates by size: then *f is finished, so
// its rest is shipped and path is followed from its start.
func (h *Handler) tail(w http.ResponseWriter, r *http.Request, path string, f **os.File, off int64, wrap, records bool, fl http.Flusher) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
		rotated := replaced(path, *f)
		end := lastNewlineEnd(*f, fileSize(*f))
		if end > off {
			serveRange(w, *f, off, end, wrap)
			off = end
			fl.Flush()
		}
		if !rotated {
			continue
		}
		nf, err := os.Open(path)
		if err != nil {
			return
		}
		_ = (*f).Close()
		*f = nf
		off = 0
		if records {
			off = markerEnd(nf)
		}
	}
}

// replaced reports whether path now names another file than f.
func replaced(path string, f *os.File) bool {
	a, err := os.Stat(path)
	if err != nil {
		return false
	}
	b, err := f.Stat()
	return err == nil && !os.SameFile(a, b)
}

func (h *Handler) status(w http.ResponseWriter, _ *http.Request) {
	cfg := h.config()
	w.Header().Set("Content-Type", "application/json")
	m := map[string]any{
		"boot_id":        h.bootID,
		"uptime_seconds": uptime(),
		"iface":          cfg.Iface,
		"addr":           cfg.Addr.String(),
		"gateway":        cfg.Gateway.String(),
		"dns":            cfg.DNS,
		"tunnel":         cfg.Tunnel,
		"quic":           cfg.QUIC,
		"blocked":        len(cfg.Block),
		"log_cursor":     cursor{h.bootID, pathSize(h.path("current.log"))}.String(),
		// Why part of the stored policy is not in force; empty when all is.
		"policy_degraded": h.degradedNow(),
	}
	if h.extra != nil {
		for k, v := range h.extra() {
			m[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(m)
}

// serveMetrics writes the Prometheus text format. Counters start at zero
// at boot, which fortressedge_boot_time_seconds dates.
func (h *Handler) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", metrics.ContentType)
	mw := metrics.NewWriter(w)
	mw.Family("fortressedge_build_info", "gauge", "The edge's build: 1, with its version and Go's as labels.")
	mw.Int("fortressedge_build_info", 1, "version", metrics.Version(), "go_version", runtime.Version())
	// Times by the clock as it is now, which boot may have stepped since:
	// each is now less the time since, measured on the monotonic clock.
	mw.Family("fortressedge_boot_time_seconds", "gauge", "When the edge started, in Unix seconds. Counters start at zero then.")
	mw.Sample("fortressedge_boot_time_seconds", metrics.BootTime())
	if up := uptime(); up > 0 {
		mw.Family("fortressedge_kernel_boot_time_seconds", "gauge", "When the kernel started, in Unix seconds.")
		mw.Sample("fortressedge_kernel_boot_time_seconds", metrics.KernelBootTime(up))
	}
	if at, ok := metrics.ReadyTime(); ok {
		mw.Family("fortressedge_ready_time_seconds", "gauge", "When the edge first accepted connections on 80 and 443, dark nodes' among them, in Unix seconds.")
		mw.Sample("fortressedge_ready_time_seconds", at)
	}
	mw.Family("fortressedge_policy_degraded", "gauge", "1 while part of the stored policy is not in force, as policy_degraded in the status says why; 0 otherwise.")
	degraded := int64(0)
	if len(h.degradedNow()) > 0 {
		degraded = 1
	}
	mw.Int("fortressedge_policy_degraded", degraded)
	if h.metrics != nil {
		h.metrics(mw)
	}
	_ = mw.Flush()
}

// serveRange writes bytes [off, end) of f, either raw or wrapped as one
// {"line": ...} JSON object per line for machine shippers.
func serveRange(w http.ResponseWriter, f *os.File, off, end int64, ndjson bool) {
	sr := io.NewSectionReader(f, off, end-off)
	if !ndjson {
		_, _ = io.Copy(w, sr)
		return
	}
	sc := bufio.NewScanner(sr)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		_ = enc.Encode(struct {
			Line string `json:"line"`
		}{sc.Text()})
	}
}

// lastNewlineEnd is the offset just past the last '\n' in the file's tail.
// A live log's final line may be half-written; never ship it — the next
// cursor picks it up once it completes.
func lastNewlineEnd(f *os.File, size int64) int64 {
	const tail = 1 << 20
	start := int64(0)
	if size > tail {
		start = size - tail
	}
	buf := make([]byte, size-start)
	n, _ := f.ReadAt(buf, start)
	i := bytes.LastIndexByte(buf[:n], '\n')
	if i < 0 {
		return 0
	}
	return start + int64(i) + 1
}

// firstLine is f's first line, up to 256 bytes, with its newline.
func firstLine(f *os.File) string {
	buf := make([]byte, 256)
	n, _ := f.ReadAt(buf, 0)
	i := bytes.IndexByte(buf[:n], '\n')
	if i < 0 {
		return ""
	}
	return string(buf[:i+1])
}

// fileID reads the marker logx writes as a log file's first line; ""
// means the file predates markers.
func fileID(f *os.File) string {
	line := firstLine(f)
	if !strings.HasPrefix(line, bootPrefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(line, bootPrefix))
}

// markerEnd is the offset just past f's marker line, 0 if it has none.
func markerEnd(f *os.File) int64 {
	if line := firstLine(f); strings.HasPrefix(line, bootPrefix) {
		return int64(len(line))
	}
	return 0
}

func (h *Handler) path(name string) string { return filepath.Join(h.dir, name) }

func fileSize(f *os.File) int64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return st.Size()
}

func pathSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// uptime reads /proc/uptime; 0 where there is no /proc.
func uptime() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	f, _ := strconv.ParseFloat(fields[0], 64)
	return f
}
