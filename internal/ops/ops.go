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
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/logx"
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

// Outcome is what applying a policy did. Reboot means the process must
// restart into it; otherwise the caller already applied it.
type Outcome struct {
	Reboot bool
	Cfg    config.Config
}

// ApplyFunc stores and applies a policy.yml body. A *config.InvalidError
// is the body's fault.
type ApplyFunc func(policy []byte) (Outcome, error)

// maxPolicy bounds a policy.yml body: a block list of some ten thousand
// prefixes.
const maxPolicy = 1 << 20

type Handler struct {
	mu     sync.RWMutex
	cfg    config.Config
	policy []byte // policy.yml as stored; nil before the first apply
	bootID string
	dir    string
	extra  func() map[string]any
	apply  ApplyFunc
	reboot func()
	// applyMu keeps a PUT's compare, apply, and swap of policy together.
	applyMu sync.Mutex
}

// New serves cfg's logs and status. policy is the policy.yml cfg was
// parsed with, as stored.
func New(cfg config.Config, policy []byte, bootID, dir string) *Handler {
	return &Handler{cfg: cfg, policy: policy, bootID: bootID, dir: dir}
}

func (h *Handler) SetStatus(fn func() map[string]any) { h.extra = fn }

// SetApply registers the policy PUT. reboot runs after the response is
// flushed when the change cannot be applied in place.
func (h *Handler) SetApply(fn ApplyFunc, reboot func()) {
	h.apply = fn
	h.reboot = reboot
}

// SetConfig swaps the config later requests see, so status follows a
// policy applied in place.
func (h *Handler) SetConfig(cfg config.Config) {
	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()
}

func (h *Handler) config() config.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// route is one endpoint: the roles that may call it.
type route struct {
	roles []ca.Role
	serve func(h *Handler, w http.ResponseWriter, r *http.Request)
}

var (
	readers   = []ca.Role{ca.RoleOps, ca.RoleLogs}
	operators = []ca.Role{ca.RoleOps}
)

// routes is keyed by method and path, as "GET /~!ops/status".
var routes = map[string]route{
	"GET " + config.OpsStatusPath: {readers, (*Handler).status},
	"GET " + config.OpsLogsPath:   {readers, (*Handler).logs},
	"GET " + config.OpsAccessPath: {readers, (*Handler).access},
	"GET " + config.OpsPolicyPath: {readers, (*Handler).getPolicy},
	"PUT " + config.OpsPolicyPath: {operators, (*Handler).putPolicy},
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
	rt.serve(h, w, r.WithContext(withCaller(r.Context(), id)))
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

// putPolicy replaces the policy whole. The same body again changes
// nothing, so a pipeline can PUT on every run.
func (h *Handler) putPolicy(w http.ResponseWriter, r *http.Request) {
	if h.apply == nil {
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
	same := bytes.Equal(b, h.policy) && (b != nil) == (h.policy != nil)
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if same {
		w.Header().Set("ETag", config.PolicyETag(b))
		io.WriteString(w, "fortressedge: policy unchanged\n")
		return
	}
	out, err := h.apply(b)
	slog.Info("ops: policy put", "id", callerOf(r), "etag", config.PolicyETag(b), "err", err, "reboot", out.Reboot)
	if err != nil {
		var inv *config.InvalidError
		if errors.As(err, &inv) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.mu.Lock()
	h.policy = b
	h.mu.Unlock()
	w.Header().Set("ETag", config.PolicyETag(b))
	if out.Reboot {
		io.WriteString(w, "fortressedge: policy stored, rebooting to apply it\n")
	} else {
		io.WriteString(w, "fortressedge: policy applied\n")
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	if out.Reboot && h.reboot != nil {
		h.reboot()
	}
}

// errCursor is a cursor query that does not parse.
var errCursor = errors.New("cursor")

// open returns the log file a cursor query names in dir, and where to
// start. live marks current.log, still being written (never ship its
// partial last line). next is the id of the file to read after this one:
// its own for current.log, else the next newer file's. gap means the
// cursor's file is gone: lines were lost, so we restart at current.log's
// beginning and say so.
func (h *Handler) open(dir, q string) (f *os.File, next string, off int64, live, gap bool, err error) {
	var c cursor
	if q != "" && q != "now" {
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
	for _, p := range logx.Rotated(dir) {
		old, err := os.Open(p)
		if err != nil {
			continue
		}
		oid := fileID(old)
		if oid == c.boot {
			_ = cur.Close()
			return old, newer, c.off, false, false, nil
		}
		_ = old.Close()
		newer = oid
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
	}
	if h.extra != nil {
		for k, v := range h.extra() {
			m[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(m)
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
