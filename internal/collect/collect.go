// Package collect is the collector of one location of an edge service. It
// runs beside the edges (on the front that stands before them), keeps a
// copy of every edge's log and access log, and answers the reads of the
// ops API for all its edges at once: an edge passes such a read on to it
// (policy.yml's collector), so a reader that reaches any edge of the
// location gets the whole location.
//
//   - Logs: the copy of an edge's log has the edge's own files, by their
//     ids, with the same bytes at the same offsets (mirror). A reader's
//     cursor is every edge's own cursor, "a=<file-id>:<offset>,b=...", so
//     it is good at either of two collectors that copy the same edges, and
//     the edge's signal for lost lines (X-Log-Gap) passes through. A read
//     first brings the copies up to their edges, so its answer has what
//     the edges have at that moment, and a collector whose copy was behind
//     another's answers that one's cursor all the same.
//   - Metrics and status: asked of every edge at the moment of the read, so
//     a counter never goes backward when another collector answers next.
package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// maxAnswer bounds the log lines of one answer. A reader that is behind
// gets the rest with the cursor of this one.
var maxAnswer int64 = 8 << 20

// An Edge is one edge of the location.
type Edge struct {
	Name string // in cursors and as the edge label: a-z, 0-9, '.', '_', '-'
	Addr string // host:port of its HTTPS port
}

var edgeName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Fetch does one GET on an edge's ops API. The default (HTTPS) asks the
// edge at its address, under the tunnel name, with a log-reader
// certificate.
type Fetch func(ctx context.Context, e Edge, path string, query url.Values) (*http.Response, error)

type Config struct {
	Edges []Edge
	Fetch Fetch
	// Dir holds the copies: <Dir>/<edge>/logs and <Dir>/<edge>/access.
	Dir string
	// Keep is the size of each copy; its oldest files go first.
	Keep int64
	// Every is how often each edge's logs are read.
	Every time.Duration
}

// logKinds are the two logs of an edge, by the name of their copy.
var logKinds = []struct {
	name, path string
	records    bool
}{
	{"logs", config.OpsLogsPath, false},
	{"access", config.OpsAccessPath, true},
}

type Collector struct {
	cfg     Config
	mirrors map[string]*mirror // by edge and kind, "a/logs"

	pullsOK, pullsFailed map[string]*atomic.Int64
	// accessOff holds the edges that keep no access log now (policy.yml's
	// access_log), so its absence is logged once.
	accessOff sync.Map
}

func New(cfg Config) (*Collector, error) {
	if len(cfg.Edges) == 0 {
		return nil, errors.New("collector: no edges")
	}
	c := &Collector{cfg: cfg, mirrors: map[string]*mirror{}, pullsOK: map[string]*atomic.Int64{}, pullsFailed: map[string]*atomic.Int64{}}
	seen := map[string]bool{}
	for _, e := range cfg.Edges {
		if !edgeName.MatchString(e.Name) || seen[e.Name] {
			return nil, fmt.Errorf("collector: edge name %q: want a name of its own, of a-z, 0-9, '.', '_', '-'", e.Name)
		}
		seen[e.Name] = true
		for _, k := range logKinds {
			m, err := openMirror(filepath.Join(cfg.Dir, e.Name, k.name), k.records, cfg.Keep)
			if err != nil {
				return nil, err
			}
			key := e.Name + "/" + k.name
			c.mirrors[key], c.pullsOK[key], c.pullsFailed[key] = m, &atomic.Int64{}, &atomic.Int64{}
		}
	}
	slices.SortFunc(c.cfg.Edges, func(a, b Edge) int { return strings.Compare(a.Name, b.Name) })
	return c, nil
}

// Run copies the edges' logs until ctx ends.
func (c *Collector) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range c.cfg.Edges {
		for _, k := range logKinds {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tick := time.NewTicker(c.cfg.Every)
				defer tick.Stop()
				for {
					_ = c.copyLog(ctx, e, k.name, k.path)
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
					}
				}
			}()
		}
	}
	wg.Wait()
}

// errNoLog is an edge that does not keep the log asked for.
var errNoLog = errors.New("the edge keeps no such log")

// copyLog reads what the edge has after the copy, file after file. It
// reports whether the copy now has all the edge has.
func (c *Collector) copyLog(ctx context.Context, e Edge, kind, path string) bool {
	key := e.Name + "/" + kind
	m := c.mirrors[key]
	for more := true; more && ctx.Err() == nil; {
		var err error
		more, err = m.pull(func(cursor string) (*page, error) {
			q := url.Values{config.OpsSelf: {""}} // for the edge itself: it must not pass the read back
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			resp, err := c.cfg.Fetch(ctx, e, path, q)
			if err != nil {
				cancel()
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				cancel()
				if resp.StatusCode == http.StatusServiceUnavailable && kind == "access" {
					return nil, errNoLog
				}
				return nil, fmt.Errorf("%s: %s", path, resp.Status)
			}
			return &page{
				body: cancelBody{resp.Body, cancel},
				next: resp.Header.Get("X-Log-Cursor"),
				gap:  resp.Header.Get("X-Log-Gap") == "true",
			}, nil
		})
		switch {
		case errors.Is(err, errNoLog):
			if _, told := c.accessOff.LoadOrStore(e.Name, true); !told {
				slog.Info("collector: the edge keeps no access log (policy.yml's access_log)", "edge", e.Name)
			}
			return true
		case err != nil:
			c.pullsFailed[key].Add(1)
			if ctx.Err() == nil {
				slog.Warn("collector: reading an edge's log", "edge", e.Name, "log", kind, "err", err)
			}
			return false
		}
		c.pullsOK[key].Add(1)
		if kind == "access" {
			c.accessOff.Delete(e.Name)
		}
	}
	return ctx.Err() == nil
}

// refresh brings every edge's copy of a log up to the edge, all at once,
// within a few seconds. It returns the edges whose copy now has all the
// edge has; the others' are as the last read left them.
func (c *Collector) refresh(ctx context.Context, kind, path string) map[string]bool {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	var mu sync.Mutex
	fresh := map[string]bool{}
	var wg sync.WaitGroup
	for _, e := range c.cfg.Edges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := c.copyLog(ctx, e, kind, path)
			mu.Lock()
			fresh[e.Name] = ok
			mu.Unlock()
		}()
	}
	wg.Wait()
	return fresh
}

// refreshTimeout bounds what a read waits for the edges.
var refreshTimeout = 3 * time.Second

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelBody) Close() error {
	defer b.cancel()
	return b.ReadCloser.Close()
}

// ServeHTTP answers the ops API's reads for the location. It checks no
// caller: it listens on the edges' network, and an edge has checked the
// reader's certificate before it passed the read on.
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case config.OpsLogsPath:
		c.serveLog(w, r, "logs")
	case config.OpsAccessPath:
		c.serveLog(w, r, "access")
	case config.OpsMetricsPath:
		c.serveMetrics(w, r)
	case config.OpsStatusPath:
		c.serveStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

// parseCursor reads a location's cursor: every edge's own, by name, as
// "a=<file-id>:<offset>,b=<file-id>:<offset>". An edge it leaves out is
// read from the oldest line kept.
func parseCursor(s string) (map[string]position, error) {
	out := map[string]position{}
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		name, pos, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("cursor: want <edge>=<file-id>:<offset>, ..., got %q", part)
		}
		p, err := parsePosition(pos)
		if err != nil {
			return nil, err
		}
		out[name] = p
	}
	return out, nil
}

func formatCursor(at map[string]position) string {
	parts := make([]string, 0, len(at))
	for _, name := range slices.Sorted(maps.Keys(at)) {
		if p := at[name]; p.id != "" {
			parts = append(parts, name+"="+p.String())
		}
	}
	return strings.Join(parts, ",")
}

// serveLog answers /~!ops/logs and /~!ops/access: the lines of every edge
// after the cursor, edge by edge, each line with its edge's name. The
// edge's log gets " edge=<name>" at the end of a line (or an edge key with
// format=ndjson), an access record an "edge" key in front.
func (c *Collector) serveLog(w http.ResponseWriter, r *http.Request, kind string) {
	q := r.URL.Query()
	if q.Has("follow") {
		http.Error(w, "the collector does not follow: read again with the cursor of the last answer", http.StatusNotImplemented)
		return
	}
	now := q.Get("cursor") == "now"
	var at map[string]position
	if !now {
		var err error
		if at, err = parseCursor(q.Get("cursor")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	records := kind == "access"
	wrap := !records && q.Get("format") == "ndjson"
	// What the edges have now, not what the last timed copy left.
	path := config.OpsLogsPath
	if records {
		path = config.OpsAccessPath
	}
	fresh := c.refresh(r.Context(), kind, path)
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	budget := maxAnswer
	next := map[string]position{}
	gap := false
	for _, e := range c.cfg.Edges {
		name := e.Name
		emit := func(line []byte) {
			switch {
			case records && len(line) > 1 && line[0] == '{':
				fmt.Fprintf(&body, `{"edge":%q,`, name)
				body.Write(line[1:])
			case records, bytes.HasPrefix(line, []byte(bootPrefix)) && !wrap:
				body.Write(line)
			case wrap:
				_ = enc.Encode(struct {
					Edge string `json:"edge"`
					Line string `json:"line"`
				}{name, string(bytes.TrimRight(line, "\n"))})
			default:
				body.Write(bytes.TrimRight(line, "\n"))
				fmt.Fprintf(&body, " edge=%s\n", name)
			}
		}
		to, lost, err := c.mirrors[name+"/"+kind].read(at[name], now, fresh[name], &budget, emit)
		if err != nil {
			http.Error(w, "collector: log unavailable", http.StatusServiceUnavailable)
			return
		}
		next[name] = to
		gap = gap || lost
	}
	if records || wrap {
		w.Header().Set("Content-Type", "application/x-ndjson")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	if gap {
		w.Header().Set("X-Log-Gap", "true")
	}
	w.Header().Set("X-Log-Cursor", formatCursor(next))
	_, _ = w.Write(body.Bytes())
}

// ask reads path from every edge at once, each for itself.
func (c *Collector) ask(ctx context.Context, path string) map[string][]byte {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	out := map[string][]byte{}
	var wg sync.WaitGroup
	for _, e := range c.cfg.Edges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.cfg.Fetch(ctx, e, path, url.Values{config.OpsSelf: {""}})
			if err != nil {
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			if err != nil || resp.StatusCode != http.StatusOK {
				return
			}
			mu.Lock()
			out[e.Name] = b
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// serveMetrics answers /~!ops/metrics: every edge's metrics as they are
// now, each sample with an edge label, then the collector's own.
func (c *Collector) serveMetrics(w http.ResponseWriter, r *http.Request) {
	answers := c.ask(r.Context(), config.OpsMetricsPath)
	w.Header().Set("Content-Type", metrics.ContentType)
	mergeMetrics(w, answers)
	mw := metrics.NewWriter(w)
	mw.Family("fortresscollector_edge_up", "gauge", "1 for an edge that answered this read of the metrics, 0 for one that did not: its samples are missing above.")
	for _, e := range c.cfg.Edges {
		up := int64(0)
		if _, ok := answers[e.Name]; ok {
			up = 1
		}
		mw.Int("fortresscollector_edge_up", up, "edge", e.Name)
	}
	mw.Family("fortresscollector_log_bytes", "gauge", "Bytes the collector keeps of an edge's log, by log: logs, access.")
	for _, e := range c.cfg.Edges {
		for _, k := range logKinds {
			mw.Int("fortresscollector_log_bytes", c.mirrors[e.Name+"/"+k.name].size(), "edge", e.Name, "log", k.name)
		}
	}
	mw.Family("fortresscollector_log_reads_total", "counter", "The collector's reads of an edge's log, by log and result: ok, failed.")
	for _, e := range c.cfg.Edges {
		for _, k := range logKinds {
			key := e.Name + "/" + k.name
			mw.Int("fortresscollector_log_reads_total", c.pullsOK[key].Load(), "edge", e.Name, "log", k.name, "result", "ok")
			mw.Int("fortresscollector_log_reads_total", c.pullsFailed[key].Load(), "edge", e.Name, "log", k.name, "result", "failed")
		}
	}
	mw.Family("fortresscollector_log_gaps_total", "counter", "Times an edge had lost lines before the collector read them, by log.")
	for _, e := range c.cfg.Edges {
		for _, k := range logKinds {
			m := c.mirrors[e.Name+"/"+k.name]
			m.mu.Lock()
			gaps := m.gaps
			m.mu.Unlock()
			mw.Int("fortresscollector_log_gaps_total", gaps, "edge", e.Name, "log", k.name)
		}
	}
	_ = mw.Flush()
}

// serveStatus answers /~!ops/status: every edge's status under its name;
// null for an edge that did not answer.
func (c *Collector) serveStatus(w http.ResponseWriter, r *http.Request) {
	answers := c.ask(r.Context(), config.OpsStatusPath)
	edges := map[string]json.RawMessage{}
	for _, e := range c.cfg.Edges {
		edges[e.Name] = json.RawMessage("null")
		if b, ok := answers[e.Name]; ok && json.Valid(b) {
			edges[e.Name] = bytes.TrimSpace(b)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"edges": edges})
}
