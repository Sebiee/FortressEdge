package collect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
	"github.com/Sebiee/fortressedge/internal/ops"
)

// An edge of the tests is the edge's real ops API over a directory.
type edge struct {
	dir  string
	h    *ops.Handler
	down bool
}

func newEdge(t *testing.T, boot string) *edge {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{
		Iface: "eth0", Addr: netip.MustParsePrefix("10.4.1.11/24"), Gateway: netip.MustParseAddr("10.4.1.1"),
		Tunnel: "tunnel.example.com",
	}
	e := &edge{dir: dir, h: ops.New(cfg, nil, boot, dir)}
	e.h.SetMetrics(func(w *metrics.Writer) {
		w.Family("fortressedge_http_requests_total", "counter", "Requests.")
		w.Int("fortressedge_http_requests_total", 7, "site", "a.example.com", "code_class", "2xx")
		w.Family("fortressedge_connections", "gauge", "Open connections.")
		w.Int("fortressedge_connections", 3)
	})
	e.write("", "# boot "+boot+"\n")
	return e
}

// write appends to the edge's log (sub "") or its access log ("access").
func (e *edge) write(sub, text string) {
	dir := filepath.Join(e.dir, sub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "current.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		panic(err)
	}
}

// rotate ends the current file under name and starts a new one with id.
func (e *edge) rotate(sub, name, id string) {
	dir := filepath.Join(e.dir, sub)
	if err := os.Rename(filepath.Join(dir, "current.log"), filepath.Join(dir, name)); err != nil {
		panic(err)
	}
	e.write(sub, "# boot "+id+"\n")
}

func fetcher(edges map[string]*edge) Fetch {
	return func(_ context.Context, e Edge, path string, q url.Values) (*http.Response, error) {
		ed := edges[e.Name]
		if ed.down {
			return nil, io.ErrUnexpectedEOF
		}
		if !q.Has(config.OpsSelf) {
			panic("the collector must ask an edge for itself")
		}
		r := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
		id, _ := url.Parse("spiffe://tunnel.example.com/logs/collector")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{id}}}}
		rec := httptest.NewRecorder()
		ed.h.ServeHTTP(rec, r)
		return rec.Result(), nil
	}
}

func newCollector(t *testing.T, edges map[string]*edge) *Collector {
	t.Helper()
	cfg := Config{Fetch: fetcher(edges), Dir: t.TempDir(), Keep: 1 << 20}
	for name := range edges {
		cfg.Edges = append(cfg.Edges, Edge{Name: name})
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// copyAll reads every edge's logs once, as Run does at each tick.
func (c *Collector) copyAll() {
	for _, e := range c.cfg.Edges {
		for _, k := range logKinds {
			_ = c.copyLog(context.Background(), e, k.name, k.path)
		}
	}
}

func get(t *testing.T, c *Collector, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", target, rec.Code, rec.Body)
	}
	return rec
}

func same(t *testing.T, copied, original string) {
	t.Helper()
	a, err := os.ReadFile(copied)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("%s is not the edge's %s:\n%q\n%q", copied, original, a, b)
	}
}

// The copy has the edge's files, byte for byte, through a reboot and a
// rotation of the access log.
func TestCopyIsTheEdgesFiles(t *testing.T) {
	a := newEdge(t, "boot1")
	c := newCollector(t, map[string]*edge{"a": a})
	a.write("", "time=1 msg=one\n")
	a.write("access", "# boot boot1\n"+`{"id":"1","site":"x.example.com"}`+"\n")
	c.copyAll()
	a.write("", "time=2 msg=two\n")
	a.write("access", `{"id":"2","site":"x.example.com"}`+"\n")
	c.copyAll()
	same(t, filepath.Join(c.cfg.Dir, "a/logs/boot1.log"), filepath.Join(a.dir, "current.log"))
	same(t, filepath.Join(c.cfg.Dir, "a/access/boot1.log"), filepath.Join(a.dir, "access/current.log"))

	// A line the edge has not ended is not copied before it ends. Then the
	// edge reboots, and its access log rotates.
	a.write("", "time=3 msg=half")
	c.copyAll()
	if b, _ := os.ReadFile(filepath.Join(c.cfg.Dir, "a/logs/boot1.log")); strings.Contains(string(b), "half") {
		t.Fatal("half a line was copied")
	}
	a.write("", "\n")
	a.rotate("", "previous.log", "boot2")
	a.write("", "time=4 msg=four\n")
	a.rotate("access", "boot1.log", "boot2")
	a.write("access", `{"id":"3","site":"x.example.com"}`+"\n")
	c.copyAll()
	same(t, filepath.Join(c.cfg.Dir, "a/logs/boot1.log"), filepath.Join(a.dir, "previous.log"))
	same(t, filepath.Join(c.cfg.Dir, "a/logs/boot2.log"), filepath.Join(a.dir, "current.log"))
	same(t, filepath.Join(c.cfg.Dir, "a/access/boot1.log"), filepath.Join(a.dir, "access/boot1.log"))
	same(t, filepath.Join(c.cfg.Dir, "a/access/boot2.log"), filepath.Join(a.dir, "access/current.log"))

	// A collector that starts again goes on where its copy ends.
	again, err := New(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.write("", "time=5 msg=five\n")
	again.copyAll()
	same(t, filepath.Join(c.cfg.Dir, "a/logs/boot2.log"), filepath.Join(a.dir, "current.log"))
}

func lineIDs(t *testing.T, body string) (ids []string) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSpace(body), "\n") {
		if l == "" {
			continue
		}
		var rec struct{ Edge, ID string }
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		ids = append(ids, rec.Edge+rec.ID)
	}
	return ids
}

// A reader gets every edge's records once, each with its edge, and its
// cursor is good at another collector of the same edges.
func TestAccessOfAllEdgesByCursor(t *testing.T) {
	a, b := newEdge(t, "boota"), newEdge(t, "bootb")
	edges := map[string]*edge{"a": a, "b": b}
	a.write("access", "# boot boota\n"+`{"id":"1"}`+"\n"+`{"id":"2"}`+"\n")
	b.write("access", "# boot bootb\n"+`{"id":"1"}`+"\n")
	front1, front2 := newCollector(t, edges), newCollector(t, edges)
	front1.copyAll()
	front2.copyAll()

	first := get(t, front1, config.OpsAccessPath)
	if got := strings.Join(lineIDs(t, first.Body.String()), " "); got != "a1 a2 b1" {
		t.Fatalf("first read: %s", got)
	}
	cursor := first.Header().Get("X-Log-Cursor")
	if cursor != "a=boota:35,b=bootb:24" {
		t.Fatalf("cursor: %s", cursor)
	}

	// More arrives; the other front answers the same cursor.
	b.write("access", `{"id":"2"}`+"\n")
	a.rotate("access", "boota.log", "boota.1")
	a.write("access", `{"id":"3"}`+"\n"+`{"id":"4"`)
	front1.copyAll()
	front2.copyAll()
	for _, front := range []*Collector{front1, front2} {
		next := get(t, front, config.OpsAccessPath+"?cursor="+url.QueryEscape(cursor))
		if got := strings.Join(lineIDs(t, next.Body.String()), " "); got != "a3 b2" {
			t.Fatalf("second read: %s", got)
		}
		if next.Header().Get("X-Log-Gap") != "" {
			t.Fatal("no line was lost")
		}
		if got := next.Header().Get("X-Log-Cursor"); got != "a=boota.1:26,b=bootb:35" {
			t.Fatalf("cursor: %s", got)
		}
	}

	// cursor=now starts after what is there.
	now := get(t, front1, config.OpsAccessPath+"?cursor=now")
	if now.Body.Len() != 0 || now.Header().Get("X-Log-Cursor") != "a=boota.1:26,b=bootb:35" {
		t.Fatalf("now: %q %s", now.Body, now.Header().Get("X-Log-Cursor"))
	}
}

// A reader that is behind gets everything, once, in answers of a bounded size.
func TestAnswersAreBounded(t *testing.T) {
	old := maxAnswer
	maxAnswer = 40
	t.Cleanup(func() { maxAnswer = old })
	a, b := newEdge(t, "boota"), newEdge(t, "bootb")
	want := []string{}
	a.write("access", "# boot boota\n")
	b.write("access", "# boot bootb\n")
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		a.write("access", `{"id":"`+id+`","pad":"xxxxxxxxxx"}`+"\n")
		want = append(want, "a"+id)
	}
	b.write("access", `{"id":"1","pad":"xxxxxxxxxx"}`+"\n")
	want = append(want, "b1")
	c := newCollector(t, map[string]*edge{"a": a, "b": b})
	c.copyAll()

	var got []string
	cursor := ""
	for i := 0; i < 20; i++ {
		rec := get(t, c, config.OpsAccessPath+"?cursor="+url.QueryEscape(cursor))
		ids := lineIDs(t, rec.Body.String())
		if len(ids) == 0 {
			break
		}
		if len(ids) > 2 {
			t.Fatalf("an answer of %d lines is over the bound", len(ids))
		}
		got = append(got, ids...)
		cursor = rec.Header().Get("X-Log-Cursor")
	}
	if strings.Join(got, " ") != "a1 a2 a3 a4 a5 b1" {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Lines the edge lost before the collector read them, and a cursor into a
// file the copy does not have, are signalled as the edge signals them.
func TestGapsAreSignalled(t *testing.T) {
	a := newEdge(t, "boot1")
	c := newCollector(t, map[string]*edge{"a": a})
	a.write("", "time=1 msg=one\n")
	c.copyAll()
	first := get(t, c, config.OpsLogsPath)
	if got := first.Body.String(); got != "# boot boot1\ntime=1 msg=one edge=a\n" {
		t.Fatalf("first read: %q", got)
	}
	cursor := first.Header().Get("X-Log-Cursor")

	// Two reboots while the collector is away: boot2's file is gone.
	a.rotate("", "previous.log", "boot3")
	a.write("", "time=9 msg=nine\n")
	if err := os.Remove(filepath.Join(a.dir, "previous.log")); err != nil {
		t.Fatal(err)
	}
	c.copyAll()
	next := get(t, c, config.OpsLogsPath+"?format=ndjson&cursor="+url.QueryEscape(cursor))
	if next.Header().Get("X-Log-Gap") != "true" {
		t.Fatal("lost lines are not signalled")
	}
	if got := next.Body.String(); got != `{"edge":"a","line":"# boot boot3"}`+"\n"+`{"edge":"a","line":"time=9 msg=nine"}`+"\n" {
		t.Fatalf("after the gap: %q", got)
	}
	// The reader is past the gap now.
	after := get(t, c, config.OpsLogsPath+"?cursor="+url.QueryEscape(next.Header().Get("X-Log-Cursor")))
	if after.Header().Get("X-Log-Gap") != "" || after.Body.Len() != 0 {
		t.Fatalf("past the gap: gap %q, body %q", after.Header().Get("X-Log-Gap"), after.Body)
	}

	// A cursor of a file this copy never had (another front's, rebuilt).
	lost := get(t, c, config.OpsLogsPath+"?cursor="+url.QueryEscape("a=boot0:10"))
	if lost.Header().Get("X-Log-Gap") != "true" || !strings.HasPrefix(lost.Body.String(), "# boot boot1\n") {
		t.Fatalf("unknown file: gap %q, body %q", lost.Header().Get("X-Log-Gap"), lost.Body)
	}
}

// The copy stays under its size: the oldest files go, never the newest.
func TestCopyIsBounded(t *testing.T) {
	a := newEdge(t, "boot1")
	c := newCollector(t, map[string]*edge{"a": a})
	c.mirrors["a/logs"].keep = 64
	a.write("", strings.Repeat("time=1 msg=aaaaaaaaaaaaaaaaaaaa\n", 3))
	c.copyAll()
	a.rotate("", "previous.log", "boot2")
	a.write("", "time=2 msg=b\n")
	c.copyAll()
	if _, err := os.Stat(filepath.Join(c.cfg.Dir, "a/logs/boot1.log")); !os.IsNotExist(err) {
		t.Fatal("the oldest file is still there")
	}
	rec := get(t, c, config.OpsLogsPath+"?cursor="+url.QueryEscape("a=boot1:13"))
	if rec.Header().Get("X-Log-Gap") != "true" || rec.Body.String() != "# boot boot2\ntime=2 msg=b edge=a\n" {
		t.Fatalf("after the prune: gap %q, body %q", rec.Header().Get("X-Log-Gap"), rec.Body)
	}
}

// Metrics and status are every edge's, as they are now, by edge.
func TestMetricsAndStatusOfAllEdges(t *testing.T) {
	a, b := newEdge(t, "boota"), newEdge(t, "bootb")
	edges := map[string]*edge{"a": a, "b": b, "c": newEdge(t, "bootc")}
	edges["c"].down = true
	c := newCollector(t, edges)

	m := get(t, c, config.OpsMetricsPath).Body.String()
	for _, want := range []string{
		`fortressedge_http_requests_total{edge="a",site="a.example.com",code_class="2xx"} 7` + "\n" +
			`fortressedge_http_requests_total{edge="b",site="a.example.com",code_class="2xx"} 7` + "\n",
		`fortressedge_connections{edge="a"} 3` + "\n" + `fortressedge_connections{edge="b"} 3` + "\n",
		`fortresscollector_edge_up{edge="a"} 1`, `fortresscollector_edge_up{edge="c"} 0`,
		`fortresscollector_log_bytes{edge="a",log="logs"} 0`,
	} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics lack %q:\n%s", want, m)
		}
	}
	if n := strings.Count(m, "# TYPE fortressedge_http_requests_total counter"); n != 1 {
		t.Fatalf("a family's TYPE is there %d times", n)
	}

	var st struct {
		Edges map[string]*struct {
			BootID string `json:"boot_id"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(get(t, c, config.OpsStatusPath).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Edges["a"].BootID != "boota" || st.Edges["b"].BootID != "bootb" || st.Edges["c"] != nil {
		t.Fatalf("status: %+v", st.Edges)
	}
}

// A read has what the edges have at that moment, and a collector whose
// copy is behind another's answers that one's cursor: with the same lines
// when it can reach the edge, with none and the cursor as it was when it
// cannot. It never sends a line again and never signals a loss that is
// none.
func TestACopyThatIsBehindAnswersTheOthersCursor(t *testing.T) {
	a := newEdge(t, "boota")
	edges := map[string]*edge{"a": a}
	a.write("access", "# boot boota\n"+`{"id":"1"}`+"\n")
	front1, front2 := newCollector(t, edges), newCollector(t, edges)
	front2.copyAll() // the partner has the first record, and then is away

	// No timed copy since the edge wrote: the read fetches it.
	a.write("access", `{"id":"2"}`+"\n")
	first := get(t, front1, config.OpsAccessPath)
	if got := strings.Join(lineIDs(t, first.Body.String()), " "); got != "a1 a2" {
		t.Fatalf("a read has what the edge has now: got %s", got)
	}

	// The access log rotates, and the reader is in the new file.
	a.rotate("access", "boota.log", "boota.1")
	a.write("access", `{"id":"3"}`+"\n")
	second := get(t, front1, config.OpsAccessPath+"?cursor="+url.QueryEscape(first.Header().Get("X-Log-Cursor")))
	if got := strings.Join(lineIDs(t, second.Body.String()), " "); got != "a3" {
		t.Fatalf("second read: %s", got)
	}
	cursor := second.Header().Get("X-Log-Cursor")
	a.write("access", `{"id":"4"}`+"\n")

	// The partner takes over while the edge does not answer: its copy ends
	// in the old file. It has no line for the reader yet, and says so by
	// the same cursor, not by a gap or by old lines.
	a.down = true
	waiting := get(t, front2, config.OpsAccessPath+"?cursor="+url.QueryEscape(cursor))
	if waiting.Body.Len() != 0 || waiting.Header().Get("X-Log-Gap") != "" || waiting.Header().Get("X-Log-Cursor") != cursor {
		t.Fatalf("a copy that is behind: body %q, gap %q, cursor %q (was %q)",
			waiting.Body, waiting.Header().Get("X-Log-Gap"), waiting.Header().Get("X-Log-Cursor"), cursor)
	}

	// The edge answers again: the partner catches up at the read and goes
	// on exactly where the reader was.
	a.down = false
	next := get(t, front2, config.OpsAccessPath+"?cursor="+url.QueryEscape(cursor))
	if got := strings.Join(lineIDs(t, next.Body.String()), " "); got != "a4" || next.Header().Get("X-Log-Gap") != "" {
		t.Fatalf("after it caught up: %s, gap %q", got, next.Header().Get("X-Log-Gap"))
	}
}
