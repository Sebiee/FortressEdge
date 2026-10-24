package ops

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

const testBoot = "11111111-2222-3333-4444-555555555555"

func testConfig() config.Config {
	return config.Config{
		Iface:   "eth0",
		Addr:    netip.MustParsePrefix("10.0.2.15/24"),
		Gateway: netip.MustParseAddr("10.0.2.2"),
		DNS:     []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		Tunnel:  "tunnel.example.com",
	}
}

// request fakes a verified client cert: the TLS layer has already done the
// CA check, so a ConnectionState with PeerCertificates is all ops sees.
// Identity lives in the URI SAN as a SPIFFE ID; "" means a cert with none.
const (
	opsID  = "spiffe://tunnel.example.com/ops/alice"
	logsID = "spiffe://tunnel.example.com/logs/filebeat"
	nodeID = "spiffe://tunnel.example.com/node/node1"
)

func request(target, id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	cert := &x509.Certificate{}
	if id != "" {
		u, err := url.Parse(id)
		if err != nil {
			panic(err)
		}
		cert.URIs = []*url.URL{u}
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

func writeLogs(t *testing.T, dir, current, previous string) {
	t.Helper()
	if current != "" {
		if err := os.WriteFile(filepath.Join(dir, "current.log"), []byte(current), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if previous != "" {
		if err := os.WriteFile(filepath.Join(dir, "previous.log"), []byte(previous), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func serve(t *testing.T, h *Handler, target, id string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request(target, id))
	return rec
}

// TestRoles: each identity reaches exactly the endpoints its role allows.
func TestRoles(t *testing.T) {
	dir := t.TempDir()
	writeLogs(t, dir, "# boot "+testBoot+"\nline\n", "")
	access := filepath.Join(dir, "access")
	if err := os.Mkdir(access, 0o755); err != nil {
		t.Fatal(err)
	}
	writeLogs(t, access, "# boot "+testBoot+"\n{}\n", "")
	h := New(testConfig(), nil, testBoot, dir)
	h.SetApply(Apply{Store: func([]byte) error { return nil }})
	for _, tc := range []struct {
		id, method, path string
		want             int
	}{
		{opsID, http.MethodGet, config.OpsLogsPath, 200},
		{opsID, http.MethodGet, config.OpsStatusPath, 200},
		{opsID, http.MethodGet, config.OpsPolicyPath, 200},
		{opsID, http.MethodPut, config.OpsPolicyPath, 200},
		{logsID, http.MethodGet, config.OpsPolicyPath, 200},
		{logsID, http.MethodPut, config.OpsPolicyPath, 403},
		{nodeID, http.MethodGet, config.OpsPolicyPath, 403},
		{opsID, http.MethodPost, config.OpsPolicyPath, 405},
		{opsID, http.MethodPost, config.OpsPathPrefix + "config", 404}, // bundles are gone
		{logsID, http.MethodGet, config.OpsLogsPath, 200},
		{logsID, http.MethodGet, config.OpsStatusPath, 200},
		{logsID, http.MethodGet, config.OpsAccessPath, 200},
		{nodeID, http.MethodGet, config.OpsAccessPath, 403},
		{logsID, http.MethodGet, config.OpsMetricsPath, 200},
		{opsID, http.MethodGet, config.OpsMetricsPath, 200},
		{nodeID, http.MethodGet, config.OpsMetricsPath, 403},
		{nodeID, http.MethodGet, config.OpsLogsPath, 403},
		{nodeID, http.MethodGet, config.OpsStatusPath, 403},
		{"", http.MethodGet, config.OpsStatusPath, 403},
		{"spiffe://tunnel.example.com/ops", http.MethodGet, config.OpsStatusPath, 403},         // no name
		{"spiffe://other.example.com/ops/alice", http.MethodGet, config.OpsStatusPath, 403},    // another tunnel
		{"spiffe://tunnel.example.com/admin/alice", http.MethodGet, config.OpsStatusPath, 403}, // unknown role
		{opsID, http.MethodPost, config.OpsStatusPath, 405},
		{logsID, http.MethodPost, config.OpsPathPrefix + "certs", 404}, // minting is gone
		{nodeID, http.MethodPost, config.OpsPathPrefix + "certs", 403},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, policyRequest(tc.method, tc.path, tc.id, "block: [1.2.3.4]\n"))
		if rec.Code != tc.want {
			t.Errorf("%s %s as %q: status %d, want %d", tc.method, tc.path, tc.id, rec.Code, tc.want)
		}
	}
}

func TestLogsFullAndCursorHeader(t *testing.T) {
	dir := t.TempDir()
	content := "# boot " + testBoot + "\nline one\nline two\n"
	writeLogs(t, dir, content, "")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath, opsID)
	if rec.Code != 200 || rec.Body.String() != content {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	want := testBoot + ":" + itoa(int64(len(content)))
	if got := rec.Header().Get("X-Log-Cursor"); got != want {
		t.Fatalf("cursor=%q want %q", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("content-type=%q", ct)
	}
}

func TestLogsNeverShipPartialLine(t *testing.T) {
	dir := t.TempDir()
	complete := "# boot " + testBoot + "\ndone\n"
	writeLogs(t, dir, complete+"partial-without-newline", "")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath, opsID)
	if rec.Body.String() != complete {
		t.Fatalf("body=%q", rec.Body.String())
	}
	want := testBoot + ":" + itoa(int64(len(complete)))
	if got := rec.Header().Get("X-Log-Cursor"); got != want {
		t.Fatalf("cursor=%q want %q", got, want)
	}
}

func TestLogsCursorOffset(t *testing.T) {
	dir := t.TempDir()
	first := "# boot " + testBoot + "\n"
	writeLogs(t, dir, first+"rest\n", "")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath+"?cursor="+testBoot+":"+itoa(int64(len(first))), opsID)
	if rec.Body.String() != "rest\n" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestLogsCursorNowIsEmpty(t *testing.T) {
	dir := t.TempDir()
	content := "# boot " + testBoot + "\nline\n"
	writeLogs(t, dir, content, "")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath+"?cursor=now", opsID)
	if rec.Body.String() != "" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	want := testBoot + ":" + itoa(int64(len(content)))
	if got := rec.Header().Get("X-Log-Cursor"); got != want {
		t.Fatalf("cursor=%q want %q", got, want)
	}
}

func TestLogsCursorFromPreviousBoot(t *testing.T) {
	dir := t.TempDir()
	writeLogs(t, dir, "# boot "+testBoot+"\nnew\n", "# boot oldboot\nold one\nold two") // frozen: no trailing newline
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath+"?cursor=oldboot:0", opsID)
	if rec.Body.String() != "# boot oldboot\nold one\nold two" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	// previous.log is served to its end, so the next poll starts this boot.
	if got := rec.Header().Get("X-Log-Cursor"); got != testBoot+":0" {
		t.Fatalf("cursor=%q", got)
	}
	if rec.Header().Get("X-Log-Gap") != "" {
		t.Fatal("unexpected gap")
	}
}

func TestLogsUnknownBootSignalsGap(t *testing.T) {
	dir := t.TempDir()
	content := "# boot " + testBoot + "\nline\n"
	writeLogs(t, dir, content, "# boot tooold\ngone\n")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath+"?cursor=nosuchboot:42", opsID)
	if rec.Header().Get("X-Log-Gap") != "true" {
		t.Fatalf("headers=%v", rec.Header())
	}
	if rec.Body.String() != content {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestLogsBadCursor(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	for _, q := range []string{"abc", "boot:-1", "boot:xyz", ":5:5"} {
		if rec := serve(t, h, config.OpsLogsPath+"?cursor="+q, opsID); rec.Code != 400 {
			t.Fatalf("cursor=%q status=%d", q, rec.Code)
		}
	}
}

func TestLogsNDJSON(t *testing.T) {
	dir := t.TempDir()
	writeLogs(t, dir, "# boot "+testBoot+"\nline one\n", "")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath+"?format=ndjson", opsID)
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content-type=%q", ct)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
		var v struct {
			Line string `json:"line"`
		}
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		lines = append(lines, v.Line)
	}
	if len(lines) != 2 || lines[0] != "# boot "+testBoot || lines[1] != "line one" {
		t.Fatalf("lines=%v", lines)
	}
}

func accessDir(t *testing.T, current, previous string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "access"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLogs(t, filepath.Join(dir, "access"), current, previous)
	return dir
}

func TestAccessIsRecords(t *testing.T) {
	head := "# boot " + testBoot + ".1\n"
	dir := accessDir(t, head+`{"status":200}`+"\n", "")
	h := New(testConfig(), nil, testBoot, dir)

	// ?format is ignored: the lines are JSON already, and the marker is not one.
	rec := serve(t, h, config.OpsAccessPath+"?format=text", opsID)
	if rec.Code != 200 || rec.Body.String() != `{"status":200}`+"\n" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content-type=%q", ct)
	}
	want := testBoot + ".1:" + itoa(int64(len(head)+15))
	if got := rec.Header().Get("X-Log-Cursor"); got != want {
		t.Fatalf("cursor=%q want %q", got, want)
	}
}

func TestAccessCursorIntoRotatedFile(t *testing.T) {
	prevHead := "# boot " + testBoot + "\n"
	dir := accessDir(t, "# boot "+testBoot+".1\n{\"n\":3}\n", prevHead+"{\"n\":1}\n{\"n\":2}\n")
	h := New(testConfig(), nil, testBoot, dir)

	// A cursor into the file that rotated out gets its rest, then the new file.
	rec := serve(t, h, config.OpsAccessPath+"?cursor="+testBoot+":"+itoa(int64(len(prevHead)+8)), opsID)
	if rec.Body.String() != "{\"n\":2}\n" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Log-Cursor"); got != testBoot+".1:0" {
		t.Fatalf("cursor=%q", got)
	}
	rec = serve(t, h, config.OpsAccessPath+"?cursor="+testBoot+".1:0", opsID)
	if rec.Body.String() != "{\"n\":3}\n" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestAccessFollowAcrossRotation(t *testing.T) {
	dir := accessDir(t, "# boot b\n{\"n\":1}\n", "")
	logDir := filepath.Join(dir, "access")
	h := New(testConfig(), nil, testBoot, dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.access(w, r)
	}))
	t.Cleanup(srv.Close)
	res, err := srv.Client().Get(srv.URL + "?follow")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	br := bufio.NewReader(res.Body)
	next := func() string {
		t.Helper()
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}
	if got := next(); got != "{\"n\":1}\n" {
		t.Fatalf("first=%q", got)
	}
	// What logx does at the size limit: finish the file, rename it, start another.
	cur := filepath.Join(logDir, "current.log")
	f, err := os.OpenFile(cur, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{\"n\":2}\n")
	f.Close()
	if err := os.Rename(cur, filepath.Join(logDir, "previous.log")); err != nil {
		t.Fatal(err)
	}
	writeLogs(t, logDir, "# boot b.1\n{\"n\":3}\n", "")
	if got := next(); got != "{\"n\":2}\n" {
		t.Fatalf("rest of the rotated file=%q", got)
	}
	if got := next(); got != "{\"n\":3}\n" {
		t.Fatalf("new file=%q", got)
	}
}

// accessFiles writes the access log as logx leaves it after two
// rotations: b.log, b.1.log, then current.log, oldest first by mtime.
func accessFiles(t *testing.T) (dir string) {
	t.Helper()
	dir = accessDir(t, "# boot b.2\n{\"n\":3}\n", "")
	logDir := filepath.Join(dir, "access")
	old := time.Now().Add(-time.Hour)
	for i, f := range []struct{ name, body string }{
		{"b.log", "# boot b\n{\"n\":1}\n"},
		{"b.1.log", "# boot b.1\n{\"n\":2}\n"},
	} {
		p := filepath.Join(logDir, f.name)
		if err := os.WriteFile(p, []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
		mod := old.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAccessCursorWalksEveryKeptFile(t *testing.T) {
	h := New(testConfig(), nil, testBoot, accessFiles(t))
	cur := "b:0"
	var got []string
	for range 3 {
		rec := serve(t, h, config.OpsAccessPath+"?cursor="+cur, opsID)
		if rec.Header().Get("X-Log-Gap") != "" {
			t.Fatalf("gap at %s", cur)
		}
		got = append(got, rec.Body.String())
		cur = rec.Header().Get("X-Log-Cursor")
	}
	want := []string{"{\"n\":1}\n", "{\"n\":2}\n", "{\"n\":3}\n"}
	if !slices.Equal(got, want) {
		t.Fatalf("bodies=%q", got)
	}
	if !strings.HasPrefix(cur, "b.2:") {
		t.Fatalf("last cursor=%q", cur)
	}
}

func TestAccessFollowFromOldestFile(t *testing.T) {
	h := New(testConfig(), nil, testBoot, accessFiles(t))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.access(w, r)
	}))
	t.Cleanup(srv.Close)
	res, err := srv.Client().Get(srv.URL + "?follow&cursor=b:0")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	br := bufio.NewReader(res.Body)
	for _, want := range []string{"{\"n\":1}\n", "{\"n\":2}\n", "{\"n\":3}\n"} {
		line, err := br.ReadString('\n')
		if err != nil || line != want {
			t.Fatalf("line=%q err=%v, want %q", line, err, want)
		}
	}
}

func TestAccessOff(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	if rec := serve(t, h, config.OpsAccessPath, opsID); rec.Code != 503 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestLogsUnavailable(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	if rec := serve(t, h, config.OpsLogsPath, opsID); rec.Code != 503 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestStatus(t *testing.T) {
	dir := t.TempDir()
	content := "# boot " + testBoot + "\nline\n"
	writeLogs(t, dir, content, "")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsStatusPath, opsID)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var st struct {
		BootID    string `json:"boot_id"`
		Tunnel    string `json:"tunnel"`
		LogCursor string `json:"log_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.BootID != testBoot || st.Tunnel != "tunnel.example.com" {
		t.Fatalf("%+v", st)
	}
	want := testBoot + ":" + itoa(int64(len(content)))
	if st.LogCursor != want {
		t.Fatalf("log_cursor=%q want %q", st.LogCursor, want)
	}
}

func TestStatusExtra(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	h.SetStatus(func() map[string]any { return map[string]any{"http_requests": 7} })
	rec := serve(t, h, config.OpsStatusPath, opsID)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["http_requests"] != float64(7) || st["tunnel"] != "tunnel.example.com" {
		t.Fatalf("%v", st)
	}
}

func TestUnknownOpsPath(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	if rec := serve(t, h, config.OpsPathPrefix+"nope", opsID); rec.Code != 404 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// policyRequest is a request with body from the client certificate id.
func policyRequest(method, path, id, body string) *http.Request {
	r := request(path, id)
	r.Method = method
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	return r
}

// fakeEdge is what a policy puts in force, as ops reaches it through
// Apply: XDP's block list, the visitor limits, and policy.yml on the data
// disk.
type fakeEdge struct {
	block    []netip.Prefix
	limits   config.Limits
	file     string
	applies  int
	rebooted bool
	// full makes XDP refuse a block list other than the one it holds, as
	// a full map does; half makes it fail with only part of one in; storeErr
	// makes the disk refuse.
	full, half bool
	storeErr   error
}

func (e *fakeEdge) apply() Apply {
	return Apply{
		Steps: []Step{func(p config.Policy) error {
			switch {
			case slices.Equal(p.Block, e.block):
			case e.full:
				return errors.New("xdp block list: no space")
			case e.half && len(p.Block) > 1:
				e.block = p.Block[len(p.Block)-1:]
				return errors.New("xdp block list: no space; restoring the previous list: no memory")
			}
			e.block = p.Block
			return nil
		}},
		Store: func(b []byte) error {
			if e.storeErr != nil {
				return e.storeErr
			}
			return os.WriteFile(e.file, b, 0o600)
		},
		Commit: []func(config.Policy){func(p config.Policy) {
			e.applies++
			e.limits = p.Limits
		}},
		Reboot: func() { e.rebooted = true },
	}
}

func (e *fakeEdge) stored(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(e.file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}

// policyEdge serves the ops API of a fake edge that booted with body as
// its stored policy.
func policyEdge(t *testing.T, body string) (*Handler, *fakeEdge) {
	t.Helper()
	cfg := testConfig()
	p, err := config.ParsePolicy([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Policy = p
	e := &fakeEdge{block: p.Block, limits: p.Limits, file: filepath.Join(t.TempDir(), "policy.yml")}
	var stored []byte
	if body != "" {
		stored = []byte(body)
		if err := os.WriteFile(e.file, stored, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := New(cfg, stored, testBoot, t.TempDir())
	h.SetApply(e.apply())
	return h, e
}

func putPolicy(h *Handler, id, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, policyRequest(http.MethodPut, config.OpsPolicyPath, id, body))
	return rec
}

func getPolicy(t *testing.T, h *Handler) string {
	t.Helper()
	rec := serve(t, h, config.OpsPolicyPath, logsID)
	if rec.Code != 200 || rec.Header().Get("ETag") != config.PolicyETag(rec.Body.Bytes()) {
		t.Fatalf("get: status=%d etag=%q", rec.Code, rec.Header().Get("ETag"))
	}
	return rec.Body.String()
}

// statusOf is /~!ops/status, decoded.
func statusOf(t *testing.T, h *Handler) map[string]any {
	t.Helper()
	rec := serve(t, h, config.OpsStatusPath, opsID)
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("status=%d %v", rec.Code, err)
	}
	return st
}

func TestPolicyPut(t *testing.T) {
	h, e := policyEdge(t, "")
	const live = "block: [1.2.3.4]\nlimits:\n  requests_per_second: 5\n"
	if rec := putPolicy(h, nodeID, live); rec.Code != 403 || e.applies != 0 {
		t.Fatalf("id gate: status=%d applies=%d", rec.Code, e.applies)
	}
	rec := putPolicy(h, opsID, live)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "applied") || e.rebooted {
		t.Fatalf("live: status=%d reboot=%v body=%q", rec.Code, e.rebooted, rec.Body.String())
	}
	if rec.Header().Get("ETag") != config.PolicyETag([]byte(live)) {
		t.Fatalf("etag %q", rec.Header().Get("ETag"))
	}
	if len(e.block) != 1 || e.limits.RequestsPerSecond != 5 || e.stored(t) != live || statusOf(t, h)["blocked"] != float64(1) {
		t.Fatalf("in force: block %v, limits %+v, stored %q, status %v", e.block, e.limits, e.stored(t), statusOf(t, h)["blocked"])
	}
	// The same body again is not applied again.
	if rec := putPolicy(h, opsID, live); rec.Code != 200 || !strings.Contains(rec.Body.String(), "unchanged") || e.applies != 1 {
		t.Fatalf("again: status=%d body=%q applies=%d", rec.Code, rec.Body.String(), e.applies)
	}
	// Refused before anything runs: the policy the edge had stays.
	if rec := putPolicy(h, opsID, "block: [nope]\n"); rec.Code != 400 || e.applies != 1 {
		t.Fatalf("invalid: status=%d body=%q applies=%d", rec.Code, rec.Body.String(), e.applies)
	}
	if got := getPolicy(t, h); got != live {
		t.Fatalf("get: %q", got)
	}
	const reboot = "limits:\n  max_connections: 10\n"
	rec = putPolicy(h, opsID, reboot)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "rebooting") || !e.rebooted || e.stored(t) != reboot || len(e.block) != 0 {
		t.Fatalf("boot limit: status=%d reboot=%v body=%q stored=%q block=%v", rec.Code, e.rebooted, rec.Body.String(), e.stored(t), e.block)
	}
	if rec := putPolicy(h, opsID, strings.Repeat("#", maxPolicy+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: status=%d", rec.Code)
	}
}

// A policy the edge cannot put in force is refused, and the edge keeps
// the one it had: in XDP, in the limits, on the disk, and in the status.
// One that would reboot the edge is tried the same way before it is
// stored, not at the next boot, where nothing could be sent to fix it.
func TestPolicyRefusedChangesNothing(t *testing.T) {
	const before = "block: [192.0.2.9]\nlimits:\n  requests_per_second: 2\n  request_burst: 2\n"
	const next = "block: [192.0.2.9, 198.51.100.0/24]\nlimits:\n  requests_per_second: 5\n  request_burst: 5\n"
	const nextReboot = next + "  max_connections: 10\n"
	noSpace := errors.New("write policy.yml: no space left on device")
	for _, tc := range []struct {
		name       string
		body       string
		full, half bool
		storeErr   error
	}{
		{"xdp cannot hold it", next, true, false, nil},
		{"xdp cannot hold one that reboots", nextReboot, true, false, nil},
		{"xdp fails part way", next, false, true, nil},
		{"the disk cannot store it", next, false, false, noSpace},
		{"the disk cannot store one that reboots", nextReboot, false, false, noSpace},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, e := policyEdge(t, before)
			block, limits := e.block, e.limits
			e.full, e.half, e.storeErr = tc.full, tc.half, tc.storeErr
			if rec := putPolicy(h, opsID, tc.body); rec.Code != http.StatusInternalServerError || e.rebooted {
				t.Fatalf("status=%d reboot=%v body=%q", rec.Code, e.rebooted, rec.Body.String())
			}
			if !slices.Equal(e.block, block) || e.limits != limits {
				t.Errorf("in force: block %v, limits %+v; want the previous %v, %+v", e.block, e.limits, block, limits)
			}
			if e.stored(t) != before || getPolicy(t, h) != before {
				t.Errorf("stored %q, get %q; want the previous", e.stored(t), getPolicy(t, h))
			}
			if st := statusOf(t, h); st["blocked"] != float64(1) {
				t.Errorf("status blocked %v, want the previous 1", st["blocked"])
			}
			if st, _ := statusOf(t, h)["policy_degraded"].([]any); len(st) != 0 {
				t.Errorf("policy_degraded %v: the previous policy is back whole", st)
			}
			// Once the edge can take it, the same body is applied.
			e.full, e.half, e.storeErr = false, false, nil
			if rec := putPolicy(h, opsID, tc.body); rec.Code != 200 || len(e.block) != 2 || e.stored(t) != tc.body {
				t.Fatalf("then: status=%d body=%q block=%v", rec.Code, rec.Body.String(), e.block)
			}
		})
	}
}

// A boot that could not load all of its stored policy says so in the
// status and the metrics until a policy is put. The same file again is
// applied rather than answered "unchanged": the edge runs less of it.
func TestPolicyDegraded(t *testing.T) {
	const stored = "block: [192.0.2.9]\nexempt: [198.51.100.7]\n"
	cfg := testConfig()
	p, err := config.ParsePolicy([]byte(stored))
	if err != nil {
		t.Fatal(err)
	}
	p.Block = nil
	cfg.Policy = p
	e := &fakeEdge{limits: p.Limits, file: filepath.Join(t.TempDir(), "policy.yml")}
	h := New(cfg, []byte(stored), testBoot, t.TempDir())
	h.SetApply(e.apply())
	const why = "xdp block list: no space; running with no block list until the next apply"
	h.SetDegraded([]string{why})
	degraded := func() (status []any, metric string) {
		t.Helper()
		st := statusOf(t, h)
		status, _ = st["policy_degraded"].([]any)
		body := serve(t, h, config.OpsMetricsPath, logsID).Body.String()
		_, rest, _ := strings.Cut(body, "\nfortressedge_policy_degraded ")
		metric, _, _ = strings.Cut(rest, "\n")
		return status, metric
	}

	if st, m := degraded(); len(st) != 1 || st[0] != why || m != "1" || getPolicy(t, h) != stored {
		t.Fatalf("after boot: policy_degraded %v, metric %q, get %q", st, m, getPolicy(t, h))
	}
	e.full = true
	if rec := putPolicy(h, opsID, stored); rec.Code != http.StatusInternalServerError {
		t.Fatalf("refused: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if st, m := degraded(); len(st) != 1 || m != "1" {
		t.Fatalf("after a refused put: policy_degraded %v, metric %q", st, m)
	}
	e.full = false
	if rec := putPolicy(h, opsID, stored); rec.Code != 200 || !strings.Contains(rec.Body.String(), "applied") || len(e.block) != 1 {
		t.Fatalf("same file: status=%d body=%q block=%v", rec.Code, rec.Body.String(), e.block)
	}
	if st, m := degraded(); st == nil || len(st) != 0 || m != "0" || statusOf(t, h)["blocked"] != float64(1) {
		t.Fatalf("after a put: policy_degraded %v, metric %q", st, m)
	}
	if rec := putPolicy(h, opsID, stored); !strings.Contains(rec.Body.String(), "unchanged") {
		t.Fatalf("then again: %q", rec.Body.String())
	}
}

// A step that cannot be undone leaves the edge running neither policy
// whole, and the status says so.
func TestPolicyUndoFailureIsDegraded(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	runs := 0
	h.SetApply(Apply{
		Steps: []Step{func(config.Policy) error {
			if runs++; runs > 1 {
				return errors.New("xdp block list: restore failed")
			}
			return nil
		}},
		Store: func([]byte) error { return errors.New("no space left on device") },
	})
	rec := putPolicy(h, opsID, "block: [192.0.2.9]\n")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "no space") || !strings.Contains(rec.Body.String(), "restore failed") {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if st, _ := statusOf(t, h)["policy_degraded"].([]any); len(st) != 1 || !strings.Contains(st[0].(string), "restore failed") {
		t.Fatalf("policy_degraded %v", st)
	}
}

// An edge nobody applied a policy to has an empty one.
func TestPolicyGetNone(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	rec := serve(t, h, config.OpsPolicyPath, opsID)
	if rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("ETag") != config.PolicyETag(nil) {
		t.Fatalf("status=%d body=%q etag=%q", rec.Code, rec.Body.String(), rec.Header().Get("ETag"))
	}
}

func TestMetrics(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	h.SetMetrics(func(w *metrics.Writer) {
		w.Family("fortressedge_test_total", "counter", "A test.")
		w.Int("fortressedge_test_total", 3, "site", "a.example.com")
	})
	rec := serve(t, h, config.OpsMetricsPath, logsID)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != metrics.ContentType {
		t.Fatalf("status=%d type=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE fortressedge_build_info gauge\nfortressedge_build_info{version=",
		"\nfortressedge_boot_time_seconds ",
		"# TYPE fortressedge_test_total counter\nfortressedge_test_total{site=\"a.example.com\"} 3\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
}

// With a collector set, a read of status, metrics or logs is the
// location's: the edge checks the caller, then passes the read on, unless
// the caller asks for this edge itself.
func TestReadsGoToTheCollector(t *testing.T) {
	var path, caller string
	calls := 0
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		path, caller = r.URL.RequestURI(), r.Header.Get("X-Fortress-Caller")
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("X-Log-Cursor", "a=boot:7")
		w.Header().Set("X-Log-Gap", "true")
		_, _ = io.WriteString(w, "the location's\n")
	}))
	defer col.Close()
	host, port, _ := strings.Cut(col.Listener.Addr().String(), ":")
	dir := t.TempDir()
	writeLogs(t, dir, "# boot "+testBoot+"\none\n", "")
	cfg := testConfig()
	cfg.Gateway = netip.MustParseAddr(host)
	cfg.Collector = "gateway:" + port
	h := New(cfg, nil, testBoot, dir)

	rec := serve(t, h, config.OpsAccessPath+"?cursor=a%3Dboot%3A3", logsID)
	if rec.Code != http.StatusOK || rec.Body.String() != "the location's\n" {
		t.Fatalf("access: %d %q", rec.Code, rec.Body)
	}
	if path != config.OpsAccessPath+"?cursor=a%3Dboot%3A3" || caller != logsID {
		t.Fatalf("the collector got %q from %q", path, caller)
	}
	if rec.Header().Get("X-Log-Cursor") != "a=boot:7" || rec.Header().Get("X-Log-Gap") != "true" ||
		rec.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("headers: %v", rec.Header())
	}

	// For this edge itself, and what is the edge's own: answered here.
	calls = 0
	if rec := serve(t, h, config.OpsLogsPath+"?"+config.OpsSelf, logsID); rec.Body.String() != "# boot "+testBoot+"\none\n" {
		t.Fatalf("logs?self: %q", rec.Body)
	}
	if rec := serve(t, h, config.OpsPolicyPath, logsID); rec.Code != http.StatusOK {
		t.Fatalf("policy: %d", rec.Code)
	}
	// A dark node may not read, with or without a collector.
	if rec := serve(t, h, config.OpsStatusPath, nodeID); rec.Code != http.StatusForbidden {
		t.Fatalf("a dark node's read: %d", rec.Code)
	}
	if calls != 0 {
		t.Fatalf("the collector was asked %d times", calls)
	}

	// A collector that does not answer: an error, not this edge's own answer.
	col.Close()
	if rec := serve(t, h, config.OpsStatusPath, opsID); rec.Code != http.StatusBadGateway {
		t.Fatalf("collector away: %d %q", rec.Code, rec.Body)
	}
}

// cursor=oldest starts at the oldest file kept, and every answer names the
// file its bytes are from.
func TestOldestCursorAndFileHeader(t *testing.T) {
	dir := t.TempDir()
	writeLogs(t, dir, "# boot "+testBoot+"\nnew\n", "# boot old-boot\nold\n")
	h := New(testConfig(), nil, testBoot, dir)

	rec := serve(t, h, config.OpsLogsPath+"?cursor=oldest", logsID)
	if rec.Body.String() != "# boot old-boot\nold\n" || rec.Header().Get("X-Log-File") != "old-boot" ||
		rec.Header().Get("X-Log-Cursor") != testBoot+":0" || rec.Header().Get("X-Log-Gap") != "" {
		t.Fatalf("oldest: %q, file %q, cursor %q", rec.Body, rec.Header().Get("X-Log-File"), rec.Header().Get("X-Log-Cursor"))
	}
	rec = serve(t, h, config.OpsLogsPath+"?cursor="+url.QueryEscape(rec.Header().Get("X-Log-Cursor")), logsID)
	if rec.Body.String() != "# boot "+testBoot+"\nnew\n" || rec.Header().Get("X-Log-File") != testBoot {
		t.Fatalf("then the current file: %q, file %q", rec.Body, rec.Header().Get("X-Log-File"))
	}

	// With no older file, the oldest is the current one.
	if err := os.Remove(filepath.Join(dir, "previous.log")); err != nil {
		t.Fatal(err)
	}
	rec = serve(t, h, config.OpsLogsPath+"?cursor=oldest", logsID)
	if rec.Body.String() != "# boot "+testBoot+"\nnew\n" || rec.Header().Get("X-Log-File") != testBoot || rec.Header().Get("X-Log-Gap") != "" {
		t.Fatalf("oldest with one file: %q, file %q", rec.Body, rec.Header().Get("X-Log-File"))
	}
}
