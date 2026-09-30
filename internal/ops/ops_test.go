package ops

import (
	"bufio"
	"bytes"
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
	h.SetApply(func([]byte) (Outcome, error) { return Outcome{}, nil }, nil)
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

func TestPolicyPut(t *testing.T) {
	h := New(testConfig(), nil, testBoot, t.TempDir())
	var applied []string
	var rebooted bool
	h.SetApply(func(b []byte) (Outcome, error) {
		applied = append(applied, string(b))
		switch {
		case bytes.Contains(b, []byte("bad")):
			return Outcome{}, &config.InvalidError{Err: errors.New("policy.yml: bad")}
		case bytes.Contains(b, []byte("max_connections")):
			return Outcome{Reboot: true}, nil
		}
		return Outcome{}, nil
	}, func() { rebooted = true })
	put := func(id, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, policyRequest(http.MethodPut, config.OpsPolicyPath, id, body))
		return rec
	}

	if rec := put(nodeID, "block: [1.2.3.4]\n"); rec.Code != 403 || len(applied) != 0 {
		t.Fatalf("id gate: status=%d applied=%q", rec.Code, applied)
	}
	rec := put(opsID, "block: [1.2.3.4]\n")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "applied") || rebooted {
		t.Fatalf("live: status=%d reboot=%v body=%q", rec.Code, rebooted, rec.Body.String())
	}
	if rec.Header().Get("ETag") != config.PolicyETag([]byte("block: [1.2.3.4]\n")) {
		t.Fatalf("etag %q", rec.Header().Get("ETag"))
	}
	// The same body again is not applied again.
	if rec := put(opsID, "block: [1.2.3.4]\n"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "unchanged") || len(applied) != 1 {
		t.Fatalf("again: status=%d body=%q applied=%q", rec.Code, rec.Body.String(), applied)
	}
	// Refused: the policy the edge had stays.
	if rec := put(opsID, "bad\n"); rec.Code != 400 {
		t.Fatalf("invalid: status=%d body=%q", rec.Code, rec.Body.String())
	}
	get := httptest.NewRecorder()
	h.ServeHTTP(get, request(config.OpsPolicyPath, logsID))
	if get.Code != 200 || get.Body.String() != "block: [1.2.3.4]\n" || get.Header().Get("ETag") != config.PolicyETag([]byte("block: [1.2.3.4]\n")) {
		t.Fatalf("get: status=%d body=%q", get.Code, get.Body.String())
	}
	rec = put(opsID, "limits:\n  max_connections: 10\n")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "rebooting") || !rebooted {
		t.Fatalf("boot limit: status=%d reboot=%v body=%q", rec.Code, rebooted, rec.Body.String())
	}
	if rec := put(opsID, strings.Repeat("#", maxPolicy+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: status=%d", rec.Code)
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
