//go:build e2e

package e2e

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	gotestwafBin = flag.String("gotestwaf", "", "GoTestWAF binary; empty skips TestGoTestWAF (make waf-bench sets it)")
	gotestwafSrc = flag.String("gotestwaf-src", "", "GoTestWAF's source, for its testcases and config.yaml")
)

const gtwHost = "gotestwaf.example.com"

// TestGoTestWAF runs Wallarm's GoTestWAF against an edge: its payloads
// (SQL, NoSQL, LDAP, mail, shell, template and XML injection, XSS, RCE,
// path traversal, CRLF, and OWASP API cases) in every encoding and every
// place in a request it knows, and its false-positive set. GoTestWAF
// scores how much a WAF blocks (403) and passes; with no WAF yet the
// score is the floor, and it becomes the WAF's certification. Its JSON
// and HTML reports go to -bench, its summary is pinned in
// testdata/gotestwaf-baseline.json, and what reaches the site must be
// clean.
func TestGoTestWAF(t *testing.T) {
	if *gotestwafBin == "" {
		t.Skip("make waf-bench runs it")
	}
	origin := newWireOrigin(t, false)
	e := newEdge(t, benchSize(), gtwHost, origin)
	proxy := connectProxy(t, net.JoinHostPort(e.vm.Addr, strconv.Itoa(e.vm.HTTPS)))
	dir := reports(t)

	log, err := os.Create(filepath.Join(dir, "gotestwaf.log"))
	require.NoError(t, err)
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), *gotestwafBin,
		"--url", "https://"+gtwHost+"/",
		"--proxy", proxy,
		"--testCasesPath", filepath.Join(*gotestwafSrc, "testcases"),
		"--configPath", filepath.Join(*gotestwafSrc, "config.yaml"),
		"--wafName", "fortressedge",
		"--noEmailReport", "--skipWAFBlockCheck", "--skipWAFIdentification", "--hideArgsInReport",
		"--reportFormat", "json,html", "--reportPath", dir, "--reportName", "gotestwaf",
		"--sendDelay", "0", "--randomDelay", "1", // 0 panics: rand.Intn(0)
		"--workers", "16", "--maxIdleConns", "16",
		"--logFormat", "text")
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = log, log
	require.NoError(t, cmd.Run(), "gotestwaf; see gotestwaf.log")

	b, err := os.ReadFile(filepath.Join(dir, "gotestwaf.json"))
	require.NoError(t, err)
	var report struct {
		Summary map[string]gtwTests `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(b, &report))
	require.Contains(t, report.Summary, "true_positive_tests")
	var rows [][]string
	for _, kind := range []string{"true_positive_tests", "true_negative_tests"} {
		s := report.Summary[kind]
		t.Logf("%s: score %.2f%%, %+v", kind, s.Score, s.Summary)
		rows = append(rows, []string{kind, fmt.Sprintf("%.2f%%", s.Score), strconv.Itoa(s.Summary.Sent),
			strconv.Itoa(s.Summary.Blocked), strconv.Itoa(s.Summary.Bypassed), strconv.Itoa(s.Summary.Unresolved),
			strconv.Itoa(s.Summary.Failed)})
	}
	md := fmt.Sprintf("### GoTestWAF %s\n\nBlocked is a 403. Unresolved is any other refusal, such as the edge's 400 for a "+
		"dot segment in the path.\n\n", filepath.Base(*gotestwafSrc)) +
		markdown([]string{"tests", "score", "sent", "blocked", "bypassed", "unresolved", "failed"}, rows)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gotestwaf-summary.md"), []byte(md), 0o644))

	assert.Zero(t, origin.bad.Load(), "requests reached the site malformed: %s", origin.problems())
	t.Logf("site: %d requests, %d partial", origin.seq.Load(), origin.partial.Load())
	baseline(t, "gotestwaf-baseline.json", report.Summary)
}

// gtwTests is one half of GoTestWAF's summary: the attacks
// (true_positive_tests), which a WAF should block, or the legitimate
// requests (true_negative_tests), which it should pass.
type gtwTests struct {
	Score   float64    `json:"score"`
	Summary gtwSummary `json:"summary"`
	AppSec  gtwSummary `json:"app_sec"`
	APISec  gtwSummary `json:"api_sec"`
	// TestSets is test set, then test case, then its counts.
	TestSets map[string]map[string]gtwCase `json:"test_sets"`
}

type gtwSummary struct {
	Sent       int `json:"total_sent"`
	Resolved   int `json:"resolved_tests"`
	Blocked    int `json:"blocked_tests"`
	Bypassed   int `json:"bypassed_tests"`
	Unresolved int `json:"unresolved_tests"`
	Failed     int `json:"failed_tests"`
}

type gtwCase struct {
	Sent       int `json:"sent"`
	Blocked    int `json:"blocked"`
	Bypassed   int `json:"bypassed"`
	Unresolved int `json:"unresolved"`
	Failed     int `json:"failed"`
}
