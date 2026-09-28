//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

const (
	wireHost = "wire.example.com"
	// quiet is how long an exchange waits for more once it has the
	// responses it expects.
	quiet = 500 * time.Millisecond
)

// TestHostileRequests sends what attackers and broken clients send:
// request smuggling, malformed framing and headers, ambiguous paths, and
// HTTP/2 that only a downgrade to HTTP/1.1 could make dangerous. The site
// behind the edge reads each request off the socket (wireOrigin), so the
// test sees what a gateway would. Whatever the edge does with a request,
// three things must hold: what reaches the site is one clean HTTP/1.1
// request per request the edge accepted, never bytes of another; a
// request the edge refuses reaches nothing; and the next visitor's
// request (the canary) arrives intact on the same pooled connection.
// Each vector also pins what the visitor gets back, so a change in the
// edge or in Go's parsers shows up here.
func TestHostileRequests(t *testing.T) {
	t.Parallel()
	origin := newWireOrigin(t, true)
	e := newEdge(t, edgeSize{}, wireHost, origin)
	h := &hostile{vm: e.vm, caFile: e.caFile, web: e.web, origin: origin}
	h.origin.take()

	step(t, "HTTP/1.1", func(t *testing.T) {
		for i, v := range h1Vectors {
			t.Run(v.name, func(t *testing.T) { h.runH1(t, i, v) })
		}
	})
	step(t, "HTTP/2", func(t *testing.T) {
		for i, v := range h2Vectors {
			t.Run(v.name, func(t *testing.T) { h.runH2(t, 1000+i, v) })
		}
	})
}

// edge is an edge VM with one site published through it.
type edge struct {
	vm     *lab.VM
	caFile string       // what the edge's certificates chain to
	web    *http.Client // a visitor
	ops    *http.Client // an operator, for /~!ops/status
}

// edgeSize is an edge VM's vCPUs and memory (zeros are os/qemu.sh's
// defaults), and whether it is on the -tap device instead of QEMU's
// user-mode network.
type edgeSize struct {
	cpus, memMiB int
	tap          bool
	tunnel       string // the dark node's: wss (the default) or quic
	iso          string // the ISO to boot; empty is the suite's -iso
}

// newEdge boots an edge of size sz and publishes origin through it as
// site. The visitor limits are off: every request comes from one
// address, and what these tests check does not depend on them.
func newEdge(t *testing.T, sz edgeSize, site string, origin *wireOrigin) *edge {
	t.Helper()
	le := lab.BootEdge(t, lab.EdgeOptions{CPUs: sz.cpus, MemMiB: sz.memMiB, Tap: sz.tap, ISO: sz.iso,
		Policy: "limits:\n  requests_per_second: 0\n  connections_per_source: 0\n  new_connections_per_second: 0\n"})
	visitor := le.VM.Visitor()
	origin.visitor.Store(&visitor)
	e := &edge{vm: le.VM, caFile: le.Roots, web: le.Web, ops: le.Ops}
	nodeCrt, nodeKey := le.Cert(ca.RoleNode, "node1")
	le.VM.Publish(t, cmp.Or(sz.tunnel, "wss"), e.caFile, nodeCrt, nodeKey, origin.Port, site)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		resp, _, err := lab.Get(e.web, "https://"+site+"/")
		require.NoError(c, err)
		assert.Equal(c, http.StatusOK, resp.StatusCode)
	}, lab.Until(t), lab.Tick)
	return e
}

type hostile struct {
	vm     *lab.VM
	caFile string
	web    *http.Client
	origin *wireOrigin
}

// reaches is what a vector must deliver to the site.
type reaches struct {
	arrive int // whole requests, each clean
	// maybe more whole requests may arrive: HTTP/2 finds some faults in
	// the DATA that follows the headers, and the edge may have proxied
	// the request by then.
	maybe int
	// cut is how many requests the edge may give up on partway, so the
	// site sees part of one and a closed connection. That part can come
	// late, even after the next vector began, so it is an upper bound.
	cut int
	uri string // the first arrival's target, when set
}

// h1Vector is raw bytes on one connection, TLS with the site's name
// unless plain, which sends them to port 80.
type h1Vector struct {
	name  string
	raw   string
	plain bool
	// want is the status of each response the visitor reads, in order;
	// empty is none at all.
	want []int
	reaches
}

func (h *hostile) runH1(t *testing.T, i int, v h1Vector) {
	var c net.Conn
	if v.plain {
		var err error
		c, err = net.DialTimeout("tcp", net.JoinHostPort(h.vm.Addr, strconv.Itoa(h.vm.HTTP)), lab.Attempt)
		require.NoError(t, err)
		defer c.Close()
	} else {
		c = h.vm.DialTLS(t, wireHost, h.caFile)
	}
	got := statuses(exchange(c, []byte(v.raw), len(v.want)))
	assert.Equal(t, v.want, got, "statuses the visitor read")
	target := ""
	if f := strings.Fields(strings.SplitN(v.raw, "\n", 2)[0]); len(f) > 1 {
		target = f[1]
	}
	h.settle(t, i, target, v.reaches)
}

// exchange writes raw to c and returns what comes back: until the edge
// closes the connection, or, once want responses are in, until it has
// been quiet a moment. A busy host gets lab.Attempt for each read.
func exchange(c net.Conn, raw []byte, want int) []byte {
	c.SetWriteDeadline(time.Now().Add(lab.Attempt))
	c.Write(raw) // a refusal may close the connection before all of raw is written
	var got []byte
	buf := make([]byte, 32<<10)
	for {
		wait := lab.Attempt
		if want > 0 && len(statuses(got)) >= want {
			wait = quiet
		}
		c.SetReadDeadline(time.Now().Add(wait))
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			return got
		}
	}
}

// statuses parses b as HTTP/1.1 responses and returns their status codes.
func statuses(b []byte) []int {
	br := bufio.NewReader(bytes.NewReader(b))
	out := []int{}
	for {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return out
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out = append(out, resp.StatusCode)
	}
}

// settle sends the canary, a plain request for vector i's site on the
// edge's pooled connections, then checks what reached the site: the
// vector's requests, then the canary intact, then nothing. The canary
// goes first because a request the edge gave up on can reach the site
// after the visitor already has its answer; target, the vector's own,
// tells its part of one from an earlier vector's.
func (h *hostile) settle(t *testing.T, i int, target string, want reaches) {
	uri := "/canary?n=" + strconv.Itoa(i)
	resp, body, err := lab.Get(h.web, "https://"+wireHost+uri)
	require.NoError(t, err, "canary")
	require.Equal(t, http.StatusOK, resp.StatusCode, "canary")
	var r reply
	require.NoError(t, json.Unmarshal([]byte(body), &r), "canary reply %q", body)
	assert.Equal(t, uri, r.URI, "canary")
	assert.Empty(t, r.Problems, "canary")

	var whole []string
	cut, canary := 0, false
	for _, a := range h.origin.take() {
		switch {
		case a.Err != "" && a.URI == "":
			t.Errorf("bytes at the site that start no request (%s): %q", a.Err, clip(a.Raw))
		case a.Err != "" && a.URI == target:
			cut++
			t.Logf("partial request at the site (%s): %q", a.Err, clip(a.Raw))
		case a.Err != "":
			t.Logf("partial request at the site from an earlier vector (%s): %q", a.Err, clip(a.Raw))
		case canary:
			t.Errorf("request at the site after the canary: %q", clip(a.Raw))
		case a.URI == uri:
			canary = true
		default:
			whole = append(whole, a.Method+" "+a.URI)
			assert.Empty(t, a.Problems, "request at the site: %q", clip(a.Raw))
		}
	}
	assert.True(t, canary, "the canary never reached the site")
	for _, w := range whole {
		assert.NotContains(t, w, "/smuggled", "a smuggled request reached the site")
	}
	if want.maybe > 0 {
		assert.GreaterOrEqual(t, len(whole), want.arrive, "requests at the site: %q", whole)
		assert.LessOrEqual(t, len(whole), want.arrive+want.maybe, "requests at the site: %q", whole)
	} else {
		assert.Equal(t, want.arrive, len(whole), "requests at the site: %q", whole)
	}
	assert.LessOrEqual(t, cut, want.cut, "partial requests at the site")
	if want.uri != "" && len(whole) > 0 {
		_, got, _ := strings.Cut(whole[0], " ")
		assert.Equal(t, want.uri, got, "target at the site")
	}
}

func clip(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

// Vectors, after PortSwigger's request smuggling research, defparam's
// smuggler, h2csmuggler and the HTTP Garden's parser discrepancies,
// written down here rather than vendored. The site is wire.example.com.
var h1Vectors = []h1Vector{
	// The baseline: the site reads what a well-behaved client sent.
	{name: "GET", raw: "GET /plain?a=1 HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/plain?a=1"}},
	{name: "POST with Content-Length", raw: "POST /cl HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: 5\r\n\r\nhello",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "chunked POST", raw: "POST /te HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "two pipelined requests", raw: "GET /one HTTP/1.1\r\nHost: wire.example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200, 200}, reaches: reaches{arrive: 2, uri: "/one"}},
	{name: "Expect 100-continue", raw: "POST /expect HTTP/1.1\r\nHost: wire.example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello",
		want: []int{100, 200}, reaches: reaches{arrive: 1}},
	{name: "absolute-form target for the site", raw: "GET https://wire.example.com/abs HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/abs"}},
	{name: "bare LF line endings", raw: "GET /lf HTTP/1.1\nHost: wire.example.com\n\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/lf"}},

	// Framing: two ways to read where the body ends. With both headers,
	// net/http goes by chunked and drops Content-Length (RFC 9112 6.3
	// allows that), and the site gets the request framed once, anew: the
	// rest of the visitor's bytes stay on the visitor's connection.
	{name: "CL.TE: Content-Length and chunked", raw: "POST /clte HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nX: X",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/clte"}},
	{name: "TE.CL: chunked and a short Content-Length", raw: "POST /tecl HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n32\r\nGET /smuggled HTTP/1.1\r\nHost: wire.example.com\r\n\r\n\r\n0\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/tecl"}},
	{name: "two different Content-Lengths", raw: "POST /cl2 HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: 5\r\nContent-Length: 44\r\n\r\nhelloGET /smuggled HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{400}},
	{name: "two equal Content-Lengths", raw: "POST /cl2same HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "Content-Length with a sign", raw: "POST /clsign HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: +5\r\n\r\nhello",
		want: []int{400}},
	{name: "Content-Length as a list", raw: "POST /cllist HTTP/1.1\r\nHost: wire.example.com\r\nContent-Length: 5, 5\r\n\r\nhello",
		want: []int{400}},
	{name: "Transfer-Encoding chunked, identity", raw: "POST /te2 HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n",
		want: []int{501}},
	{name: "Transfer-Encoding twice", raw: "POST /tete HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		want: []int{501}},
	{name: "Transfer-Encoding xchunked", raw: "POST /tex HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
		want: []int{501}},
	{name: "Transfer-Encoding in capitals", raw: "POST /teuc HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: CHUNKED\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "Transfer-Encoding with a space before the colon", raw: "POST /tesp HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
		want: []int{400}},
	// net/http unfolds obs-fold into a space before it reads the header,
	// as RFC 9112 5.2 allows, so the site gets one plain line.
	{name: "Transfer-Encoding folded onto the next line", raw: "POST /tefold HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "Transfer-Encoding on HTTP/1.0", raw: "POST /te10 HTTP/1.0\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	// A broken chunk is found once the edge is already streaming the body
	// to the site: the site gets a request cut short and a closed
	// connection, and the visitor gets 502, though the fault is its own.
	{name: "chunk size with 0x", raw: "POST /ch0x HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n",
		want: []int{502}, reaches: reaches{cut: 1}},
	{name: "chunk size that overflows", raw: "POST /chbig HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffff\r\nhello\r\n0\r\n\r\n",
		want: []int{502}, reaches: reaches{cut: 1}},
	{name: "chunk without its CRLF", raw: "POST /chcrlf HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloGET /smuggled HTTP/1.1\r\n\r\n0\r\n\r\n",
		want: []int{502}, reaches: reaches{cut: 1}},
	{name: "chunk size ended by a bare LF", raw: "POST /chlf HTTP/1.1\r\nHost: wire.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n",
		want: []int{502}, reaches: reaches{cut: 1}},

	// Header syntax.
	{name: "bare CR in a header value", raw: "GET /cr HTTP/1.1\r\nHost: wire.example.com\r\nX-A: a\rX-B: b\r\n\r\n",
		want: []int{400}},
	{name: "NUL in a header value", raw: "GET /nul HTTP/1.1\r\nHost: wire.example.com\r\nX-A: a\x00b\r\n\r\n",
		want: []int{400}},
	{name: "space in a header name", raw: "GET /sp HTTP/1.1\r\nHost: wire.example.com\r\nX A: b\r\n\r\n",
		want: []int{400}},
	{name: "header line without a colon", raw: "GET /nocolon HTTP/1.1\r\nHost: wire.example.com\r\nX-A b\r\n\r\n",
		want: []int{400}},
	{name: "first header line folded", raw: "GET /fold1 HTTP/1.1\r\n Host: wire.example.com\r\n\r\n",
		want: []int{400}},
	{name: "folded header value", raw: "GET /fold HTTP/1.1\r\nHost: wire.example.com\r\nX-A: a\r\n b\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "obs-text in a header value", raw: "GET /obs HTTP/1.1\r\nHost: wire.example.com\r\nX-A: caf\xe9\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "headers over 64 KiB", raw: "GET /big HTTP/1.1\r\nHost: wire.example.com\r\nX-A: " + strings.Repeat("a", 70<<10) + "\r\n\r\n",
		want: []int{431}},
	{name: "the visitor names forwarded headers hop-by-hop", raw: "GET /hop HTTP/1.1\r\nHost: wire.example.com\r\nConnection: X-Forwarded-For, X-Real-IP, X-Forwarded-Proto\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "forged forwarded headers", raw: "GET /fwd HTTP/1.1\r\nHost: wire.example.com\r\nForwarded: for=198.51.100.7\r\nX-Forwarded-For: 198.51.100.7\r\nX-Real-IP: 198.51.100.7\r\nX-Forwarded-Proto: http\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "h2c upgrade", raw: "GET /h2c HTTP/1.1\r\nHost: wire.example.com\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},

	// Host.
	{name: "no Host on HTTP/1.1", raw: "GET /nohost HTTP/1.1\r\n\r\n",
		want: []int{400}},
	{name: "no Host on HTTP/1.0", raw: "GET /nohost10 HTTP/1.0\r\n\r\n",
		want: []int{}},
	{name: "two Host headers", raw: "GET /host2 HTTP/1.1\r\nHost: wire.example.com\r\nHost: other.example.com\r\n\r\n",
		want: []int{400}},
	{name: "Host with userinfo", raw: "GET /hostat HTTP/1.1\r\nHost: evil@wire.example.com\r\n\r\n",
		want: []int{400}},
	{name: "absolute-form target for another name", raw: "GET https://nobody.example.com/ HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{}},

	// The request line.
	{name: "two spaces in the request line", raw: "GET  /sp2 HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{400}},
	{name: "space in the target", raw: "GET /a b HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{400}},
	{name: "HTTP/0.9", raw: "GET /\r\n\r\n",
		want: []int{400}},
	{name: "HTTP/1.2", raw: "GET /v12 HTTP/1.2\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "HTTP/2.0 on an HTTP/1 connection", raw: "GET /v20 HTTP/2.0\r\nHost: wire.example.com\r\n\r\n",
		want: []int{505}},
	{name: "lower-case method", raw: "get /lower HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1}},
	{name: "method that is not a token", raw: "G(T /tok HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{400}},
	{name: "TRACE", raw: "TRACE /trace HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{405}},
	{name: "TRACK", raw: "TRACK /track HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{405}},
	{name: "CONNECT", raw: "CONNECT wire.example.com:443 HTTP/1.1\r\nHost: wire.example.com:443\r\n\r\n", want: []int{405}},
	// A question for the server, which the edge answers for the names it
	// serves: proxied, it would reach the site as OPTIONS /*.
	{name: "OPTIONS *", raw: "OPTIONS * HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}},
	{name: "OPTIONS * for a name the edge does not serve", raw: "OPTIONS * HTTP/1.1\r\nHost: nobody.example.com\r\n\r\n",
		want: []int{}},
	{name: "target over 16 KiB", raw: "GET /" + strings.Repeat("a", 17<<10) + " HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{414}},

	// Paths a gateway could resolve another way.
	{name: "dot-dot segment", raw: "GET /a/../etc/passwd HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "encoded dot-dot", raw: "GET /a/%2e%2e/etc HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "half-encoded dot-dot", raw: "GET /a/.%2E/etc HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "dot-dot with an encoded slash", raw: "GET /a/..%2fetc HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "dot segment", raw: "GET /a/./b HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "backslash", raw: "GET /a\\..\\etc HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "encoded backslash", raw: "GET /a%5c..%5cetc HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "encoded NUL", raw: "GET /a%00.jpg HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "target not starting with a slash", raw: "GET a/b HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: []int{400}},
	{name: "double-encoded dot-dot passes as literal text", raw: "GET /a/%252e%252e/etc HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/a/%252e%252e/etc"}},
	// Tomcat and Spring drop ";..." path parameters before they resolve
	// dot segments, so behind the edge this can read as /admin.
	{name: "dot-dot with a path parameter", raw: "GET /a/..;/admin HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/a/..;/admin"}},
	{name: "empty segments", raw: "GET //a//b HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "//a//b"}},
	{name: "fragment in the target", raw: "GET /frag#x HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/frag%23x"}},
	{name: "raw UTF-8 in the path", raw: "GET /caf\xc3\xa9 HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/caf%C3%A9"}},
	// net/http/httputil re-encodes a query with a semicolon or a broken
	// escape: sorted, and what does not parse dropped.
	{name: "semicolon in the query", raw: "GET /q?b=2;a=1&c=3 HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/q?c=3"}},
	{name: "broken escape in the query", raw: "GET /q?a=%zz&b=1 HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{200}, reaches: reaches{arrive: 1, uri: "/q?b=1"}},

	// Port 80 answers only the names HTTPS serves, with a redirect.
	{name: "plain HTTP: redirect", plain: true, raw: "GET /x HTTP/1.1\r\nHost: wire.example.com\r\n\r\n",
		want: []int{308}},
	{name: "plain HTTP: a name the edge does not serve", plain: true, raw: "GET / HTTP/1.1\r\nHost: 10.0.2.15\r\n\r\n",
		want: []int{}},
	{name: "plain HTTP: OPTIONS * for the address", plain: true, raw: "OPTIONS * HTTP/1.1\r\nHost: 10.0.2.15\r\n\r\n",
		want: []int{}},
	// net/http answers a request it cannot parse before any edge code
	// runs, so these get its 400 though no name was given.
	{name: "plain HTTP: no Host", plain: true, raw: "GET / HTTP/1.1\r\n\r\n",
		want: []int{400}},
	{name: "plain HTTP: garbage", plain: true, raw: "\x16\x03\x01\x00\x05hello\r\n\r\n",
		want: []int{400}},
}

// h2Vector is one HTTP/2 stream: header fields exactly as given (HPACK
// carries any bytes, so these can break rules a real client keeps), then
// data, if any, ending the stream.
type h2Vector struct {
	name   string
	fields [][2]string
	data   string
	// want is the status the stream ends with, "reset" for RST_STREAM, or
	// "goaway" when the edge closes the connection; "|" separates
	// outcomes that are all right.
	want string
	reaches
}

// racyReset is how a stream ends that HTTP/2 resets for DATA after the
// headers: reset, or answered first when the site was quicker.
const racyReset = "reset|200 reset|200"

// get is the pseudo-headers of a GET for path on the site, then extra.
func get(path string, extra ...[2]string) [][2]string {
	return append([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", wireHost}, {":path", path}}, extra...)
}

func post(path string, extra ...[2]string) [][2]string {
	return append([][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", wireHost}, {":path", path}}, extra...)
}

var h2Vectors = []h2Vector{
	{name: "GET", fields: get("/h2"), want: "200", reaches: reaches{arrive: 1, uri: "/h2"}},
	{name: "POST with content-length", fields: post("/h2cl", [2]string{"content-length", "5"}), data: "hello",
		want: "200", reaches: reaches{arrive: 1}},
	{name: "POST without content-length", fields: post("/h2nocl"), data: "hello",
		want: "200", reaches: reaches{arrive: 1}},
	{name: "Host instead of :authority", fields: [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/h2host"}, {"host", wireHost}},
		want: "200", reaches: reaches{arrive: 1}},
	{name: ":authority and a different host", fields: get("/h2both", [2]string{"host", "nobody.example.com"}),
		want: "200", reaches: reaches{arrive: 1}},
	{name: "te: trailers", fields: get("/h2te", [2]string{"te", "trailers"}), want: "200", reaches: reaches{arrive: 1}},

	// H2.CL and H2.TE: framing a downgrade to HTTP/1.1 could read another
	// way. Fields HTTP/2 forbids get net/http's 400.
	// The extra DATA resets the stream. If the edge proxied the headers
	// first, the site got one clean, empty POST, never the payload.
	{name: "H2.CL: body longer than content-length", fields: post("/h2cl0", [2]string{"content-length", "0"}),
		data: "GET /smuggled HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: racyReset, reaches: reaches{maybe: 1}},
	// Found only at the end of the stream, once the body is on its way to
	// the site: as with a broken chunk, 502 and a request cut short.
	{name: "body shorter than content-length", fields: post("/h2short", [2]string{"content-length", "10"}), data: "hello",
		want: "502", reaches: reaches{cut: 1}},
	{name: "H2.TE: transfer-encoding chunked", fields: post("/h2tec", [2]string{"transfer-encoding", "chunked"}),
		data: "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: wire.example.com\r\n\r\n", want: "400"},
	// net/http's HTTP/2 server reads a content-length it cannot parse as
	// 0 (HTTP/1.1 answers 400), so this goes as H2.CL does.
	{name: "content-length that is not a number", fields: post("/h2clx", [2]string{"content-length", "5x"}), data: "hello",
		want: racyReset, reaches: reaches{maybe: 1}},
	{name: "connection header", fields: get("/h2conn", [2]string{"connection", "close"}), want: "400"},
	{name: "upgrade header", fields: get("/h2up", [2]string{"upgrade", "h2c"}), want: "400"},
	{name: "te other than trailers", fields: get("/h2tegz", [2]string{"te", "gzip"}), want: "400"},

	// Field syntax HTTP/1.1 would read as more headers or another request.
	{name: "CRLF in a header value", fields: get("/h2crlf", [2]string{"x-a", "a\r\nTransfer-Encoding: chunked"}), want: "reset"},
	{name: "LF in a header value", fields: get("/h2lf", [2]string{"x-a", "a\nx-b: b"}), want: "reset"},
	{name: "colon in a header name", fields: get("/h2colon", [2]string{"x-a:b", "c"}), want: "reset"},
	{name: "space in a header name", fields: get("/h2sp", [2]string{"x a", "b"}), want: "reset"},
	{name: "upper-case header name", fields: get("/h2upper", [2]string{"X-Upper", "b"}), want: "reset"},
	{name: "CRLF in :path", fields: get("/h2 HTTP/1.1\r\nHost: wire.example.com\r\n\r\nGET /smuggled"), want: "reset"},
	// net/http takes it and the edge sends it on escaped.
	{name: "space in :path", fields: get("/a b"), want: "200", reaches: reaches{arrive: 1, uri: "/a%20b"}},
	{name: "CRLF in :method", fields: [][2]string{{":method", "GET /smuggled HTTP/1.1\r\nX:"}, {":scheme", "https"}, {":authority", wireHost}, {":path", "/"}},
		want: "reset"},
	{name: "CRLF in :authority", fields: [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", wireHost + "\r\nX: y"}, {":path", "/"}},
		want: "reset"},
	{name: "pseudo-header after a regular one", fields: [][2]string{{":method", "GET"}, {"x-a", "b"}, {":scheme", "https"}, {":authority", wireHost}, {":path", "/"}},
		want: "reset"},
	{name: "two :path", fields: get("/h2a", [2]string{":path", "/h2b"}), want: "reset"},
	{name: "no :path", fields: [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", wireHost}}, want: "reset"},

	// The edge's own rules hold on HTTP/2 too.
	{name: "dot-dot in :path", fields: get("/a/../etc"), want: "400"},
	{name: "CONNECT", fields: [][2]string{{":method", "CONNECT"}, {":authority", wireHost + ":443"}}, want: "405"},
	{name: ":authority the edge does not serve", fields: [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "nobody.example.com"}, {":path", "/"}},
		want: "reset"},
}

func (h *hostile) runH2(t *testing.T, i int, v h2Vector) {
	pool, err := ca.LoadPool(h.caFile)
	require.NoError(t, err)
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: lab.Attempt},
		Config: &tls.Config{ServerName: wireHost, RootCAs: pool, NextProtos: []string{"h2"}}}
	c, err := d.DialContext(t.Context(), "tcp", net.JoinHostPort(h.vm.Addr, strconv.Itoa(h.vm.HTTPS)))
	require.NoError(t, err)
	defer c.Close()
	require.Equal(t, "h2", c.(*tls.Conn).ConnectionState().NegotiatedProtocol)
	assert.Contains(t, strings.Split(v.want, "|"), h2Stream(t, c, v.fields, []byte(v.data)), "how the stream ended")
	path := ""
	for _, f := range v.fields {
		if f[0] == ":path" {
			path = f[1]
		}
	}
	h.settle(t, i, path, v.reaches)
}

// h2Stream sends one request on stream 1 of c and returns how it ended:
// its status, "reset", "goaway", or "none" if the edge went quiet.
func h2Stream(t *testing.T, c net.Conn, fields [][2]string, data []byte) string {
	c.SetWriteDeadline(time.Now().Add(lab.Attempt))
	_, err := io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	require.NoError(t, fr.WriteSettings())
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range fields {
		require.NoError(t, enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block.Bytes(), EndStream: len(data) == 0, EndHeaders: true,
	}))
	if len(data) > 0 {
		fr.WriteData(1, true, data) // the edge may already have reset the stream
	}
	status := "none"
	for deadline := time.Now().Add(lab.Attempt); ; {
		c.SetReadDeadline(deadline)
		f, err := fr.ReadFrame()
		if err != nil {
			return status
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID == 1 && f.PseudoValue("status") != "" {
				status = f.PseudoValue("status")
				if f.StreamEnded() {
					return status
				}
			}
		case *http2.DataFrame:
			if f.StreamID == 1 && f.StreamEnded() {
				return status
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				if status != "none" {
					return status + " reset"
				}
				return "reset"
			}
		case *http2.GoAwayFrame:
			if f.ErrCode == http2.ErrCodeNo && f.LastStreamID >= 1 {
				continue // graceful: stream 1 still ends on its own
			}
			return "goaway"
		}
	}
}
