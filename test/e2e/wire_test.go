//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// wireOrigin is a dark node's site that reads requests off the socket
// itself, so it sees the bytes that crossed the edge, frps and frpc, not
// what a lenient parser made of them. Each request is checked against
// the strict HTTP/1.1 grammar (strictRequest) and answered with a reply.
type wireOrigin struct {
	Port int
	// visitor is the address the forwarded headers must carry, set once
	// the VM is known (lab.VM.Visitor); empty skips that check.
	visitor atomic.Pointer[string]
	// keep stores every arrival for take; off, only replies tell.
	keep bool

	seq      atomic.Int64
	bad      atomic.Int64 // requests the strict grammar objected to
	partial  atomic.Int64 // requests cut short, and bytes that start none
	mu       sync.Mutex
	arrivals []arrival
	samples  []arrival // the first few bad or partial ones, kept or not
	conns    map[net.Conn]struct{}
}

// maxSamples bounds wireOrigin.samples.
const maxSamples = 20

// replyHeader carries the reply, base64, in a response to HEAD.
const replyHeader = "Wire-Reply"

// arrival is one request as the origin read it.
type arrival struct {
	Method, URI string
	Body        []byte
	Raw         []byte
	// Problems are the strict grammar's objections; none for a clean request.
	Problems []string
	// Err is set when no whole request could be read: garbage, or a
	// connection closed partway through, as when the edge aborts one.
	// Method and URI are then from the request line, if there was one.
	Err string
}

// reply is the origin's answer: what it received, so a visitor can
// compare it with what it sent.
type reply struct {
	Seq      int64    `json:"seq"`
	Method   string   `json:"method"`
	URI      string   `json:"uri"`
	BodySHA  string   `json:"body_sha256"`
	Problems []string `json:"problems,omitempty"`
}

func newWireOrigin(t *testing.T, keep bool) *wireOrigin {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	o := &wireOrigin{Port: l.Addr().(*net.TCPAddr).Port, keep: keep, conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			o.mu.Lock()
			o.conns[c] = struct{}{}
			o.mu.Unlock()
			go o.serve(c)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		o.mu.Lock()
		defer o.mu.Unlock()
		for c := range o.conns {
			c.Close()
		}
	})
	return o
}

func (o *wireOrigin) visitorAddr() string {
	if v := o.visitor.Load(); v != nil {
		return *v
	}
	return ""
}

// take returns the arrivals since the last take and forgets them.
func (o *wireOrigin) take() []arrival {
	o.mu.Lock()
	defer o.mu.Unlock()
	a := o.arrivals
	o.arrivals = nil
	return a
}

func (o *wireOrigin) record(a arrival) {
	switch {
	case a.Err != "":
		o.partial.Add(1)
	case len(a.Problems) > 0:
		o.bad.Add(1)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if (a.Err != "" || len(a.Problems) > 0) && len(o.samples) < maxSamples {
		a.Raw = []byte(clip(a.Raw))
		o.samples = append(o.samples, a)
	}
	if o.keep {
		o.arrivals = append(o.arrivals, a)
	}
}

// problems describes the bad and partial requests seen so far, for a
// failure message.
func (o *wireOrigin) problems() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "%d requests the strict grammar objects to, %d partial ones", o.bad.Load(), o.partial.Load())
	for _, a := range o.samples {
		fmt.Fprintf(&b, "\n  %s %q %s %q", a.Err, a.Problems, a.Method+" "+a.URI, a.Raw)
	}
	return b.String()
}

func (o *wireOrigin) serve(c net.Conn) {
	defer func() {
		c.Close()
		o.mu.Lock()
		delete(o.conns, c)
		o.mu.Unlock()
	}()
	tp := &tape{r: c}
	br := bufio.NewReader(tp)
	for {
		req, err := http.ReadRequest(br)
		if err == nil {
			var body []byte
			if body, err = io.ReadAll(req.Body); err == nil {
				raw := tp.take(br.Buffered())
				a := arrival{Method: req.Method, URI: req.RequestURI, Body: body, Raw: raw,
					Problems: strictRequest(raw, o.visitorAddr())}
				o.record(a)
				if o.answer(c, a) != nil || req.Close {
					return
				}
				continue
			}
		}
		if raw := tp.take(br.Buffered()); len(raw) > 0 || !errors.Is(err, io.EOF) {
			// EOF with nothing read is a pooled connection closing: not a request.
			a := arrival{Raw: raw, Err: err.Error()}
			if line, _, ok := bytes.Cut(raw, []byte("\r\n")); ok {
				if f := strings.Fields(string(line)); len(f) == 3 {
					a.Method, a.URI = f[0], f[1]
				}
			}
			o.record(a)
			io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		}
		return
	}
}

func (o *wireOrigin) answer(c net.Conn, a arrival) error {
	sum := sha256.Sum256(a.Body)
	b, _ := json.Marshal(reply{Seq: o.seq.Add(1), Method: a.Method, URI: a.URI,
		BodySHA: hex.EncodeToString(sum[:]), Problems: a.Problems})
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", len(b))
	if a.Method == http.MethodHead {
		// A HEAD response has no body, whatever its Content-Length says;
		// the reply rides in a header instead.
		head += replyHeader + ": " + base64.StdEncoding.EncodeToString(b) + "\r\n"
		b = nil
	}
	head += "\r\n"
	_, err := c.Write(append([]byte(head), b...))
	return err
}

// tape keeps the bytes read through it until take hands them out.
type tape struct {
	r   io.Reader
	buf []byte
}

func (t *tape) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.buf = append(t.buf, p[:n]...)
	return n, err
}

// take returns the bytes read so far, except the last pending ones that
// bufio holds for the next request, and forgets them.
func (t *tape) take(pending int) []byte {
	n := len(t.buf) - pending
	out := bytes.Clone(t.buf[:n])
	t.buf = append(t.buf[:0], t.buf[n:]...)
	return out
}

// strictRequest lists what in raw, one whole request as the origin
// received it, a strict HTTP/1.1 parser (RFC 9112) would refuse or a
// different one could read two ways: loose line endings, folded or
// malformed headers, ambiguous framing, a body that does not match it.
// It also holds the edge to its own contract: the visitor's address in
// the forwarded headers, and no path a gateway could resolve differently.
// clientIP empty skips the forwarded-header checks.
func strictRequest(raw []byte, clientIP string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return []string{"head does not end in CRLF CRLF"}
	}
	head, body := string(raw[:i]), raw[i+4:]
	lines := strings.Split(head, "\r\n")
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\n\x00") {
			bad("bare CR, LF or NUL in %q", l)
		}
	}
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || !isToken(parts[0]) || !isTarget(parts[1]) || parts[2] != "HTTP/1.1" {
		bad("request line %q", lines[0])
	} else {
		problems = append(problems, pathProblems(parts[1])...)
	}
	h := http.Header{}
	for _, l := range lines[1:] {
		if l == "" || l[0] == ' ' || l[0] == '\t' {
			bad("folded or empty header line %q", l)
			continue
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok || !isToken(name) {
			bad("header name in %q", l)
			continue
		}
		value = strings.Trim(value, " \t")
		if !isFieldValue(value) {
			bad("header value in %q", l)
		}
		k := http.CanonicalHeaderKey(name)
		h[k] = append(h[k], value)
	}
	if n := len(h["Host"]); n != 1 {
		bad("%d Host headers", n)
	}
	cl, te := h["Content-Length"], h["Transfer-Encoding"]
	switch {
	case len(cl) > 0 && len(te) > 0:
		bad("both Content-Length %q and Transfer-Encoding %q", cl, te)
	case len(te) > 0:
		if len(te) != 1 || !strings.EqualFold(te[0], "chunked") {
			bad("Transfer-Encoding %q", te)
		} else if err := strictChunked(body); err != nil {
			bad("chunked body: %v", err)
		}
	case len(cl) > 1:
		bad("%d Content-Length headers", len(cl))
	case len(cl) == 1:
		n, err := strconv.ParseUint(cl[0], 10, 63)
		if err != nil || strings.TrimLeft(cl[0], "0123456789") != "" {
			bad("Content-Length %q", cl[0])
		} else if uint64(len(body)) != n {
			bad("Content-Length %d, body %d bytes", n, len(body))
		}
	case len(body) > 0:
		bad("%d body bytes without Content-Length or Transfer-Encoding", len(body))
	}
	for _, k := range []string{"Forwarded", "Proxy-Connection", "Keep-Alive"} {
		if v, ok := h[k]; ok {
			bad("%s %q reached the origin", k, v)
		}
	}
	if clientIP != "" {
		for _, k := range []string{"X-Forwarded-For", "X-Real-Ip"} {
			if v := h[k]; len(v) != 1 || v[0] != clientIP {
				bad("%s %q, want %q", k, v, clientIP)
			}
		}
		if v := h["X-Forwarded-Proto"]; len(v) != 1 || v[0] != "https" {
			bad("X-Forwarded-Proto %q", v)
		}
	}
	return problems
}

// pathProblems holds the edge to what it promises a gateway: an
// origin-form target whose path has no dot segment, backslash or NUL,
// before or after percent-decoding, so no gateway reads it another way.
func pathProblems(target string) []string {
	if target == "*" {
		return nil
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || !strings.HasPrefix(target, "/") {
		return []string{fmt.Sprintf("target %q is not origin-form", target)}
	}
	var problems []string
	for _, p := range []string{u.EscapedPath(), u.Path} {
		if strings.ContainsAny(p, "\\\x00") {
			problems = append(problems, fmt.Sprintf("backslash or NUL in path %q", p))
		}
		for seg := range strings.SplitSeq(p, "/") {
			if seg == "." || seg == ".." {
				problems = append(problems, fmt.Sprintf("dot segment in path %q", p))
				break
			}
		}
	}
	return problems
}

// strictChunked checks b is exactly a chunked body: hex sizes, each
// chunk followed by CRLF, a last chunk, trailers, and nothing after.
func strictChunked(b []byte) error {
	crlf := []byte("\r\n")
	for {
		i := bytes.Index(b, crlf)
		if i < 0 {
			return errors.New("chunk size without CRLF")
		}
		size, _, _ := strings.Cut(string(b[:i]), ";")
		b = b[i+2:]
		if size == "" || strings.Trim(size, "0123456789abcdefABCDEF") != "" {
			return fmt.Errorf("chunk size %q", size)
		}
		n, err := strconv.ParseUint(size, 16, 63)
		if err != nil {
			return fmt.Errorf("chunk size %q: %w", size, err)
		}
		if n == 0 {
			for {
				i := bytes.Index(b, crlf)
				if i < 0 {
					return errors.New("trailer without CRLF")
				}
				b = b[i+2:]
				if i == 0 {
					break
				}
			}
			if len(b) > 0 {
				return fmt.Errorf("%d bytes after the last chunk", len(b))
			}
			return nil
		}
		if uint64(len(b)) < n+2 || !bytes.Equal(b[n:n+2], crlf) {
			return fmt.Errorf("chunk of %d bytes not followed by CRLF", n)
		}
		b = b[n+2:]
	}
}

// isToken reports whether s is an RFC 9110 token: a method or field name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// isTarget reports whether s is visible ASCII only, as a request target is.
func isTarget(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// isFieldValue reports whether s is a field value: no control
// characters except tab. obs-text (0x80-0xff) is allowed, as RFC 9110 does.
func isFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}
