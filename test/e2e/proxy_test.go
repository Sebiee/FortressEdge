//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// What a visitor and a dark node see through the edge: routing by
// hostname, what reaches the origin, and who may use the tunnel name.
func TestProxyingToDarkNodes(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{
		Policy: "access_log: true\nlimits:\n  request_burst: 1000\n  new_connections_per_second: 200\n  response_header_timeout: 5s\n" +
			"sites:\n  limits.example.com:\n    response_header_timeout: 1s\n    max_body_size: 1KiB\n"})
	vm, web, caFile, pki := e.VM, e.Web, e.Roots, e.PKI
	lab.Ctl(t, "ca", "client", pki, ca.ID(lab.Tunnel, ca.RoleNode, "node2"))
	node1Crt, node1Key := e.Cert(ca.RoleNode, "node1")
	node2Crt, node2Key := e.Cert(ca.RoleNode, "node2")
	opsCrt, opsKey := e.Cert(ca.RoleOps, "alice")
	logsCrt, logsKey := e.Cert(ca.RoleLogs, "shipper")

	blob := make([]byte, 4<<20)
	rand.Read(blob)
	release := make(chan struct{})
	origin := http.NewServeMux()
	origin.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(seen{Host: r.Host, URI: r.RequestURI, Header: r.Header})
	})
	origin.HandleFunc("/sum", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, sum(r.Body)) })
	origin.HandleFunc("/blob", func(w http.ResponseWriter, _ *http.Request) { w.Write(blob) })
	origin.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		wait(r, release)
		io.WriteString(w, "last\n")
	})
	origin.HandleFunc("/hang", func(_ http.ResponseWriter, r *http.Request) { wait(r, nil) })
	origin.Handle("/ws", websocket.Handler(func(c *websocket.Conn) { io.Copy(c, c) }))
	vm.Publish(t, "wss", caFile, node1Crt, node1Key, lab.Origin(t, origin), "echo.example.com", "limits.example.com")
	vm.Publish(t, "quic", caFile, node2Crt, node2Key, lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "other")
	})), "other.example.com")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, body, err := lab.Get(web, "https://other.example.com/")
		require.NoError(c, err)
		assert.Equal(c, "other", body)
		assert.Equal(c, "echo.example.com", echo(c, web, "https://echo.example.com/", nil).Host)
		assert.Equal(c, "limits.example.com", echo(c, web, "https://limits.example.com/", nil).Host)
	}, lab.Until(t), lab.Tick)
	logs := vm.Client(t, caFile, logsCrt, logsKey)

	for _, tc := range []struct {
		name  string
		check func(t *testing.T)
	}{
		{"plain HTTP redirects to the same path and query on HTTPS", func(t *testing.T) {
			resp, _, err := lab.Get(web, "http://echo.example.com/a/b?c=d&e=%20f")
			require.NoError(t, err)
			assert.Equal(t, http.StatusPermanentRedirect, resp.StatusCode)
			assert.Equal(t, "https://echo.example.com/a/b?c=d&e=%20f", resp.Header.Get("Location"))
		}},
		{"each hostname reaches its own dark node, in any letter case", func(t *testing.T) {
			_, body, err := lab.Get(web, "https://OTHER.Example.com/")
			require.NoError(t, err)
			assert.Equal(t, "other", body)
			got := echo(t, web, "https://echo.example.com/a/b?c=d", nil)
			assert.Equal(t, "/a/b?c=d", got.URI)
		}},
		{"a hostname with a trailing dot reaches the same site", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://echo.example.com/", nil)
			require.NoError(t, err)
			req.Host = "echo.example.com."
			resp, _, err := lab.Do(web, req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}},
		{"a hostname no dark node published gets no answer on either port", func(t *testing.T) {
			_, _, err := lab.Get(web, "https://nobody.example.com/")
			assert.Error(t, err, "HTTPS")
			_, _, err = lab.Get(web, "http://nobody.example.com/")
			assert.Error(t, err, "plain HTTP")
		}},
		{"a scan of the address gets not one byte back", func(t *testing.T) {
			for name, probe := range map[string]struct {
				port int
				send func(net.Conn)
			}{
				"TLS without a server name": {vm.HTTPS, func(c net.Conn) {
					tls.Client(c, &tls.Config{InsecureSkipVerify: true}).Handshake()
				}},
				"TLS for another name": {vm.HTTPS, func(c net.Conn) {
					tls.Client(c, &tls.Config{ServerName: "nobody.example.com", InsecureSkipVerify: true}).Handshake()
				}},
				"plain HTTP on 443":          {vm.HTTPS, func(c net.Conn) { io.WriteString(c, "GET / HTTP/1.1\r\nHost: echo.example.com\r\n\r\n") }},
				"plain HTTP for the address": {vm.HTTP, func(c net.Conn) { io.WriteString(c, "GET / HTTP/1.1\r\nHost: 10.0.2.15\r\n\r\n") }},
			} {
				c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(probe.port)), lab.Attempt)
				require.NoError(t, err)
				c.SetDeadline(time.Now().Add(lab.Attempt))
				n := &counted{Conn: c}
				probe.send(n)
				io.Copy(io.Discard, n)
				c.Close()
				assert.Zero(t, n.read, name)
			}
		}},
		{"a site whose origin is down answers 502, and nothing names frp", func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			closed := l.Addr().(*net.TCPAddr).Port
			l.Close()
			vm.Publish(t, "wss", caFile, node1Crt, node1Key, closed, "down.example.com")
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				resp, body, err := lab.Get(web, "https://down.example.com/")
				require.NoError(c, err)
				assert.Equal(c, http.StatusBadGateway, resp.StatusCode)
				assert.Empty(c, body)
				assert.Empty(c, resp.Header.Get("Server"))
			}, lab.Until(t), lab.Tick)
		}},
		{"the origin sees the visitor's address, host and scheme, not forged ones", func(t *testing.T) {
			is := assert.New(t)
			got := echo(t, web, "https://echo.example.com/", http.Header{
				"X-Forwarded-For":   {"198.51.100.7"},
				"X-Forwarded-Host":  {"evil.example"},
				"X-Forwarded-Proto": {"http"},
				"X-Real-Ip":         {"198.51.100.7"},
			})
			is.Equal("echo.example.com", got.Host)
			is.Equal([]string{"10.0.2.2"}, got.Header["X-Forwarded-For"], "slirp sends every host connection from 10.0.2.2")
			is.Equal([]string{"10.0.2.2"}, got.Header["X-Real-Ip"])
			is.Equal([]string{"echo.example.com"}, got.Header["X-Forwarded-Host"])
			is.Equal([]string{"https"}, got.Header["X-Forwarded-Proto"])
		}},
		{"one request id reaches the visitor, the origin and the access log; status counts the site", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://echo.example.com/traced?token=secret", nil)
			require.NoError(t, err)
			req.Header.Set("X-Request-Id", "forged")
			req.Header.Set("Forwarded", "for=198.51.100.7")
			resp, body, err := lab.Do(web, req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, body)
			var got seen
			require.NoError(t, json.Unmarshal([]byte(body), &got))
			id := resp.Header.Get("Fortress-Request-Id")
			require.NotEmpty(t, id)
			assert.Equal(t, []string{id}, got.Header["X-Request-Id"], "the origin gets the edge's id, not the visitor's")
			assert.Empty(t, got.Header["Forwarded"])

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				line := accessLine(c, logs, id)
				assert.Equal(c, "echo.example.com", line["site"])
				assert.Equal(c, "/traced", line["path"], "the query string is not logged")
				assert.Equal(c, "10.0.2.2", line["ip"])
				assert.EqualValues(c, 200, line["status"])
			}, lab.Until(t), lab.Tick)

			resp, body, err = lab.Get(logs, lab.OpsURL+"status")
			require.NoError(t, err)
			var st struct {
				Sites  map[string]map[string]int64 `json:"sites"`
				Limits map[string]any              `json:"limits"`
				Clock  struct {
					Server   string `json:"server"`
					SyncedAt string `json:"synced_at"`
				} `json:"clock"`
			}
			require.NoError(t, json.Unmarshal([]byte(body), &st))
			assert.Equal(t, vm.NTP(), st.Clock.Server, "the clock keeps to the lab's server")
			assert.NotEmpty(t, st.Clock.SyncedAt)
			assert.Positive(t, st.Sites["echo.example.com"]["2xx"])
			assert.EqualValues(t, 1000, st.Limits["request_burst"], "limits from fortress.yml")
			assert.EqualValues(t, 200, st.Limits["new_connections_per_second"])
			assert.EqualValues(t, 150, st.Limits["requests_per_second"], "a key left out keeps its default")
		}},
		{"a site's own response_header_timeout and max_body_size, and a proxy error line that names the request", func(t *testing.T) {
			start := time.Now()
			resp, _, err := lab.Get(&http.Client{Transport: web.Transport, Timeout: 3 * lab.Attempt}, "https://limits.example.com/hang?token=secret")
			require.NoError(t, err)
			assert.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
			took := time.Since(start)
			assert.GreaterOrEqual(t, took, 900*time.Millisecond, "1s, not sooner")
			// The timer starts once the request is on its way to the dark
			// node, so a busy VM adds a little; the edge's 5s cannot be less.
			assert.Less(t, took, 5*time.Second, "the site's 1s, not the edge's 5s")
			id := resp.Header.Get("Fortress-Request-Id")
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				_, body, err := lab.Get(logs, lab.OpsURL+"logs")
				require.NoError(c, err)
				var line string
				for l := range strings.Lines(body) {
					if strings.Contains(l, `msg="proxy error"`) && strings.Contains(l, "id="+id) {
						line = l
					}
				}
				require.NotEmpty(c, line, "no proxy error line for %s", id)
				for _, want := range []string{"site=limits.example.com", "method=GET", "path=/hang", "reason=header_timeout", "trace_id="} {
					assert.Contains(c, line, want)
				}
				assert.NotContains(c, line, "secret", "the query string is not logged")
			}, lab.Until(t), lab.Tick)

			post := func(url string, body io.Reader) int {
				req, err := http.NewRequest(http.MethodPost, url, body)
				require.NoError(t, err)
				resp, _, err := lab.Do(web, req)
				require.NoError(t, err)
				return resp.StatusCode
			}
			big := bytes.Repeat([]byte("x"), 4096)
			assert.Equal(t, http.StatusRequestEntityTooLarge, post("https://limits.example.com/sum", bytes.NewReader(big)), "Content-Length over 1KiB")
			assert.Equal(t, http.StatusRequestEntityTooLarge, post("https://limits.example.com/sum", io.MultiReader(bytes.NewReader(big))),
				"a streamed body over 1KiB")
			assert.Equal(t, http.StatusOK, post("https://limits.example.com/sum", bytes.NewReader(big[:512])))
			assert.Equal(t, http.StatusOK, post("https://echo.example.com/sum", bytes.NewReader(big)), "another site keeps the edge's limit")
		}},
		{"the origin continues the edge's trace, which the visitor and the access log name", func(t *testing.T) {
			const visitor = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
			req, err := http.NewRequest(http.MethodGet, "https://echo.example.com/", nil)
			require.NoError(t, err)
			req.Header.Set("Traceparent", visitor)
			req.Header.Set("Tracestate", "evil=1")
			resp, body, err := lab.Do(web, req)
			require.NoError(t, err)
			var got seen
			require.NoError(t, json.Unmarshal([]byte(body), &got))
			tp := strings.Split(got.Header.Get("Traceparent"), "-")
			require.Len(t, tp, 4, "origin's traceparent %q", got.Header.Get("Traceparent"))
			traceID := resp.Header.Get("Fortress-Trace-Id")
			assert.Equal(t, traceID, tp[1], "the visitor is told the trace the origin is in")
			assert.NotEqual(t, "4bf92f3577b34da6a3ce929d0e0e4736", traceID, "an untrusted visitor does not pick the trace")
			assert.Empty(t, got.Header["Tracestate"])
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				line := accessLine(c, logs, resp.Header.Get("Fortress-Request-Id"))
				assert.Equal(c, traceID, line["trace_id"])
				assert.Equal(c, tp[2], line["span_id"], "the origin's parent is the edge's span")
				assert.Equal(c, "4bf92f3577b34da6a3ce929d0e0e4736", line["link_trace_id"])
				assert.NotEmpty(c, line["start"])
				assert.NotEmpty(c, line["headers_us"])
			}, lab.Until(t), lab.Tick)
		}},
		{"metrics in Prometheus's format, for a log reader and not a dark node", func(t *testing.T) {
			resp, _, err := lab.Get(vm.Client(t, caFile, node1Crt, node1Key), lab.OpsURL+"metrics")
			require.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				resp, body, err := lab.Get(logs, lab.OpsURL+"metrics")
				require.NoError(c, err)
				require.Equal(c, http.StatusOK, resp.StatusCode)
				assert.Contains(c, resp.Header.Get("Content-Type"), "version=0.0.4")
				for _, want := range []string{
					"fortressedge_build_info{",
					"fortressedge_boot_time_seconds ",
					`fortressedge_http_requests_total{site="echo.example.com",code_class="2xx"} `,
					`fortressedge_http_request_duration_seconds_bucket{site="echo.example.com",le="+Inf"} `,
					`fortressedge_tunnel_clients{node="node1"} `,
					`fortressedge_tunnel_clients{node="node2"} `, // over QUIC
					"fortressedge_tunnel_logins_total ",
					`fortressedge_work_connections{state="pooled"} `,
					`fortressedge_certificate_not_after_seconds{name="echo.example.com"} `,
					`fortressedge_certificate_obtains_total{name="echo.example.com",result="ok"} `,
					`fortressedge_xdp_packets_total{action="pass",reason="service"} `,
					`fortressedge_kernel_tcp_total{counter="passive_opens"} `,
					"fortressedge_clock_offset_seconds ",
					"fortressedge_clock_sync_timestamp_seconds ",
					`fortressedge_clock_stratum{server="` + vm.NTP() + `"} 1`,
					`fortressedge_ntp_queries_total{server="` + vm.NTP() + `",result="ok"} `,
				} {
					assert.Contains(c, body, want)
				}
			}, lab.Until(t), lab.Tick)
		}},
		{"requests no site should get are refused at the edge", func(t *testing.T) {
			for _, tc := range []struct {
				method, url string
				want        int
			}{
				{http.MethodGet, "https://echo.example.com/a/%2e%2e/etc/passwd", http.StatusBadRequest},
				{http.MethodTrace, "https://echo.example.com/", http.StatusMethodNotAllowed},
			} {
				req, err := http.NewRequest(tc.method, tc.url, nil)
				require.NoError(t, err)
				resp, _, err := lab.Do(web, req)
				require.NoError(t, err)
				assert.Equal(t, tc.want, resp.StatusCode, "%s %s", tc.method, tc.url)
			}
		}},
		{"sites speak HTTP/2", func(t *testing.T) {
			tr := web.Transport.(*http.Transport).Clone()
			tr.ForceAttemptHTTP2 = true
			resp, _, err := lab.Get(&http.Client{Transport: tr, Timeout: lab.Attempt}, "https://echo.example.com/")
			require.NoError(t, err)
			assert.Equal(t, "HTTP/2.0", resp.Proto)
		}},
		{"a large upload and a large download arrive intact", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://echo.example.com/sum", bytes.NewReader(blob))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/octet-stream")
			_, got, err := lab.Do(web, req)
			require.NoError(t, err)
			assert.Equal(t, sum(bytes.NewReader(blob)), got, "upload")
			_, got, err = lab.Get(web, "https://echo.example.com/blob")
			require.NoError(t, err)
			assert.Equal(t, sum(bytes.NewReader(blob)), sum(strings.NewReader(got)), "download")
		}},
		{"a streamed response reaches the visitor before the origin finishes", func(t *testing.T) {
			resp, err := web.Get("https://echo.example.com/stream")
			require.NoError(t, err)
			defer resp.Body.Close()
			r := bufio.NewReader(resp.Body)
			line, err := r.ReadString('\n')
			require.NoError(t, err, "the first chunk is held back until the origin ends")
			assert.Equal(t, "first\n", line)
			close(release)
			line, _ = r.ReadString('\n')
			assert.Equal(t, "last\n", line)
		}},
		{"a WebSocket to a site carries messages both ways", func(t *testing.T) {
			cfg, err := websocket.NewConfig("wss://echo.example.com/ws", "https://echo.example.com")
			require.NoError(t, err)
			ws, err := websocket.NewClient(cfg, vm.DialTLS(t, "echo.example.com", caFile))
			require.NoError(t, err)
			ws.SetDeadline(time.Now().Add(lab.Attempt))
			for _, msg := range []string{"hello", "again"} {
				require.NoError(t, websocket.Message.Send(ws, msg))
				var got string
				require.NoError(t, websocket.Message.Receive(ws, &got))
				assert.Equal(t, msg, got)
			}
		}},
		{"a site that never answers times out with 504 after the policy's response_header_timeout", func(t *testing.T) {
			start := time.Now()
			resp, _, err := lab.Get(&http.Client{Transport: web.Transport, Timeout: 3 * lab.Attempt}, "https://echo.example.com/hang")
			require.NoError(t, err)
			assert.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
			took := time.Since(start)
			assert.GreaterOrEqual(t, took, 4500*time.Millisecond, "5s, not sooner")
			assert.Less(t, took, 9*time.Second, "5s, not frp's 10s nor the 60s default")
		}},
		{"a site goes silent when its dark node leaves and serves again when it returns", func(t *testing.T) {
			stop := vm.Tunnel(t, web, "wss", "flap.example.com", caFile, node1Crt, node1Key)
			stop()
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				web.CloseIdleConnections()
				_, _, err := lab.Get(web, "https://flap.example.com/")
				assert.Error(c, err)
			}, lab.Until(t), lab.Tick)
			vm.Tunnel(t, web, "wss", "flap.example.com", caFile, node1Crt, node1Key)
		}},
		{"the tunnel name refuses a connection without a client certificate", func(t *testing.T) {
			_, _, err := lab.Get(web, "https://"+lab.Tunnel+"/")
			assert.Error(t, err)
		}},
		{"the tunnel name refuses a client certificate from another CA", func(t *testing.T) {
			other := filepath.Join(t.TempDir(), "other")
			lab.Ctl(t, "ca", "init", other)
			lab.Ctl(t, "ca", "client", other, ca.ID(lab.Tunnel, ca.RoleNode, "node1"))
			crt, key := lab.Cert(other, ca.RoleNode, "node1")
			c := vm.Client(t, caFile, crt, key)
			_, _, err := lab.Get(c, "https://"+lab.Tunnel+"/")
			assert.Error(t, err)
		}},
		{"only a dark-node certificate joins the tunnel, over WebSocket and QUIC", func(t *testing.T) {
			// An operator or log reader that could log in to frps could
			// register any hostname.
			for _, proto := range []string{"wss", "quic"} {
				assert.Error(t, vm.Login(t, proto, caFile, opsCrt, opsKey), "%s: operator certificate", proto)
				assert.Error(t, vm.Login(t, proto, caFile, logsCrt, logsKey), "%s: log-reader certificate", proto)
				assert.NoError(t, vm.Login(t, proto, caFile, node2Crt, node2Key), "%s: dark-node certificate", proto)
			}
		}},
		{"a dark node without trustedCaFile checks the edge against the system roots, and skips the check only when told", func(t *testing.T) {
			// Pebble's root is in no system store, so this is a stand-in
			// for an edge that is not the real one.
			skip := func(c *v1.TLSClientConfig) { c.InsecureSkipVerify = true }
			for _, proto := range []string{"wss", "quic"} {
				err := vm.Login(t, proto, "", node2Crt, node2Key)
				if assert.Error(t, err, "%s: no trustedCaFile", proto) {
					assert.Contains(t, err.Error(), "certificate", proto)
				}
				assert.NoError(t, vm.Login(t, proto, "", node2Crt, node2Key, skip), "%s: insecureSkipVerify", proto)
			}
		}},
		{"a dark-node certificate on the tunnel name reaches no site", func(t *testing.T) {
			resp, _, err := lab.Get(vm.Client(t, caFile, node1Crt, node1Key), "https://"+lab.Tunnel+"/")
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		}},
		// The client certificate is asked for by TLS server name. These name
		// a site in TLS and the tunnel only in the Host header.
		{"frp control cannot be reached without a client certificate by naming the tunnel only in Host", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://"+lab.Tunnel+"/~!frp", nil)
			require.NoError(t, err)
			key := make([]byte, 16)
			rand.Read(key)
			req.Header = http.Header{
				"Connection":            {"Upgrade"},
				"Upgrade":               {"websocket"},
				"Sec-Websocket-Version": {"13"},
				"Sec-Websocket-Key":     {base64.StdEncoding.EncodeToString(key)},
				"Origin":                {"https://" + lab.Tunnel},
			}
			resp, _, err := lab.Do(sniOnly(web, "echo.example.com"), req)
			require.NoError(t, err)
			assert.NotEqual(t, http.StatusSwitchingProtocols, resp.StatusCode, "frps accepted a WebSocket with no client certificate")
		}},
		{"the ops API cannot be reached by naming the tunnel only in Host", func(t *testing.T) {
			resp, _, err := lab.Get(sniOnly(vm.Client(t, caFile, opsCrt, opsKey), "echo.example.com"), lab.OpsURL+"status")
			require.NoError(t, err)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.check(t)
		})
	}
}

// accessLine is the access log's line for the request id.
func accessLine(c *assert.CollectT, logs *http.Client, id string) map[string]any {
	resp, body, err := lab.Get(logs, lab.OpsURL+"access")
	require.NoError(c, err)
	require.Equal(c, http.StatusOK, resp.StatusCode)
	var line map[string]any
	for l := range bytes.Lines([]byte(body)) {
		var m map[string]any
		require.NoError(c, json.Unmarshal(l, &m), "access line %q", l)
		if m["id"] == id {
			line = m
		}
	}
	require.NotNil(c, line, "no access line for %s", id)
	return line
}

// seen is what the echo origin reports about the request it received.
type seen struct {
	Host   string
	URI    string
	Header http.Header
}

func echo(t require.TestingT, c *http.Client, url string, h http.Header) seen {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	for k, v := range h {
		req.Header[k] = v
	}
	resp, body, err := lab.Do(c, req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	var s seen
	require.NoError(t, json.Unmarshal([]byte(body), &s))
	return s
}

// wait holds an origin handler until release closes or the request ends,
// and never longer than a few attempts, so cleanup cannot hang on it.
func wait(r *http.Request, release <-chan struct{}) {
	select {
	case <-release:
	case <-r.Context().Done():
	case <-time.After(3 * lab.Attempt):
	}
}

func sum(r io.Reader) string {
	h := sha256.New()
	n, _ := io.Copy(h, r)
	return fmt.Sprintf("%d %x", n, h.Sum(nil))
}

// counted is a connection that counts the bytes read from it.
type counted struct {
	net.Conn
	read int
}

func (c *counted) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read += n
	return n, err
}

// sniOnly is c with sni as the TLS server name, whatever host the URL names.
func sniOnly(c *http.Client, sni string) *http.Client {
	tr := c.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = sni
	return &http.Client{Transport: tr, Timeout: c.Timeout, CheckRedirect: c.CheckRedirect}
}
