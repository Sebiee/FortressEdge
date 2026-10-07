//go:build e2e

package e2e

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

var (
	pgImage  = flag.String("pg-image", "postgres:17", "PostgreSQL image for the TCP route tests: the server, psql, and pgbench")
	jdbcJar  = flag.String("pgjdbc", filepath.Join(os.Getenv("HOME"), ".m2/repository/org/postgresql/postgresql/42.7.4/postgresql-42.7.4.jar"), "pgJDBC 42.7.4 or later; missing skips its check")
	jdbcJava = flag.String("pgjdbc-image", "eclipse-temurin:21-jdk", "Java image to run pgJDBC in")
	pgbench  = flag.Duration("pgbench", 0, "how long each pgbench run of TestTCPRouteOverhead lasts; 0 skips it")
)

// echoServer accepts on loopback and echoes, closing its side after the
// client's EOF. accepted counts the connections.
func echoServer(t *testing.T) (port int, accepted *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	accepted = &atomic.Int64{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted
}

// postgres runs image's server on a loopback port, password pw, without
// TLS: the edge ends it.
func postgres(t *testing.T) int {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("needs docker")
	}
	out, err := exec.Command("docker", "run", "-d", "--rm", "-e", "POSTGRES_PASSWORD=pw", "-p", "127.0.0.1::5432", *pgImage).CombinedOutput()
	require.NoError(t, err, "%s", out)
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", id).Run() })
	out, err = exec.Command("docker", "port", id, "5432/tcp").CombinedOutput()
	require.NoError(t, err, "%s", out)
	_, p, _ := net.SplitHostPort(strings.TrimSpace(strings.Split(string(out), "\n")[0]))
	port, err := strconv.Atoi(p)
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		out, err := exec.Command("docker", "exec", id, "pg_isready", "-U", "postgres", "-h", "127.0.0.1").CombinedOutput()
		assert.NoError(c, err, "%s", out)
	}, time.Minute, 500*time.Millisecond)
	return port
}

// pgTool runs a PostgreSQL client from image on the host's network, with
// name resolving to the edge's address and the edge's roots at /ca.pem.
func pgTool(t *testing.T, vm *lab.VM, roots string, args ...string) (string, error) {
	t.Helper()
	cmd := append([]string{"run", "--rm", "--network", "host", "--add-host", "db.example.com:" + vm.Addr,
		"-v", roots + ":/ca.pem:ro", "-e", "PGPASSWORD=pw", *pgImage}, args...)
	out, err := exec.Command("docker", cmd...).CombinedOutput()
	return string(out), err
}

func pgConn(vm *lab.VM) string {
	return fmt.Sprintf("host=db.example.com port=%d user=postgres dbname=postgres sslmode=verify-full sslnegotiation=direct sslrootcert=/ca.pem", vm.HTTPS)
}

// openssl runs s_client against the edge for sni, sends in, and returns
// what came back: up to len(in) bytes, read before stdin closes, since
// s_client quits at its end of input.
func openssl(t *testing.T, vm *lab.VM, roots, sni, in string, alpn ...string) (string, error) {
	t.Helper()
	args := []string{"s_client", "-connect", net.JoinHostPort(vm.Addr, strconv.Itoa(vm.HTTPS)), "-servername", sni,
		"-CAfile", roots, "-verify_return_error", "-quiet", "-no_ign_eof"}
	if len(alpn) > 0 {
		args = append(args, "-alpn", strings.Join(alpn, ","))
	}
	cmd := exec.Command("openssl", args...)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	io.WriteString(stdin, in)
	got := make([]byte, len(in))
	done := make(chan int, 1)
	go func() { n, _ := io.ReadFull(stdout, got); done <- n }()
	var n int
	select {
	case n = <-done:
	case <-time.After(lab.Attempt):
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return string(got[:n]), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(got[:n]), nil
}

// TCP routes: TLS ended at the edge, the stream through the tunnel to a
// TCP service. openssl, psql, and pgJDBC reach their services; a wrong
// ALPN never reaches the backend; a name is an HTTP name or a TCP route;
// the idle timeout and the per-source limit hold, exempt sources are not
// limited; HTTP names are as before.
func TestTCPRoutes(t *testing.T) {
	t.Parallel()
	policy := "access_log: true\nsites:\n  idle.example.com:\n    tcp_idle_timeout: 2s\n" +
		"  limit.example.com:\n    tcp_connections_per_source: 2\n"
	e := lab.BootEdge(t, lab.EdgeOptions{Policy: policy})
	vm, web, roots := e.VM, e.Web, e.Roots
	crt, key := e.Cert(ca.RoleNode, "node1")
	echoPort, _ := echoServer(t)
	alpnPort, alpnAccepted := echoServer(t)
	pgPort := postgres(t)
	httpOrigin := lab.Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "http ok") }))
	vm.PublishProxies(t, lab.Member{}, "wss", roots, crt, key,
		lab.TCPRoute("echo.example.com", echoPort),
		lab.TCPRoute("alpn.example.com", alpnPort, "echo"),
		lab.TCPRoute("db.example.com", pgPort, "postgresql"),
		lab.TCPRoute("idle.example.com", echoPort),
		lab.TCPRoute("limit.example.com", echoPort),
		&v1.HTTPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{Name: "app.example.com", Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: httpOrigin}},
			DomainConfig:    v1.DomainConfig{CustomDomains: []string{"app.example.com"}},
		},
	)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, body, err := lab.Get(web, "https://app.example.com/")
		assert.NoError(c, err)
		assert.Equal(c, "http ok", body)
	}, lab.Until(t), lab.Tick)
	// The HTTP name's, from another frpc of the node: refused.
	vm.PublishProxies(t, lab.Member{User: "b"}, "wss", roots, crt, key, lab.TCPRoute("app.example.com", echoPort))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		out, err := openssl(t, vm, roots, "echo.example.com", "hello\n")
		assert.NoError(c, err)
		assert.Equal(c, "hello\n", out)
	}, lab.Until(t), lab.Tick)

	dial := func(t *testing.T, sni string, alpn ...string) (*tls.Conn, error) {
		pool, err := ca.LoadPool(roots)
		require.NoError(t, err)
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: lab.Attempt}, Config: &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: alpn}}
		c, err := d.DialContext(t.Context(), "tcp", net.JoinHostPort(vm.Addr, strconv.Itoa(vm.HTTPS)))
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { c.Close() })
		return c.(*tls.Conn), nil
	}
	echoOnce := func(t *testing.T, c *tls.Conn) {
		t.Helper()
		_, err := io.WriteString(c, "ping")
		require.NoError(t, err)
		b := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err = io.ReadFull(c, b)
		require.NoError(t, err)
		require.Equal(t, "ping", string(b))
	}

	step(t, "openssl reaches an echo backend, with and without an alpn list", func(t *testing.T) {
		out, err := openssl(t, vm, roots, "alpn.example.com", "with alpn\n", "echo")
		require.NoError(t, err)
		assert.Equal(t, "with alpn\n", out)
		// The edge's half-close carries the backend's EOF back.
		c, err := dial(t, "echo.example.com")
		require.NoError(t, err)
		io.WriteString(c, "bytes, then EOF")
		require.NoError(t, c.CloseWrite())
		got, err := io.ReadAll(c)
		require.NoError(t, err)
		assert.Equal(t, "bytes, then EOF", string(got))
	})
	step(t, "over a QUIC tunnel too, each way closed on its own", func(t *testing.T) {
		lab.Ctl(t, "ca", "client", e.PKI, ca.ID(lab.Tunnel, ca.RoleNode, "node2"))
		node2Crt, node2Key := e.Cert(ca.RoleNode, "node2")
		vm.PublishProxies(t, lab.Member{}, "quic", roots, node2Crt, node2Key, lab.TCPRoute("quic.example.com", echoPort))
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			conn, err := dial(t, "quic.example.com")
			if !assert.NoError(c, err) {
				return
			}
			io.WriteString(conn, "over quic")
			assert.NoError(c, conn.CloseWrite())
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := io.ReadAll(conn)
			assert.NoError(c, err)
			assert.Equal(c, "over quic", string(got))
		}, lab.Until(t), lab.Tick)
	})
	step(t, "a wrong alpn fails the handshake and the backend sees no connection", func(t *testing.T) {
		before := alpnAccepted.Load()
		_, err := openssl(t, vm, roots, "alpn.example.com", "x\n", "x")
		assert.Error(t, err)
		_, err = dial(t, "alpn.example.com", "x")
		assert.ErrorContains(t, err, "no application protocol")
		_, err = dial(t, "alpn.example.com")
		assert.Error(t, err, "no alpn at all")
		time.Sleep(time.Second)
		assert.Equal(t, before, alpnAccepted.Load())
	})
	step(t, "psql 17 runs SELECT 1 with sslnegotiation=direct", func(t *testing.T) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			out, err := pgTool(t, vm, roots, "psql", pgConn(vm), "-tAc", "SELECT 1")
			assert.NoError(c, err, out)
			assert.Equal(c, "1", strings.TrimSpace(out))
		}, lab.Until(t), lab.Tick)
	})
	step(t, "pgJDBC runs SELECT 1 with sslNegotiation=direct", func(t *testing.T) {
		if _, err := os.Stat(*jdbcJar); err != nil {
			t.Skipf("no pgJDBC at %s: %v", *jdbcJar, err)
		}
		dir := t.TempDir()
		src := `import java.sql.*;
public class Select1 {
	public static void main(String[] a) throws Exception {
		try (Connection c = DriverManager.getConnection(a[0], "postgres", "pw");
			ResultSet r = c.createStatement().executeQuery("SELECT 1")) {
			r.next();
			System.out.println(r.getInt(1));
		}
	}
}
`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Select1.java"), []byte(src), 0o644))
		url := fmt.Sprintf("jdbc:postgresql://db.example.com:%d/postgres?sslmode=verify-full&sslrootcert=/ca.pem&sslNegotiation=direct", vm.HTTPS)
		out, err := exec.Command("docker", "run", "--rm", "--network", "host", "--add-host", "db.example.com:"+vm.Addr,
			"-v", roots+":/ca.pem:ro", "-v", *jdbcJar+":/pgjdbc.jar:ro", "-v", dir+":/src:ro", *jdbcJava,
			"java", "-cp", "/pgjdbc.jar", "/src/Select1.java", url).CombinedOutput()
		require.NoError(t, err, "%s", out)
		assert.Equal(t, "1", strings.TrimSpace(string(out)))
	})
	step(t, "an HTTP name and a TCP route on one name: the second is refused", func(t *testing.T) {
		_, body, err := lab.Get(web, "https://app.example.com/")
		require.NoError(t, err)
		assert.Equal(t, "http ok", body, "the HTTP name keeps its route")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, metrics, err := lab.Get(e.Ops, lab.OpsURL+"metrics")
			require.NoError(c, err)
			// frpc retries the refused proxy: each attempt counts.
			assert.Contains(c, metrics, `fortressedge_name_conflicts_total{name="app.example.com",refused="tcp_route"}`)
		}, lab.Until(t), lab.Tick)
	})
	step(t, "the idle timeout closes a quiet connection", func(t *testing.T) {
		c, err := dial(t, "idle.example.com")
		require.NoError(t, err)
		echoOnce(t, c)
		start := time.Now()
		c.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, err = c.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)
		assert.Less(t, time.Since(start), 6*time.Second)
	})
	step(t, "a source holds at most tcp_connections_per_source, unless exempt", func(t *testing.T) {
		for range 2 {
			c, err := dial(t, "limit.example.com")
			require.NoError(t, err)
			echoOnce(t, c)
		}
		_, err := dial(t, "limit.example.com")
		assert.Error(t, err, "the third")
		e.Apply(t, policy+"exempt:\n  - "+vm.Visitor()+"\n")
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			conn, err := dial(t, "limit.example.com")
			if assert.NoError(c, err) {
				conn.Close()
			}
		}, lab.Until(t), lab.Tick)
		for range 3 {
			c, err := dial(t, "limit.example.com")
			require.NoError(t, err)
			echoOnce(t, c)
		}
	})
	step(t, "metrics and the access log carry the TCP routes", func(t *testing.T) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, metrics, err := lab.Get(e.Ops, lab.OpsURL+"metrics")
			require.NoError(c, err)
			for _, want := range []string{
				`fortressedge_tcp_route_connections_total{site="echo.example.com",result="ok"}`,
				`fortressedge_tcp_route_connections_total{site="alpn.example.com",result="alpn_refused"}`,
				`fortressedge_tcp_route_connections_total{site="limit.example.com",result="policy_refused"} 1`,
				`fortressedge_tcp_route_bytes_total{site="db.example.com",direction="out"}`,
				`fortressedge_tcp_route_connections{site="db.example.com"}`,
			} {
				assert.Contains(c, metrics, want)
			}
			_, access, err := lab.Get(e.Ops, lab.OpsURL+"access")
			require.NoError(c, err)
			assert.Contains(c, access, `"site":"db.example.com","proto":"tcp","alpn":"postgresql"`)
			assert.Contains(c, access, `"close":"idle_timeout"`)
		}, lab.Until(t), lab.Tick)
	})
	step(t, "HTTP names are unchanged", func(t *testing.T) {
		lab.Redirects(t, web)
		_, body, err := lab.Get(web, "https://app.example.com/")
		require.NoError(t, err)
		assert.Equal(t, "http ok", body)
		resp, _, err := lab.Get(web, "http://app.example.com/x")
		require.NoError(t, err)
		assert.Equal(t, http.StatusPermanentRedirect, resp.StatusCode)
		// A TCP route's name answers no plain HTTP.
		_, _, err = lab.Get(web, "http://db.example.com/")
		assert.Error(t, err)
	})
}

// TestTCPRouteOverhead is pgbench through the edge against the same
// database directly, for the release notes: a benchmark, not pass or
// fail. Run with -pgbench=30s.
func TestTCPRouteOverhead(t *testing.T) {
	if *pgbench == 0 {
		t.Skip("-pgbench=0")
	}
	e := lab.BootEdge(t, lab.EdgeOptions{CPUs: 2, MemMiB: 1024})
	vm, roots := e.VM, e.Roots
	crt, key := e.Cert(ca.RoleNode, "node1")
	pgPort := postgres(t)
	vm.PublishProxies(t, lab.Member{}, "wss", roots, crt, key, lab.TCPRoute("db.example.com", pgPort, "postgresql"))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		out, err := pgTool(t, vm, roots, "psql", pgConn(vm), "-tAc", "SELECT 1")
		assert.NoError(c, err, out)
	}, lab.Until(t), lab.Tick)
	direct := fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=disable", pgPort)
	out, err := pgTool(t, vm, roots, "pgbench", "-i", "-q", direct)
	require.NoError(t, err, out)
	secs := strconv.Itoa(int(pgbench.Seconds()))
	for _, run := range []struct{ name, conn string }{{"direct", direct}, {"edge", pgConn(vm)}} {
		for _, mode := range [][]string{{"-S", "-c", "4"}, {"-S", "-C", "-c", "4"}} {
			args := append(append([]string{"pgbench"}, mode...), "-T", secs, "-n", run.conn)
			out, err := pgTool(t, vm, roots, args...)
			require.NoError(t, err, out)
			for line := range strings.Lines(out) {
				if strings.HasPrefix(line, "tps") || strings.HasPrefix(line, "latency average") || strings.HasPrefix(line, "average connection time") {
					t.Logf("%s %s: %s", run.name, strings.Join(mode, " "), strings.TrimSpace(line))
				}
			}
		}
	}
}
