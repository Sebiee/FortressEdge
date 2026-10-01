package httpsvc

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// keepTunnelAlive finds the socket under a request and sets
// tunnel_dead_timeout on it; a connection leaves the registry when it
// closes.
func TestKeepTunnelAlive(t *testing.T) {
	socks := &sockets{}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := socks.listen(raw)
	srv := &http.Server{Handler: socks.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := keepTunnelAlive(r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tc := socketOf(r)
		if tc == nil {
			http.Error(w, "no socket", http.StatusInternalServerError)
			return
		}
		sc, _ := tc.SyscallConn()
		var ms int
		var gerr error
		_ = sc.Control(func(fd uintptr) { ms, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT) })
		if gerr != nil {
			http.Error(w, gerr.Error(), http.StatusInternalServerError)
			return
		}
		io.WriteString(w, strconv.Itoa(ms))
	}))}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	get := func() string {
		t.Helper()
		c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		resp, err := c.Get("http://" + raw.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		return string(b)
	}
	socks.setDeadTimeout(3 * time.Second)
	if got := get(); got != "3000" {
		t.Fatalf("TCP_USER_TIMEOUT %s ms, want 3000", got)
	}
	socks.setDeadTimeout(0)
	if got := get(); got != "0" {
		t.Fatalf("off: TCP_USER_TIMEOUT %s ms, want the kernel's 0", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := 0
		socks.m.Range(func(any, any) bool { n++; return true })
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sockets left after their connections closed", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
