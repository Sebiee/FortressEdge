//go:build linux

package frpsvc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	glog "github.com/fatedier/golib/log"

	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/logx"
)

func TestStartListensLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	frps, err := Start(ctx, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer frps.Stop()

	c, err := net.DialTimeout("tcp", config.ControlAddr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", config.ControlAddr(), err)
	}
	c.Close()

	// frps's own answer for a name no proxy has names neither frp nor
	// its version.
	rec := httptest.NewRecorder()
	frps.Vhost.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://nobody.example.com/", nil))
	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusNotFound || len(body) != 0 || res.Header.Get("Server") != "" {
		t.Fatalf("status=%d server=%q body=%q", res.StatusCode, res.Header.Get("Server"), body)
	}
}

// TestVisitorLeftIsDebug writes frp's proxy errors through a logger set
// up as Start sets frp's: a visitor who left is debug, the rest stay warn.
func TestVisitorLeftIsDebug(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	l := glog.New(glog.WithOutput(logx.Forward("frp").Quiet(visitorLeft)), glog.WithLevel(glog.InfoLevel))

	// frp's ErrorHandler (pkg/util/vhost/http.go).
	const proxyErr = "do http proxy request [host: %s] error: %v"
	for _, tc := range []struct {
		msg   string
		args  []any
		level string
	}{
		{proxyErr, []any{"argocd.example.com", context.Canceled}, "DEBUG"},
		{proxyErr, []any{"argocd.example.com", errors.New("timeout awaiting response headers")}, "WARN"},
		{proxyErr, []any{"argocd.example.com", context.DeadlineExceeded}, "WARN"},
		{proxyErr, []any{"argocd.example.com", errors.New("no route found")}, "WARN"},
		{proxyErr, []any{"argocd.example.com", errors.New("dial: context canceled")}, "WARN"},
		{"get a user connection [%s] error: %v", []any{"10.0.0.1", context.Canceled}, "WARN"},
	} {
		buf.Reset()
		l.Warnf(tc.msg, tc.args...)
		if want := "level=" + tc.level + " "; !strings.Contains(buf.String(), want) {
			t.Errorf("%s: want %s", strings.TrimSpace(buf.String()), tc.level)
		}
	}
}

// holdConn blocks in its first Write until release is closed, and records
// every Write. The first block is what lets later writes pile up in batchConn.
type holdConn struct {
	net.Conn
	mu      sync.Mutex
	writes  [][]byte
	entered chan struct{}
	release chan struct{}
}

func newHoldConn() *holdConn {
	a, _ := net.Pipe()
	return &holdConn{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
}

func (c *holdConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	first := len(c.writes) == 1
	c.mu.Unlock()
	if first {
		close(c.entered)
		<-c.release
	}
	return len(p), nil
}

// TestBatchConnCoalesces is yamux's pattern: a header write is on the wire
// while many small body writes arrive, and they must leave as one write.
// Close then flushes that batch.
func TestBatchConnCoalesces(t *testing.T) {
	inner := newHoldConn()
	b := newBatchConn(inner)

	go func() {
		if _, err := b.Write([]byte("hdr")); err != nil {
			t.Errorf("first write: %v", err)
		}
	}()
	select {
	case <-inner.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not start")
	}

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(n byte) {
			defer wg.Done()
			if _, err := b.Write([]byte{n}); err != nil {
				t.Errorf("write %d: %v", n, err)
			}
		}(byte(i))
	}
	wg.Wait()
	close(inner.release)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.writes) != 2 {
		t.Fatalf("underlying writes = %d, want 2 (the one on the wire, then one batch)", len(inner.writes))
	}
	if !bytes.Equal(inner.writes[0], []byte("hdr")) {
		t.Fatalf("first write = %q", inner.writes[0])
	}
	if len(inner.writes[1]) != 32 {
		t.Fatalf("coalesced %d bytes, want 32", len(inner.writes[1]))
	}
	var saw [32]bool
	for _, n := range inner.writes[1] {
		if int(n) >= len(saw) || saw[n] {
			t.Fatalf("coalesced bytes = %v", inner.writes[1])
		}
		saw[n] = true
	}
}
