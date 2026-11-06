package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

// backendHealth answers a liveness probe for the backend the published
// proxies forward to: 200 while a TCP connection to it opens, 503 while
// not. A replica that cannot reach its backend while the others can is
// restarted by the kubelet, its tunnel closes, and the edge sends its share
// of requests to the other replicas. Cilium is the common case: a
// connection to a Gateway's address is served only by the node's own
// Envoy, never another node's. It has no fail-open: with the backend down
// for every replica, every replica restarts (docs/kubernetes.md).
//
// The name is resolved on each check, so a new Service address is followed.
// A failed lookup reuses the last address: the cluster's DNS being away is
// not this replica's backend being away, and restarting every replica would
// not bring it back.
type backendHealth struct {
	host, port string
	// timeout bounds a check, lookup and dial together, below a kubelet
	// probe's one-second timeout.
	timeout time.Duration
	lookup  func(ctx context.Context, host string) ([]string, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)

	mu   sync.Mutex
	last string // the last address the name resolved to
	down string // why the last check failed; empty while up
}

func newBackendHealth(host string, port int) *backendHealth {
	d := &net.Dialer{}
	return &backendHealth{
		host: host, port: strconv.Itoa(port), timeout: 800 * time.Millisecond,
		lookup: net.DefaultResolver.LookupHost, dial: d.DialContext,
	}
}

func (b *backendHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), b.timeout)
	defer cancel()
	if err := b.check(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

// check opens and closes one TCP connection to the backend.
func (b *backendHealth) check(ctx context.Context) error {
	addr, err := b.address(ctx)
	if err == nil {
		var c net.Conn
		if c, err = b.dial(ctx, "tcp", net.JoinHostPort(addr, b.port)); err == nil {
			_ = c.Close()
		}
	}
	b.record(err)
	return err
}

// address is the backend's address now, or the last one when the lookup
// fails. The lookup gets half the check's time, so a slow DNS still leaves
// the dial its share.
func (b *backendHealth) address(ctx context.Context) (string, error) {
	if net.ParseIP(b.host) != nil {
		return b.host, nil
	}
	lctx, cancel := context.WithTimeout(ctx, b.timeout/2)
	addrs, err := b.lookup(lctx, b.host)
	cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil && len(addrs) > 0 {
		b.last = addrs[0]
		return b.last, nil
	}
	if b.last != "" {
		return b.last, nil
	}
	if err == nil {
		err = fmt.Errorf("%s has no address", b.host)
	}
	return "", err
}

// record logs each change between up and down, once.
func (b *backendHealth) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	backend := net.JoinHostPort(b.host, b.port)
	switch {
	case err != nil && b.down == "":
		b.down = err.Error()
		log.Warnf("backend %s down: %v", backend, err)
	case err == nil && b.down != "":
		b.down = ""
		log.Infof("backend %s up again", backend)
	}
}

// serveHealth serves h on addr's /healthz until the process ends.
func serveHealth(addr string, h http.Handler) {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", h)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Warnf("health: %v", err)
	}
}
