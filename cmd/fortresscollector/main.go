// Command fortresscollector is the collector of one location of an edge
// service: the machine that stands before a group of edges runs it. It
// keeps a copy of every edge's log and access log, and answers the reads
// of the ops API (status, metrics, logs) for all its edges at once, for
// the edges that pass such reads on to it (policy.yml's collector). See
// docs/operations.md, "The collector".
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sebiee/fortressedge/internal/collect"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fortresscollector: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":9464", "host:port the edges reach the collector on, at their gateway's address; it checks no caller, so only the edges' network may reach it")
	edges := flag.String("edges", "", "the location's edges, as name=host[:port],...; the port is 443 when left out")
	tunnel := flag.String("tunnel", "", "the edges' tunnel name")
	caFile := flag.String("ca", "", "PEM file of the root the edges' certificates chain to; empty trusts the system's roots")
	certFile := flag.String("cert", "", "PEM file of the collector's log-reader certificate, spiffe://<tunnel>/logs/<name>")
	keyFile := flag.String("key", "", "PEM file of that certificate's key")
	dir := flag.String("dir", "/var/lib/fortresscollector", "where the copies of the edges' logs are kept")
	keep := flag.String("keep", "1GiB", "size of the copy of each log of each edge (KiB, MiB, GiB); its oldest lines go first")
	every := flag.Duration("every", 2*time.Second, "how often each edge's logs are read")
	flag.Parse()

	if *tunnel == "" || *certFile == "" || *keyFile == "" {
		return errors.New("-tunnel, -cert and -key are required")
	}
	cfg := collect.Config{Dir: *dir, Every: *every}
	var err error
	if cfg.Edges, err = parseEdges(*edges); err != nil {
		return err
	}
	if cfg.Keep, err = parseSize(*keep); err != nil {
		return fmt.Errorf("-keep: %w", err)
	}
	if *every < 100*time.Millisecond {
		return errors.New("-every: at least 100ms")
	}
	var roots *x509.CertPool
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("-ca: no certificate in %s", *caFile)
		}
	}
	cfg.Fetch = collect.HTTPS(*tunnel, roots, *certFile, *keyFile)
	c, err := collect.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	srv := &http.Server{Addr: *listen, Handler: c, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	go c.Run(ctx)
	slog.Info("fortresscollector up", "version", metrics.Version(), "listen", *listen, "edges", len(cfg.Edges), "dir", *dir, "keep", cfg.Keep)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shut)
}

// parseEdges reads -edges: name=host[:port], separated by commas.
func parseEdges(s string) ([]collect.Edge, error) {
	var out []collect.Edge
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		name, addr, ok := strings.Cut(part, "=")
		if !ok || name == "" || addr == "" {
			return nil, fmt.Errorf("-edges: want name=host[:port], got %q", part)
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "443")
		}
		out = append(out, collect.Edge{Name: name, Addr: addr})
	}
	if len(out) == 0 {
		return nil, errors.New("-edges: name at least one edge, as name=host[:port]")
	}
	return out, nil
}

// parseSize reads a size such as 512MiB or 1GiB.
func parseSize(s string) (int64, error) {
	for unit, mul := range map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30} {
		if num, ok := strings.CutSuffix(s, unit); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
			if err != nil || n < 1 || n > 1<<20 {
				break
			}
			return n * mul, nil
		}
	}
	return 0, fmt.Errorf("want a size such as 512MiB or 1GiB, got %q", s)
}
