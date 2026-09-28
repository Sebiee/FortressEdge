package httpsvc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"

	"github.com/Sebiee/fortressedge/internal/config"
)

var fqdnRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$`)

// Domains is the set of hostnames that currently have an HTTP route.
// frps reports a name when its first route appears and when its last route
// disappears. Under tls: acme, the first report of an exact name manages
// its certificate: loaded from disk, or obtained. certmagic's timer then
// checks it every renew_interval and renews it once it is due. The last
// report stops that; the certificate stays on disk.
type Domains struct {
	tunnel string

	mu    sync.Mutex
	names map[string]context.CancelFunc // cancel stops that name's pending obtain
	magic *certmagic.Config
	cache *certmagic.Cache

	acmeMu    sync.Mutex // held while the tunnel certificate is obtained
	acmeMagic *certmagic.Config
}

func NewDomains(tunnel string) *Domains {
	return &Domains{tunnel: hostname(tunnel)}
}

// setMagic starts managing the names registered before ACME was ready.
func (d *Domains) setMagic(magic *certmagic.Config, cache *certmagic.Cache) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.magic, d.cache = magic, cache
	for name := range d.names {
		d.startLocked(name)
	}
}

// Domain is the frps vhost callback. added is true when the name gains its
// first route and false when it loses its last. frps calls it with its
// router lock held, so the obtain runs in the background.
func (d *Domains) Domain(domain string, added bool) {
	if d == nil {
		return
	}
	domain = hostname(domain)
	if domain == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !added {
		if cancel, ok := d.names[domain]; ok {
			cancel()
			delete(d.names, domain)
			d.unmanageLocked(domain)
		}
		return
	}
	if _, ok := d.names[domain]; ok {
		return
	}
	if d.names == nil {
		d.names = map[string]context.CancelFunc{}
	}
	d.names[domain] = func() {}
	d.startLocked(domain)
}

// startLocked manages name's certificate in the background, when ACME is
// ready and the name can have one.
func (d *Domains) startLocked(name string) {
	if d.magic == nil || !issueable(name) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.names[name] = cancel
	go func(magic *certmagic.Config, cache *certmagic.Cache) {
		err := manage(ctx, magic, cache, name)
		if err != nil && ctx.Err() == nil {
			slog.Warn("acme: certificate", "name", name, "err", err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		// The name may have left while its certificate was being fetched.
		if _, ok := d.names[name]; !ok {
			d.unmanageLocked(name)
		}
	}(d.magic, d.cache)
}

// unmanageLocked drops name from the cache, so the timer stops renewing it.
func (d *Domains) unmanageLocked(name string) {
	if d.cache != nil && name != d.tunnel {
		d.cache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: name}})
	}
}

// manage puts name's certificate in the cache as a managed certificate:
// loaded from disk, or obtained when there is none. certmagic's timer
// renews cached managed certificates. One that already expired, after the
// edge was off for a while, is renewed here first. Every call is
// non-interactive: certmagic's Sync variants prompt on the console for an
// email address.
func manage(ctx context.Context, magic *certmagic.Config, cache *certmagic.Cache, name string) error {
	cert, err := magic.CacheManagedCertificate(ctx, name)
	if errors.Is(err, fs.ErrNotExist) {
		// ObtainCertAsync retries for up to 30 days; cancelling ctx stops it.
		if err := magic.ObtainCertAsync(ctx, name); err != nil {
			return err
		}
		cert, err = magic.CacheManagedCertificate(ctx, name)
	}
	if err != nil || !cert.Expired() {
		return err
	}
	if err := magic.RenewCertAsync(ctx, name, false); err != nil {
		return err
	}
	if _, err := magic.CacheManagedCertificate(ctx, name); err != nil {
		return err
	}
	cache.Remove([]string{cert.Hash()})
	return nil
}

// acme is the one certmagic config behind TCP 443 and QUIC, created on
// first use. It returns once the tunnel certificate is cached, because a
// dark node cannot connect without it.
func (d *Domains) acme(ctx context.Context, cfg config.Config) (*certmagic.Config, error) {
	d.acmeMu.Lock()
	defer d.acmeMu.Unlock()
	if d.acmeMagic != nil {
		return d.acmeMagic, nil
	}
	magic, cache, err := acmeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err := manage(ctx, magic, cache, cfg.Tunnel); err != nil {
		return nil, err
	}
	slog.Info("tls: tunnel certificate ready", "name", cfg.Tunnel, "renew_interval", cfg.RenewInterval)
	d.setMagic(magic, cache)
	d.acmeMagic = magic
	return magic, nil
}

// Allowed is the tunnel name, or an exact name a dark node currently has
// registered: the names that may have a certificate.
func (d *Domains) Allowed(name string) bool {
	if d == nil {
		return false
	}
	name = hostname(name)
	if name == "" {
		return false
	}
	if name == d.tunnel {
		return true
	}
	if !issueable(name) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.names[name]
	return ok
}

// Routed reports whether frps has a route for host, matched the way its
// router matches: the exact name, then each wildcard parent down to three
// labels (a.b.example.com tries *.b.example.com, then *.example.com), then
// a catch-all "*".
func (d *Domains) Routed(host string) bool {
	if d == nil {
		return false
	}
	host = hostname(host)
	if host == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.names[host]; ok {
		return true
	}
	labels := strings.Split(host, ".")
	for len(labels) >= 3 {
		labels[0] = "*"
		if _, ok := d.names[strings.Join(labels, ".")]; ok {
			return true
		}
		labels = labels[1:]
	}
	_, ok := d.names["*"]
	return ok
}

// Known is a name the edge answers for: the tunnel or a routed site.
// Anything else gets no certificate, no status code, and no bytes.
func (d *Domains) Known(name string) bool {
	if d == nil {
		return false
	}
	if d.tunnel != "" && hostname(name) == d.tunnel {
		return true
	}
	return d.Routed(name)
}

// certificate serves the tunnel name and registered names from the cache.
// A name that lost its route has no certificate, even when one is still on
// disk.
func (d *Domains) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	d.mu.Lock()
	magic := d.magic
	d.mu.Unlock()
	if magic == nil {
		return nil, fmt.Errorf("acme: not ready")
	}
	if !d.Allowed(hello.ServerName) {
		return nil, fmt.Errorf("acme: %s is not registered", hello.ServerName)
	}
	return magic.GetCertificate(hello)
}

func issueable(name string) bool {
	if len(name) < 1 || len(name) > 253 {
		return false
	}
	return fqdnRegex.MatchString(name)
}
