//go:build e2e

package lab

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/challtestsrv"
	"github.com/letsencrypt/pebble/v2/acme"
	pebbleca "github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/stretchr/testify/require"
)

// hostAlias is the host as a QEMU user-network guest sees it.
const hostAlias = "10.0.2.2"

// Pebble is Let's Encrypt's test ACME server, in-process, for one VM. Its
// challenge checks resolve every name to the VM through a mock DNS server
// and dial its 443 there: the host forward, or the guest on the tap.
type Pebble struct {
	URL   string // directory URL, as the guest sees it
	TLSCA []byte // PEM that signed URL's certificate: the edge's acme_ca
	Roots string // file with the PEM root that issued certificates chain to

	db *db.MemoryStore

	mu     sync.Mutex
	issued []string // certificate IDs the edge downloaded, in order
}

// PebbleOptions changes what Pebble issues. The zero value is Pebble's
// defaults: 90-day certificates, with ACME Renewal Info (ARI).
type PebbleOptions struct {
	Validity time.Duration // certificate lifetime
	// NoARI leaves renewalInfo out of the directory, so the edge renews
	// on lifetime alone. Pebble's ARI window for a certificate of a few
	// seconds spans its whole life.
	NoARI bool
}

// StartPebble serves an ACME directory to vm. On a tap, call UseTap first.
func StartPebble(t *testing.T, vm *VM, opts PebbleOptions) *Pebble {
	t.Helper()
	// Validate at once, and never reject a good nonce: certmagic retries
	// both, but a retry is minutes, not seconds. Read by va.New and wfe.New.
	os.Setenv("PEBBLE_VA_NOSLEEP", "1")
	os.Setenv("PEBBLE_WFE_NONCEREJECT", "0")

	logf, err := os.Create(filepath.Join(t.ArtifactDir(), "pebble.log"))
	require.NoError(t, err)
	t.Cleanup(func() { logf.Close() })
	logger := log.New(logf, "", log.LstdFlags|log.Lmicroseconds)

	dnsAddr := "127.0.0.1:" + strconv.Itoa(freePort(t))
	dns, err := challtestsrv.New(challtestsrv.Config{DNSAddrs: []string{dnsAddr}, Log: logger})
	require.NoError(t, err)
	dns.SetDefaultDNSIPv4(vm.Addr)
	dns.SetDefaultDNSIPv6("")
	dns.Run()
	t.Cleanup(dns.Shutdown)

	store := db.NewMemoryStore()
	profile := pebbleca.Profile{ValidityPeriod: uint64(opts.Validity / time.Second)}
	issuer := pebbleca.New(logger, store, "", "ecdsa", 0, 1, map[string]pebbleca.Profile{"default": profile})
	validator := va.New(logger, 0, vm.HTTPS, false, dnsAddr, store)
	front := wfe.New(logger, store, validator, issuer, []string{"pebble.letsencrypt.org"}, false, false, 0, 0)

	p := &Pebble{db: store}
	api := front.Handler()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/certZ/"); ok {
			p.mu.Lock()
			if !slices.Contains(p.issued, id) {
				p.issued = append(p.issued, id)
			}
			p.mu.Unlock()
		}
		switch {
		case r.URL.Path == newOrderPath:
			p.aliasReplaced(r)
		case strings.Contains(r.URL.Path, "/renewalInfo/"):
			w = shortRetry{w}
		case opts.NoARI && r.URL.Path == wfe.DirectoryPath:
			withoutARI(w, r, api)
			return
		}
		api.ServeHTTP(w, r)
	}))
	// On slirp the guest dials 10.0.2.2, which slirp hands to the host's
	// loopback. On the tap it dials the host's tap address.
	listen := "127.0.0.1:0"
	if vm.tap {
		listen = TapHost + ":0"
		srv.Listener.Close()
		srv.Listener, err = net.Listen("tcp", listen)
		require.NoError(t, err)
	}
	crt, key := selfSigned(t, net.ParseIP(vm.host()), net.IPv4(127, 0, 0, 1))
	pair, err := tls.X509KeyPair(crt, key)
	require.NoError(t, err)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	p.URL = "https://" + vm.host() + ":" + strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port) + wfe.DirectoryPath
	p.TLSCA = crt
	p.Roots = Write(t, t.TempDir(), "pebble-root.pem", issuer.GetRootCert(0).PEM())
	return p
}

// Issued lists the names of each certificate the edge has downloaded, in
// order. A name that appears twice was issued twice.
func (p *Pebble) Issued() []string {
	p.mu.Lock()
	ids := slices.Clone(p.issued)
	p.mu.Unlock()
	var names []string
	for _, id := range ids {
		if c := p.db.GetCertificateByID(id); c != nil {
			names = append(names, c.Cert.DNSNames...)
		}
	}
	return names
}

// Certificates lists every certificate for name the edge downloaded, in
// order: the record of each renewal, whoever happened to be watching.
func (p *Pebble) Certificates(name string) []*x509.Certificate {
	p.mu.Lock()
	ids := slices.Clone(p.issued)
	p.mu.Unlock()
	var certs []*x509.Certificate
	for _, id := range ids {
		if c := p.db.GetCertificateByID(id); c != nil && slices.Contains(c.Cert.DNSNames, name) {
			certs = append(certs, c.Cert)
		}
	}
	return certs
}

// RenewNow tells the edge, through ACME Renewal Info (ARI), to renew the
// newest certificate it downloaded for name: its renewal window moves to
// the past, as a CA does before it revokes. It returns that certificate's
// serial.
func (p *Pebble) RenewNow(t *testing.T, name string) string {
	t.Helper()
	p.mu.Lock()
	ids := slices.Clone(p.issued)
	p.mu.Unlock()
	for _, id := range slices.Backward(ids) {
		c := p.db.GetCertificateByID(id)
		if c == nil || !slices.Contains(c.Cert.DNSNames, name) {
			continue
		}
		now := time.Now().UTC()
		ari := fmt.Sprintf(`{"suggestedWindow":{"start":%q,"end":%q}}`,
			now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339))
		require.NoError(t, p.db.SetARIResponse(c.Cert.SerialNumber, ari))
		return c.Cert.SerialNumber.String()
	}
	require.FailNow(t, "no certificate downloaded", name)
	return ""
}

// newOrderPath is where Pebble takes new orders; wfe does not export it.
const newOrderPath = "/order-plz"

// aliasReplaced lets Pebble find the certificate a new order replaces
// when its serial's first byte is 0x80 or more. An ARI CertID carries the
// serial as a DER integer, which puts a zero byte in front of such a
// serial (RFC 9773, section 4.1); acmez sends it so, and so must a CA.
// Pebble looks the order up by that hex, but indexes issued orders by the
// hex of big.Int.Bytes(), which has no zero byte, so it rejects the order
// with a 500. Its serials are random below 2^63, so one in 256 is such a
// serial, and certmagic waits minutes before it retries without replaces:
// a short-lived certificate expires first. Before Pebble reads the order,
// this indexes the replaced certificate's order under the padded hex too.
// Only the fields Pebble checks on a replacement are copied: the account,
// the identifiers, and whether it was already replaced, which then lives
// on the alias, where every later lookup lands.
func (p *Pebble) aliasReplaced(r *http.Request) {
	body, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return
	}
	var jws struct{ Payload string }
	if json.Unmarshal(body, &jws) != nil {
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return
	}
	var order struct{ Replaces string }
	if json.Unmarshal(payload, &order) != nil {
		return
	}
	_, serial, _ := strings.Cut(order.Replaces, ".")
	der, err := base64.RawURLEncoding.DecodeString(serial)
	if err != nil || len(der) < 2 || der[0] != 0 {
		return
	}
	padded := hex.EncodeToString(der)
	if _, err := p.db.GetOrderByIssuedSerial(padded); err == nil {
		return
	}
	orig, err := p.db.GetOrderByIssuedSerial(hex.EncodeToString(der[1:]))
	if err != nil {
		return
	}
	orig.RLock()
	alias := &core.Order{
		Order:             acme.Order{Identifiers: slices.Clone(orig.Identifiers)},
		ID:                orig.ID,
		AccountID:         orig.AccountID,
		CertificateObject: &core.Certificate{ID: padded},
		IsReplaced:        orig.IsReplaced,
	}
	orig.RUnlock()
	p.db.AddOrderByIssuedSerial(alias)
}

// withoutARI serves Pebble's directory without its renewalInfo URL.
func withoutARI(w http.ResponseWriter, r *http.Request, api http.Handler) {
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, r)
	var dir map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	delete(dir, "renewalInfo")
	maps.Copy(w.Header(), rec.Header())
	w.Header().Del("Content-Length")
	w.WriteHeader(rec.Code)
	json.NewEncoder(w).Encode(dir)
}

// shortRetry makes Pebble's ARI answers say "ask again in a second", not
// in six hours, so the edge sees a window RenewNow moved on its next
// handshake.
type shortRetry struct{ http.ResponseWriter }

func (w shortRetry) WriteHeader(code int) {
	w.shorten()
	w.ResponseWriter.WriteHeader(code)
}

func (w shortRetry) Write(b []byte) (int, error) {
	w.shorten()
	return w.ResponseWriter.Write(b)
}

func (w shortRetry) shorten() {
	if w.Header().Get("Retry-After") != "" {
		w.Header().Set("Retry-After", "1")
	}
}

func selfSigned(t *testing.T, ips ...net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pebble"},
		IPAddresses:           ips,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(k)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
