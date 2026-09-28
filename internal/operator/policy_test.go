package operator

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/ops"
)

const tunnel = "edge1.example.com"

// policyEdge serves the ops API over mTLS as the edge does, and returns
// how fortressctl reaches it with an operator certificate. applied holds
// what each accepted PUT carried.
func policyEdge(t *testing.T) (e Edge, applied *[]string) {
	t.Helper()
	pki := filepath.Join(t.TempDir(), "tls")
	if err := ca.Init(pki, []string{tunnel}); err != nil {
		t.Fatal(err)
	}
	if err := ca.Client(pki, ca.ID(tunnel, ca.RoleOps, "alice")); err != nil {
		t.Fatal(err)
	}
	server, err := tls.LoadX509KeyPair(filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	applied = new([]string)
	h := ops.New(config.Config{Tunnel: tunnel}, nil, "boot", t.TempDir())
	h.SetApply(func(b []byte) (ops.Outcome, error) {
		if _, err := config.ParsePolicy(b); err != nil {
			return ops.Outcome{}, &config.InvalidError{Err: err}
		}
		*applied = append(*applied, string(b))
		return ops.Outcome{}, nil
	}, nil)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	crt, key := ca.ClientFiles(pki, ca.RoleOps, "alice")
	return Edge{Name: tunnel, Connect: srv.Listener.Addr().String(), CACert: filepath.Join(pki, "ca.crt"), Cert: crt, Key: key}, applied
}

func TestApplyAndDiff(t *testing.T) {
	e, applied := policyEdge(t)
	dir := t.TempDir()
	policy := write(t, dir, "policy.yml", "block: [192.0.2.9]\nlimits:\n  requests_per_second: 50\n")

	var out bytes.Buffer
	if err := Diff(e, policy, &out); !errors.Is(err, ErrDrift) || !strings.Contains(out.String(), "has no policy yet") ||
		!strings.Contains(out.String(), "+block: [192.0.2.9]") {
		t.Fatalf("diff before apply: %v\n%s", err, out.String())
	}

	out.Reset()
	if err := Apply(e, policy, &out); err != nil || out.String() != tunnel+": policy applied\n" {
		t.Fatalf("apply: %v %q", err, out.String())
	}
	out.Reset()
	if err := Apply(e, policy, &out); err != nil || !strings.Contains(out.String(), "unchanged") || len(*applied) != 1 {
		t.Fatalf("apply again: %v %q %q", err, out.String(), *applied)
	}
	out.Reset()
	if err := Diff(e, policy, &out); err != nil || !strings.Contains(out.String(), "in sync") {
		t.Fatalf("diff after apply: %v\n%s", err, out.String())
	}

	// A change in git shows as a diff of the lines that moved.
	write(t, dir, "policy.yml", "block: [192.0.2.9, 198.51.100.0/24]\nlimits:\n  requests_per_second: 50\n")
	out.Reset()
	if err := Diff(e, policy, &out); !errors.Is(err, ErrDrift) ||
		!strings.Contains(out.String(), "-block: [192.0.2.9]\n+block: [192.0.2.9, 198.51.100.0/24]") {
		t.Fatalf("diff after a change: %v\n%s", err, out.String())
	}
}

// A mistake is caught before it is sent.
func TestApplyChecksFirst(t *testing.T) {
	e, applied := policyEdge(t)
	dir := t.TempDir()
	for _, bad := range []string{"quic: true\n", "block: [nope]\n"} {
		if err := Apply(e, write(t, dir, "policy.yml", bad), &bytes.Buffer{}); err == nil {
			t.Errorf("%q: applied", bad)
		}
	}
	if len(*applied) != 0 {
		t.Fatalf("sent: %q", *applied)
	}
	// Without the operator certificate, the edge is not reached.
	e.Key = filepath.Join(dir, "missing.key")
	if err := Apply(e, write(t, dir, "policy.yml", "block: []\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("applied without a key")
	}
}
