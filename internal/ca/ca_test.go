package ca

import (
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestInitAndClient(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, []string{"tunnel.example.com", "app.example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"spiffe://tunnel.example.com/node/node1",
		"spiffe://tunnel.example.com/ops/alice",
		"spiffe://tunnel.example.com/logs/filebeat",
	} {
		if err := Client(dir, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := Client(dir, "node1"); err == nil { // not a SPIFFE ID
		t.Fatal("want error")
	}
	pool, err := LoadPool(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	crt, key := ClientFiles(dir, RoleOps, "alice")
	if _, err := os.Stat(key); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	if role, name, ok := Identify(cert, "Tunnel.Example.com"); !ok || role != RoleOps || name != "alice" {
		t.Fatalf("Identify = %q %q %v", role, name, ok)
	}
	if _, _, ok := Identify(cert, "other.example.com"); ok {
		t.Fatal("a certificate for another tunnel was accepted")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
}

func TestParseID(t *testing.T) {
	td, role, name, err := ParseID(ID("tunnel.example.com", RoleLogs, "vector-1"))
	if err != nil || td != "tunnel.example.com" || role != RoleLogs || name != "vector-1" {
		t.Fatalf("%q %q %q %v", td, role, name, err)
	}
	for _, id := range []string{
		"spiffe://tunnel.example.com/ops",             // no name: the old shared ops identity
		"spiffe://tunnel.example.com/admin/alice",     // unknown role
		"spiffe://tunnel.example.com/ops/alice/extra", // too deep
		"spiffe://tunnel.example.com/ops/Alice",       // names are lower case
		"spiffe://tunnel.example.com/ops/-x",          // must start alphanumeric
		"spiffe://tunnel.example.com/node/",
		"https://tunnel.example.com/ops/alice",
		"spiffe:///ops/alice",
		"spiffe://tunnel.example.com/ops/alice?x=1",
	} {
		if _, _, _, err := ParseID(id); err == nil {
			t.Errorf("accepted %q", id)
		}
	}
}

func TestIdentifyNeedsExactlyOneURI(t *testing.T) {
	a, _ := url.Parse("spiffe://tunnel.example.com/ops/alice")
	b, _ := url.Parse("spiffe://tunnel.example.com/node/n1")
	for name, uris := range map[string][]*url.URL{"none": nil, "two": {a, b}} {
		if _, _, ok := Identify(&x509.Certificate{URIs: uris}, "tunnel.example.com"); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, ok := Identify(nil, "tunnel.example.com"); ok {
		t.Error("nil certificate accepted")
	}
}
