package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// client_ca holds one CA or several, as PEM certificates and nothing else:
// whatever the edge trusts, a reader of the file sees.
func TestParseCAs(t *testing.T) {
	newCA := func() (string, []byte) {
		t.Helper()
		crt, key, err := NewCA()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(crt)), key
	}
	a, aKey := newCA()
	b, _ := newCA()
	for _, tc := range []struct {
		name, pem string
		n         int
	}{
		{"one", a, 1},
		{"two", a + "\n" + b + "\n", 2},
		{"two with blank lines and indentation", "\n" + a + "\n\n   " + b + "\n\n", 2},
	} {
		cas, err := ParseCAs([]byte(tc.pem))
		if err != nil || len(cas) != tc.n {
			t.Fatalf("%s: %d CAs, %v; want %d", tc.name, len(cas), err, tc.n)
		}
	}
	cas, _ := ParseCAs([]byte(a + "\n" + b))
	first, _ := ParseCAs([]byte(a))
	if !cas[0].Equal(first[0]) || Fingerprint(cas[0]) == Fingerprint(cas[1]) || len(Fingerprint(cas[0])) != 64 {
		t.Fatal("the CAs are not in the file's order, or their fingerprints do not tell them apart")
	}

	caCert, caKey, err := ParseCA([]byte(a), aKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := SignClient(caCert, caKey, ID("tunnel.example.com", RoleNode, "node1"), &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tooMany := ""
	for range MaxCAs + 1 {
		c, _ := newCA()
		tooMany += c + "\n"
	}
	for name, bad := range map[string]string{
		"empty":                          "  \n",
		"text before":                    "subject=CN = old CA\n" + a,
		"text between":                   a + "\nsubject=CN = new CA\n" + b,
		"text after":                     a + "\n# the old one\n",
		"a key":                          a + "\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIB==\n-----END EC PRIVATE KEY-----",
		"PEM headers":                    strings.Replace(a, "-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nComment: old\n\n", 1),
		"the same CA twice":              a + "\n" + b + "\n" + a,
		"more than MaxCAs":               tooMany,
		"a certificate that is not a CA": a + "\n" + string(leaf),
		"a broken block":                 "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----",
	} {
		if _, err := ParseCAs([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
