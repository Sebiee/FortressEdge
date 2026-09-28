package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// NewCA generates a self-signed client CA in memory. It runs on the
// operator's workstation (fortressctl); the edge never holds a CA key.
func NewCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	der, err := createCert(&x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "fortressedge-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// Role is what a client certificate may do.
type Role string

const (
	RoleNode Role = "node" // a dark node: the frp tunnel, nothing else
	RoleOps  Role = "ops"  // an operator: the whole ops API
	RoleLogs Role = "logs" // a log shipper or monitor: logs and status, read-only
)

// Identity is a SPIFFE ID in the certificate's only URI SAN, never the CN.
// The trust domain is the tunnel name, so a certificate for one edge is
// worth nothing at another that shares its CA. The name identifies one
// node, operator, or shipper in the edge's log.
//
//	spiffe://tunnel.example.com/node/node1
//	spiffe://tunnel.example.com/ops/alice
//	spiffe://tunnel.example.com/logs/filebeat
func ID(trustDomain string, role Role, name string) string {
	return "spiffe://" + trustDomain + "/" + string(role) + "/" + name
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ParseID splits a SPIFFE ID of the form above. The role must be one the
// edge knows and the name 1-63 of [a-z0-9._-], starting alphanumeric.
func ParseID(id string) (trustDomain string, role Role, name string, err error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", "", fmt.Errorf("identity: want spiffe://<tunnel>/<role>/<name>, got %q", id)
	}
	r, n, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	switch role = Role(r); {
	case !ok || (role != RoleNode && role != RoleOps && role != RoleLogs):
		return "", "", "", fmt.Errorf("identity: want a role of node, ops, or logs in %q", id)
	case !nameRE.MatchString(n):
		return "", "", "", fmt.Errorf("identity: want a name of 1-63 of a-z, 0-9, '.', '_', '-' in %q", id)
	}
	return u.Host, role, n, nil
}

// Identify is the role and name of a verified client certificate issued
// for trustDomain. ok is false for anything else: no URI SAN, more than
// one, another trust domain, or an unknown role.
func Identify(cert *x509.Certificate, trustDomain string) (role Role, name string, ok bool) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", "", false
	}
	td, role, name, err := ParseID(cert.URIs[0].String())
	if err != nil || !strings.EqualFold(td, trustDomain) {
		return "", "", false
	}
	return role, name, true
}

// SignClient signs pub — the caller's public key, so private keys never
// cross the wire — as a client cert carrying id (a SPIFFE ID) in its URI
// SAN. The CN repeats the ID for openssl readability; nothing consults it.
func SignClient(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, id string, pub any) ([]byte, error) {
	if _, _, _, err := ParseID(id); err != nil {
		return nil, err
	}
	u, _ := url.Parse(id)
	now := time.Now()
	der, err := createCert(&x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: id},
		URIs:         []*url.URL{u},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, caCert, pub, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SignServer generates a server key and signs it for names: a test's
// stand-in for an edge, whose own certificates come from ACME.
func SignServer(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, names []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	der, err := createCert(&x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// ParseCA decodes a CA cert+key PEM pair.
func ParseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("no PEM private key")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// Init writes a self-signed CA (ca.key/ca.crt) into dir. With serverNames it
// also issues a server cert (server.key/server.crt), for tests.
func Init(dir string, serverNames []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPEM, keyPEM, err := NewCA()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o644); err != nil {
		return err
	}
	if len(serverNames) == 0 {
		return nil
	}
	caCert, caKey, err := loadCA(dir)
	if err != nil {
		return err
	}
	srvCrt, srvKey, err := SignServer(caCert, caKey, serverNames)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), srvKey, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "server.crt"), srvCrt, 0o644)
}

// Client signs a client certificate for a SPIFFE ID with the CA in dir and
// writes it, with a new key, to dir/clients/<role>/<name>.crt and .key.
func Client(dir, id string) error {
	_, role, name, err := ParseID(id)
	if err != nil {
		return err
	}
	caCert, caKey, err := loadCA(dir)
	if err != nil {
		return err
	}
	out := filepath.Join(dir, "clients", string(role))
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	crt, err := SignClient(caCert, caKey, id, &key.PublicKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(out, name+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, name+".crt"), crt, 0o644)
}

// ClientFiles is where Client writes id's certificate and key.
func ClientFiles(dir string, role Role, name string) (crt, key string) {
	base := filepath.Join(dir, "clients", string(role), name)
	return base + ".crt", base + ".key"
}

func loadCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	crtPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, nil, err
	}
	cert, key, err := ParseCA(crtPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", dir, err)
	}
	return cert, key, nil
}

func createCert(tmpl, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) ([]byte, error) {
	if parent == nil {
		parent = tmpl
	}
	return x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

// ParseCertPEM returns the first certificate in pemBytes.
func ParseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, fmt.Errorf("no PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ParseCAPEM parses exactly one PEM certificate, which must be a CA's.
// Anything after it is refused: a trust anchor that holds a second
// certificate would trust that one too, and a reader of the file might
// see only the first.
func ParseCAPEM(pemBytes []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(pemBytes)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("more than one certificate: give the one CA")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	if !c.IsCA {
		return nil, fmt.Errorf("%q is not a CA certificate", c.Subject.CommonName)
	}
	return c, nil
}

// LoadPool reads a PEM CA bundle into a pool.
func LoadPool(caPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("client CA: no certificates in %s", caPath)
	}
	return pool, nil
}
