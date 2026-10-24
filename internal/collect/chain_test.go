package collect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/config"
)

// logReader writes a client certificate with the SPIFFE ID of a log reader
// of tunnel to files, as the collector and a reader hold one.
func logReader(t *testing.T, tunnel, name string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := url.Parse("spiffe://" + tunnel + "/logs/" + name)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, URIs: []*url.URL{id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// A reader that asks one edge gets the location: the edge checks its
// certificate and passes the read to the collector, which asks every edge
// for itself, over TLS, with its own log-reader certificate.
func TestAReadOfOneEdgeIsTheLocations(t *testing.T) {
	// httptest's certificate is for this name, which stands for the tunnel.
	const tunnel = "example.com"
	roots := x509.NewCertPool()
	col := httptest.NewUnstartedServer(nil)
	t.Cleanup(col.Close)
	at := col.Listener.Addr().String()
	edges := map[string]*edge{"a": newEdgeOf(t, "boota", tunnel, at), "b": newEdgeOf(t, "bootb", tunnel, at)}
	var list []Edge
	for name, e := range edges {
		srv := httptest.NewUnstartedServer(e.h)
		// The edge's TLS layer checks the certificate against the client CA;
		// here any is taken, and the ops API reads its SPIFFE ID.
		srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		roots.AddCert(srv.Certificate())
		list = append(list, Edge{Name: name, Addr: srv.Listener.Addr().String()})
		e.write("", "time=1 msg=from-"+name+"\n")
	}
	cert, key := logReader(t, tunnel, "collector")
	c, err := New(Config{Edges: list, Fetch: HTTPS(tunnel, roots, cert, key), Dir: t.TempDir(), Keep: 1 << 20, Every: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c.copyAll()
	col.Config.Handler = c
	col.Start()

	rc, rk := logReader(t, tunnel, "reader")
	pair, err := tls.LoadX509KeyPair(rc, rk)
	if err != nil {
		t.Fatal(err)
	}
	reader := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		ServerName: tunnel, RootCAs: roots, Certificates: []tls.Certificate{pair},
	}}}
	read := func(path string) string {
		t.Helper()
		resp, err := reader.Get("https://" + list[0].Addr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %s %s", path, resp.Status, b)
		}
		return string(b)
	}

	logs := read(config.OpsLogsPath)
	if !strings.Contains(logs, "msg=from-a edge=a\n") || !strings.Contains(logs, "msg=from-b edge=b\n") {
		t.Fatalf("the location's logs: %q", logs)
	}
	m := read(config.OpsMetricsPath)
	if !strings.Contains(m, `fortressedge_connections{edge="a"} 3`) || !strings.Contains(m, `fortressedge_connections{edge="b"} 3`) ||
		!strings.Contains(m, `fortresscollector_edge_up{edge="b"} 1`) {
		t.Fatalf("the location's metrics:\n%s", m)
	}
	// For the edge itself.
	own := read(config.OpsLogsPath + "?" + config.OpsSelf)
	if strings.Contains(own, "edge=") || !strings.Contains(own, "msg=from-"+list[0].Name) {
		t.Fatalf("the edge's own log: %q", own)
	}
}
