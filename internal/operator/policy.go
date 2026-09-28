package operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/Sebiee/fortressedge/internal/config"
)

// Edge is how fortressctl reaches one edge's ops API: by its fqdn, which
// is the SNI and the name its certificate is for, with an operator's
// client certificate.
type Edge struct {
	Name string
	// Connect is host:port to dial instead of Name:443, for an edge that
	// DNS does not point at yet.
	Connect string
	// CACert is a PEM file of roots for the edge's certificate: the ACME
	// server's CA. Empty is the system roots.
	CACert    string
	Cert, Key string // an ops/<name> client certificate
}

// Apply puts the policy.yml at path on the edge. It is checked here first,
// so a mistake is reported without a round trip.
func Apply(e Edge, path string, out io.Writer) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := config.ParsePolicy(body); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, e.url(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/yaml")
	msg, _, err := do(c, req)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: %s", e.Name, strings.TrimPrefix(msg, "fortressedge: "))
	return nil
}

// ErrDrift is Diff's result when the edge's policy is not the file's.
var ErrDrift = errors.New("the edge's policy differs from the file")

// Diff compares the edge's policy with the policy.yml at path, byte for
// byte, and writes a unified diff when they differ: fortressctl apply
// would change the edge. The edge keeps what apply sent, so a file that
// was applied reads back the same.
func Diff(e Edge, path string, out io.Writer) error {
	want, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c, err := e.client()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, e.url(), nil)
	if err != nil {
		return err
	}
	have, etag, err := do(c, req)
	if err != nil {
		return err
	}
	if etag == config.PolicyETag(want) {
		fmt.Fprintf(out, "%s: in sync with %s\n", e.Name, path)
		return nil
	}
	d, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(have), B: difflib.SplitLines(string(want)),
		FromFile: e.Name, ToFile: path, Context: 3,
	})
	if err != nil {
		return err
	}
	if have == "" {
		fmt.Fprintf(out, "%s has no policy yet: it runs the defaults\n", e.Name)
	}
	fmt.Fprint(out, d)
	return ErrDrift
}

func (e Edge) url() string { return "https://" + e.Name + config.OpsPolicyPath }

func (e Edge) client() (*http.Client, error) {
	if e.Name == "" {
		return nil, errors.New("no edge name")
	}
	cert, err := tls.LoadX509KeyPair(e.Cert, e.Key)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, ServerName: e.Name, MinVersion: tls.VersionTLS12}
	if e.CACert != "" {
		pem, err := os.ReadFile(e.CACert)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates", e.CACert)
		}
	}
	tr := &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: false}
	if e.Connect != "" {
		d := &net.Dialer{Timeout: 10 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, e.Connect)
		}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// do sends req and returns the body and ETag of a 200 reply; any other
// status is an error carrying the edge's message.
func do(c *http.Client, req *http.Request) (body, etag string, err error) {
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, strings.TrimSpace(string(b)))
	}
	return string(b), resp.Header.Get("ETag"), nil
}
