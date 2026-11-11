package collect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTPS is the Fetch that asks an edge at its address, under the tunnel
// name, as the edge's ops API wants it: TLS that names the tunnel, with a
// log-reader certificate (spiffe://<tunnel>/logs/<name>). The certificate
// is read from its files at every connection, so a renewed one is used
// without a restart. roots nil trusts the system's.
func HTTPS(tunnel string, roots *x509.CertPool, certFile, keyFile string) Fetch {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: tunnel,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				c, err := tls.LoadX509KeyPair(certFile, keyFile)
				return &c, err
			},
		},
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   4,
		// Under the edge's own 65 s, so the collector closes first.
		IdleConnTimeout: 30 * time.Second,
	}}
	return func(ctx context.Context, e Edge, path string, q url.Values) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+e.Addr+path+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Host = tunnel
		return client.Do(req)
	}
}
