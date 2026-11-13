package httpsvc

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// The status and the metrics list every client CA the edge trusts, by
// subject, fingerprint, and end: during a change of CA, which edges still
// trust the old one.
func TestClientCAsInStatusAndMetrics(t *testing.T) {
	var bundle []byte
	for range 2 {
		crt, _, err := ca.NewCA()
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, crt...)
	}
	cas, err := ca.ParseCAs(bundle)
	if err != nil {
		t.Fatal(err)
	}
	st := clientCAStatus(cas)
	if len(st) != 2 || st[0]["sha256"] != ca.Fingerprint(cas[0]) || st[1]["subject"] != "CN=fortressedge-ca" ||
		st[0]["not_after"] != cas[0].NotAfter.UTC().Format("2006-01-02T15:04:05Z") {
		t.Fatalf("status: %v", st)
	}
	var b bytes.Buffer
	w := metrics.NewWriter(&b)
	writeClientCAMetrics(w, cas)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		want := `fortressedge_client_ca_not_after_seconds{sha256="` + ca.Fingerprint(c) + `",subject="CN=fortressedge-ca"} `
		if !strings.Contains(b.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, b.String())
		}
	}
}
