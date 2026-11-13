package httpsvc

import (
	"crypto/x509"
	"log/slog"
	"time"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/metrics"
)

// clientCAEnding is how long before a client CA's end the boot log warns.
const clientCAEnding = 30 * 24 * time.Hour

// clientCAStatus lists the client CAs the edge trusts, as the status shows
// them: during a change of CA, which edges still trust the old one.
func clientCAStatus(cas []*x509.Certificate) []map[string]any {
	out := make([]map[string]any, 0, len(cas))
	for _, c := range cas {
		out = append(out, map[string]any{
			"subject":   c.Subject.String(),
			"sha256":    ca.Fingerprint(c),
			"not_after": c.NotAfter.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func writeClientCAMetrics(w *metrics.Writer, cas []*x509.Certificate) {
	w.Family("fortressedge_client_ca_not_after_seconds", "gauge",
		"When each client CA the edge trusts ends, in Unix seconds, by its SHA-256 and subject.")
	for _, c := range cas {
		w.Int("fortressedge_client_ca_not_after_seconds", c.NotAfter.Unix(),
			"sha256", ca.Fingerprint(c), "subject", c.Subject.String())
	}
}

// logClientCAs says at boot which client CAs the edge trusts, and warns of
// one that has ended or ends within clientCAEnding: certificates it signed
// stop working then.
func logClientCAs(cas []*x509.Certificate, now time.Time) {
	for _, c := range cas {
		args := []any{"subject", c.Subject.String(), "sha256", ca.Fingerprint(c), "not_after", c.NotAfter.UTC().Format(time.RFC3339)}
		switch {
		case now.After(c.NotAfter):
			slog.Warn("client CA has ended: no certificate it signed is accepted", args...)
		case c.NotAfter.Sub(now) < clientCAEnding:
			slog.Warn("client CA ends soon", args...)
		default:
			slog.Info("client CA", args...)
		}
	}
	if len(cas) > 1 {
		slog.Info("client CAs: each can name any node, operator, and log reader of this edge", "count", len(cas))
	}
}
