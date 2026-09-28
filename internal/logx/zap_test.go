package logx

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestZapBecomesSlog(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	log := zap.New(zapCore{h: h}).Named("renew").With(zap.String("identifiers", "a.example.com"))
	log.Debug("hidden")
	log.Info("certificate renewed", zap.Duration("remaining", 90*time.Second), zap.Int("attempt", 2),
		zap.Bool("ari", true), zap.Strings("names", []string{"a", "b"}))
	log.Error("could not renew", zap.Error(errors.New("rate limited")))
	log.Warn("x", zap.Error(nil))

	got := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		`level=INFO msg="certificate renewed" identifiers=a.example.com logger=renew remaining=1m30s attempt=2 ari=true names="[a b]"`,
		`level=ERROR msg="could not renew" identifiers=a.example.com logger=renew error="rate limited"`,
		`level=WARN msg=x identifiers=a.example.com logger=renew`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
