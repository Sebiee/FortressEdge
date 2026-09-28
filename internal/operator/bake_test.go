package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sebiee/fortressedge/internal/ca"
)

func TestReadEdge(t *testing.T) {
	dir := t.TempDir()
	crt, _, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	clientCA := "client_ca: |\n  " + strings.ReplaceAll(strings.TrimSpace(string(crt)), "\n", "\n  ") + "\n"
	good := write(t, dir, "good.yml", "acme: https://ca.internal/acme/directory\nquic: true\n"+clientCA)
	if b, err := ReadEdge(good); err != nil || !strings.HasPrefix(string(b), "acme:") {
		t.Fatalf("%q %v", b, err)
	}
	for name, body := range map[string]string{
		"no client_ca": "quic: true\n",
		"policy":       "block: [192.0.2.9]\n" + clientCA,
		"not yaml":     "quic: [\n",
	} {
		if _, err := ReadEdge(write(t, dir, strings.ReplaceAll(name, " ", "-"), body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ReadEdge(filepath.Join(dir, "missing.yml")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
