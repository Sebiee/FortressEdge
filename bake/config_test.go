package bake

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
)

// Config has a field for every key the edge reads, and no other: a new
// fortress.yml key fails here until Config carries it, and so reaches the
// tools built on this package.
func TestConfigHasEveryKey(t *testing.T) {
	got, want := Keys(), config.EdgeKeys()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("Config's keys %v, the edge's %v", got, want)
	}
}

func testCA(t *testing.T) string {
	t.Helper()
	crt, _, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	return string(crt)
}

// Every field reaches the edge as the setting it names.
func TestConfigYAMLIsWhatTheEdgeReads(t *testing.T) {
	c := Config{
		ClientCA:      testCA(t),
		ACME:          "https://vault.example.com:8200/v1/pki/acme/directory",
		ACMECA:        testCA(t),
		NTP:           "10.0.0.1:123",
		RenewInterval: "90m",
		QUIC:          true,
	}
	if err := c.Check(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("#cloud-config\nfqdn: edge1.example.com\n"),
		[]byte("version: 2\nethernets:\n  eth0:\n    addresses: [192.0.2.10/24]\n    gateway4: 192.0.2.1\n"), c.YAML(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACME != c.ACME || string(cfg.ACMECA) != strings.TrimSpace(c.ACMECA) || string(cfg.ClientCA) != strings.TrimSpace(c.ClientCA) ||
		cfg.NTP != c.NTP || cfg.RenewInterval != 90*time.Minute || !cfg.QUIC {
		t.Fatalf("%+v", cfg)
	}
}

// A field left at its zero value leaves its key out: the edge's default.
func TestConfigYAMLLeavesDefaultsOut(t *testing.T) {
	ca := testCA(t)
	got := string(Config{ClientCA: ca}.YAML())
	want := "client_ca: |\n  " + strings.ReplaceAll(strings.TrimSpace(ca), "\n", "\n  ") + "\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if err := (Config{ACME: "https://ca.example/dir"}).Check(); err == nil || !strings.Contains(err.Error(), "client_ca") {
		t.Fatalf("no client_ca: %v", err)
	}
	if err := (Config{ClientCA: ca, ACME: "not a url"}).Check(); err == nil || !strings.Contains(err.Error(), "fortress.yml: acme:") {
		t.Fatalf("bad acme: %v", err)
	}
}
