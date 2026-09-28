package bake

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/ca"
)

func TestISO(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vmlinuz", "isolinux.bin", "ldlinux.c32"} {
		if err := os.WriteFile(filepath.Join(dir, name), append([]byte(name), make([]byte, 4096)...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var initrd bytes.Buffer // a release's initramfs is gzip; bake appends to it
	gz := gzip.NewWriter(&initrd)
	gz.Write([]byte("070701"))
	gz.Close()
	if err := os.WriteFile(filepath.Join(dir, "initrd"), initrd.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(dir, "release.iso")
	if err := WriteISO(release, filepath.Join(dir, "vmlinuz"), filepath.Join(dir, "initrd"),
		filepath.Join(dir, "isolinux.bin"), filepath.Join(dir, "ldlinux.c32"), time.Unix(1790000000, 0)); err != nil {
		t.Fatal(err)
	}
	crt, _, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	edge := []byte("quic: true\nclient_ca: |\n  " + strings.ReplaceAll(strings.TrimSpace(string(crt)), "\n", "\n  ") + "\n")
	if err := Check(edge); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(dir, "a.iso"), filepath.Join(dir, "b.iso")
	for _, out := range []string{a, b} {
		if err := ISO(out, release, edge); err != nil {
			t.Fatal(err)
		}
	}
	ab, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if !bytes.Equal(ab, bb) || !bytes.Contains(ab, []byte("quic: true")) {
		t.Fatal("two bakes differ, or the file is missing")
	}
	if err := ISO(filepath.Join(dir, "c.iso"), release, []byte("block: [192.0.2.9]\n")); err == nil {
		t.Fatal("baked a policy key")
	}
}
