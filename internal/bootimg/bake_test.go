package bootimg

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sebiee/fortressedge/internal/ca"
)

// testRelease writes a release ISO in dir and returns its path and
// initramfs.
func testRelease(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	for _, name := range []string{"vmlinuz", "isolinux.bin", "ldlinux.c32"} {
		body := append([]byte("payload-"+name), bytes.Repeat([]byte{0}, 4096)...)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	initrd := filepath.Join(dir, "initrd")
	var release bytes.Buffer
	gz := gzip.NewWriter(&release)
	if err := writeCPIO(gz, []entry{{"init", 0o100755, []byte("edge")}}); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	if err := os.WriteFile(initrd, release.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "release.iso")
	if err := WriteISO(src, filepath.Join(dir, "vmlinuz"), initrd, filepath.Join(dir, "isolinux.bin"), filepath.Join(dir, "ldlinux.c32"), testTime); err != nil {
		t.Fatal(err)
	}
	return src, release.Bytes()
}

// bakedCPIO is the uncompressed initramfs of the ISO at path.
func bakedCPIO(t *testing.T, path string) []byte {
	t.Helper()
	out := t.TempDir()
	if err := extract(path, out, map[string]string{"boot/initramfs.gz": "initrd"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(out, "initrd"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBakeAppendsFortressYML(t *testing.T) {
	dir := t.TempDir()
	src, release := testRelease(t, dir)

	dest := filepath.Join(dir, "edge.iso")
	edge := []byte("quic: true\n")
	if err := Bake(dest, src, edge); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := extract(dest, out, map[string]string{"boot/initramfs.gz": "initrd", "boot/vmlinuz": "vmlinuz"}); err != nil {
		t.Fatal(err)
	}
	baked, err := os.ReadFile(filepath.Join(out, "initrd"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(baked, release) {
		t.Fatal("release initramfs changed")
	}
	zr, err := gzip.NewReader(bytes.NewReader(baked))
	if err != nil {
		t.Fatal(err)
	}
	cpio, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"init\x00", "etc/fortressedge/fortress.yml\x00", "quic: true\n"} {
		if !bytes.Contains(cpio, []byte(want)) {
			t.Fatalf("baked initramfs lacks %q", want)
		}
	}
	if k, _ := os.ReadFile(filepath.Join(out, "vmlinuz")); !bytes.HasPrefix(k, []byte("payload-vmlinuz")) {
		t.Fatal("kernel changed")
	}

	if err := Bake(filepath.Join(dir, "again.iso"), dest, edge); err == nil || !strings.Contains(err.Error(), "already has a fortress.yml") {
		t.Fatalf("rebake: %v", err)
	}
	if err := Bake(src, src, edge); err == nil {
		t.Fatal("overwrote the source")
	}
}

// An ISO baked with an edge's own Vault secret ID is a credential: it is
// created readable by its owner alone, and so is fortress.yml in it. A
// shared one stays readable.
func TestBakeWithASecretIsTheOwnersAlone(t *testing.T) {
	dir := t.TempDir()
	src, _ := testRelease(t, dir)
	crt, _, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	shared := "client_ca: |\n  " + strings.ReplaceAll(strings.TrimSpace(string(crt)), "\n", "\n  ") + "\n" +
		"vault: https://v.example.com:8200\nvault_mount: m\nvault_path: p\nvault_role_id: r\n"
	own := shared + "vault_secret_id: s\nvault_secret_in_iso: true\n"
	for _, tc := range []struct {
		edge string
		perm os.FileMode
		mode string // fortress.yml's mode in the cpio header, as newc writes it
	}{
		{shared, 0o644, "000081A4"},
		{own, 0o600, "00008180"},
	} {
		dest := filepath.Join(t.TempDir(), "edge.iso")
		if err := Bake(dest, src, []byte(tc.edge)); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(dest)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != tc.perm&0o077 {
			t.Errorf("ISO mode %v, want %v", st.Mode().Perm(), tc.perm)
		}
		cpio := bakedCPIO(t, dest)
		i := bytes.LastIndex(cpio, []byte("etc/fortressedge/fortress.yml\x00"))
		if i < 0 || !bytes.Contains(cpio[max(0, i-110):i], []byte("070701")) || string(cpio[i-110+14:i-110+22]) != tc.mode {
			t.Errorf("fortress.yml's mode in the initramfs: want %s", tc.mode)
		}
	}
}
