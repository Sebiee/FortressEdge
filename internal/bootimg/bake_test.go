package bootimg

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBakeAppendsFortressYML(t *testing.T) {
	dir := t.TempDir()
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
	if !bytes.HasPrefix(baked, release.Bytes()) {
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
