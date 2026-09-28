package bootimg

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteISO(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vmlinuz", "initrd", "isolinux.bin", "ldlinux.c32"} {
		body := append([]byte("payload-"+name), bytes.Repeat([]byte{0}, 4096)...)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dest := filepath.Join(dir, "fortress.iso")
	if err := WriteISO(dest, filepath.Join(dir, "vmlinuz"), filepath.Join(dir, "initrd"), filepath.Join(dir, "isolinux.bin"), filepath.Join(dir, "ldlinux.c32"), testTime); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("FORTRESSEDGE")) {
		t.Fatal("volume id")
	}
	if !bytes.Contains(raw, []byte("payload-vmlinuz")) {
		t.Fatal("kernel missing")
	}
	// El Torito boot record must be the volume descriptor at sector 17.
	boot := raw[17*2048 : 18*2048]
	if !bytes.Contains(boot[:64], []byte("EL TORITO SPECIFICATION")) {
		t.Fatalf("sector 17 is not the boot record: %q", boot[:64])
	}
}
