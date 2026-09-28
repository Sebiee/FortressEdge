package bootimg

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

var testTime = time.Date(2026, 9, 25, 12, 34, 56, 0, time.UTC)

// release writes a stand-in release ISO into dir: a kernel, an initramfs
// with an init, and the boot loader, stamped at.
func release(t *testing.T, dir string, at time.Time) string {
	t.Helper()
	for _, name := range []string{"vmlinuz", "isolinux.bin", "ldlinux.c32"} {
		body := append([]byte("payload-"+name), bytes.Repeat([]byte{0}, 4096)...)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var initrd bytes.Buffer
	gz := gzip.NewWriter(&initrd)
	if err := writeCPIO(gz, []entry{{"init", 0o100755, []byte("edge")}}); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	if err := os.WriteFile(filepath.Join(dir, "initrd"), initrd.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(dir, "release.iso")
	if err := WriteISO(iso, filepath.Join(dir, "vmlinuz"), filepath.Join(dir, "initrd"),
		filepath.Join(dir, "isolinux.bin"), filepath.Join(dir, "ldlinux.c32"), at); err != nil {
		t.Fatal(err)
	}
	return iso
}

// The same files at the same time are the same bytes, whenever they are
// written: nothing comes from the clock, and nothing from the files'
// own times.
func TestWriteISOIsReproducible(t *testing.T) {
	a := read(t, release(t, t.TempDir(), testTime))
	time.Sleep(1100 * time.Millisecond) // the clock's seconds move on
	b := read(t, release(t, t.TempDir(), testTime))
	if !bytes.Equal(a, b) {
		t.Fatalf("%d bytes differ", differ(a, b))
	}
	other := read(t, release(t, t.TempDir(), testTime.Add(time.Hour)))
	if bytes.Equal(a, other) {
		t.Fatal("another time wrote the same bytes")
	}
}

func TestBakeIsReproducible(t *testing.T) {
	src := release(t, t.TempDir(), testTime)
	dir := t.TempDir()
	edge := []byte("quic: true\n")
	if err := Bake(filepath.Join(dir, "a.iso"), src, edge); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := Bake(filepath.Join(dir, "b.iso"), src, edge); err != nil {
		t.Fatal(err)
	}
	a, b := read(t, filepath.Join(dir, "a.iso")), read(t, filepath.Join(dir, "b.iso"))
	if !bytes.Equal(a, b) {
		t.Fatalf("%d bytes differ", differ(a, b))
	}
	if at, err := VolumeTime(filepath.Join(dir, "a.iso")); err != nil || !at.Equal(testTime) {
		t.Fatalf("baked ISO dated %v %v, want the release's %v", at, err, testTime)
	}
	if err := Bake(filepath.Join(dir, "c.iso"), src, []byte("quic: false\n")); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, read(t, filepath.Join(dir, "c.iso"))) {
		t.Fatal("another fortress.yml baked the same bytes")
	}
}

// The stamped image still reads as it did, with every file at the time.
func TestStampedImageReads(t *testing.T) {
	iso := release(t, t.TempDir(), testTime)
	if at, err := VolumeTime(iso); err != nil || !at.Equal(testTime) {
		t.Fatalf("volume time %v %v", at, err)
	}
	f, err := os.Open(iso)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	fsys, err := iso9660.Read(file.New(f, true), st.Size(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".", "boot", "isolinux"} {
		ents, err := fsys.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			fi, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if !fi.ModTime().Equal(testTime) {
				t.Errorf("%s/%s: %v", dir, e.Name(), fi.ModTime())
			}
			if e.Name() == "boot.cat" {
				t.Errorf("the boot catalog is listed")
			}
		}
	}
	out := t.TempDir()
	if err := extract(iso, out, map[string]string{"boot/vmlinuz": "vmlinuz"}); err != nil {
		t.Fatal(err)
	}
	if k := read(t, filepath.Join(out, "vmlinuz")); !bytes.HasPrefix(k, []byte("payload-vmlinuz")) {
		t.Fatal("kernel changed")
	}
}

func TestSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1790000000")
	if at, err := SourceDateEpoch(); err != nil || at.Unix() != 1790000000 {
		t.Fatalf("%v %v", at, err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "yesterday")
	if _, err := SourceDateEpoch(); err == nil {
		t.Fatal("accepted a word")
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func differ(a, b []byte) int {
	n := max(len(a), len(b)) - min(len(a), len(b))
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}
