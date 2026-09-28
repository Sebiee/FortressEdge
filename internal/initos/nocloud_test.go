//go:build linux

package initos

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestChooseDisk(t *testing.T) {
	present := func(names ...string) func(string) bool {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return func(n string) bool { return set[n] }
	}
	if got, ok := chooseDisk(present("/dev/sda")); !ok || got != "/dev/sda" {
		t.Fatalf("scsi: %q %v", got, ok)
	}
	if got, ok := chooseDisk(present("/dev/vda", "/dev/sda")); !ok || got != "/dev/vda" {
		t.Fatalf("both: %q %v", got, ok)
	}
	if _, ok := chooseDisk(present()); ok {
		t.Fatal("expected no disk")
	}
}

func TestIsDisk(t *testing.T) {
	want := map[string]bool{
		"vda": true, "vdb": true, "vda1": false,
		"sda": true, "sda1": false,
		"xvda": true, "xvda1": false,
		"nvme0n1": true, "nvme0n1p1": false,
		"sr0": true, "sr1": true, "sra": false,
		"loop0": false, "ttyS0": false,
	}
	for n, ok := range want {
		if g := isDisk(n); g != ok {
			t.Fatalf("isDisk(%q)=%v want %v", n, g, ok)
		}
	}
}

func TestExt4Magic(t *testing.T) {
	empty := make([]byte, ext4MagicOff+2)
	if ext4Magic(bytes.NewReader(empty)) {
		t.Fatal("empty")
	}
	empty[ext4MagicOff], empty[ext4MagicOff+1] = 0x53, 0xEF
	if !ext4Magic(bytes.NewReader(empty)) {
		t.Fatal("magic")
	}
}

func TestMkfsExt4(t *testing.T) {
	img := filepath.Join(t.TempDir(), "disk.img")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(32 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if blank, err := blankDisk(img); err != nil || !blank {
		t.Fatalf("zeroed image: blank=%v err=%v", blank, err)
	}
	iso := filepath.Join(t.TempDir(), "seed.img")
	if err := os.WriteFile(iso, append(make([]byte, 32<<10), "\x01CD001"...), 0o644); err != nil {
		t.Fatal(err)
	}
	if blank, err := blankDisk(iso); err != nil || blank {
		t.Fatalf("iso9660 header: blank=%v err=%v", blank, err)
	}
	if err := mkfsExt4(img); err != nil {
		t.Fatal(err)
	}
	ok, err := hasExt4Super(img)
	if err != nil || !ok {
		t.Fatalf("ext4 magic: ok=%v err=%v", ok, err)
	}
}

func TestStorePolicyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fortressedge", "policy.yml")
	if b, err := LoadPolicy(path); err != nil || b != nil {
		t.Fatalf("no policy yet: %q %v", b, err)
	}
	for _, body := range []string{"block: [192.0.2.9]\n", "limits:\n  ban: 0\n"} {
		if err := StorePolicy(path, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if b, err := LoadPolicy(path); err != nil || !bytes.Equal(b, []byte(body)) {
			t.Fatalf("got %q %v", b, err)
		}
	}
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(ents) != 1 {
		t.Fatalf("temporary files left: %v %v", ents, err)
	}
}

func TestParseMounts(t *testing.T) {
	mounts := `proc /proc proc rw,nosuid,nodev,noexec 0 0
/dev/vda /var ext4 rw,relatime 0 0
tmpfs /run tmpfs rw 0 0
`
	if src, ok := parseMounts([]byte(mounts), "/var"); !ok || src != "/dev/vda" {
		t.Fatalf("/var: %q %v", src, ok)
	}
	if _, ok := parseMounts([]byte(mounts), "/nope"); ok {
		t.Fatal("/nope found")
	}
}
