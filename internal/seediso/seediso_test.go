package seediso

import (
	"bytes"
	"os"
	"testing"
)

func TestWriteVolumeAndFile(t *testing.T) {
	dest := t.TempDir() + "/cidata.iso"
	body := []byte("#cloud-config\nfqdn: t.example\n")
	if err := Write(dest, map[string][]byte{"user-data": body}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 0x8000+72 {
		t.Fatalf("iso too small: %d", len(raw))
	}
	id := string(raw[0x8000+40 : 0x8000+46])
	if id != "cidata" {
		t.Fatalf("volume id %q", id)
	}
	if !bytes.Contains(raw, body) {
		t.Fatal("user-data missing from image")
	}
	if !bytes.Contains(raw, []byte("instance-id: fortressedge")) {
		t.Fatal("meta-data missing")
	}
	if len(raw)%2048 != 0 {
		t.Fatalf("image length %d is not a whole number of sectors", len(raw))
	}
}
