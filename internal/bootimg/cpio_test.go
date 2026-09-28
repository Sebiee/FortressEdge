package bootimg

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"
)

func TestWriteInitramfsContainsInit(t *testing.T) {
	dir := t.TempDir()
	bin := dir + "/fortressedge"
	ca := dir + "/ca.crt"
	if err := os.WriteFile(bin, []byte("#!/init-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := dir + "/initramfs.cpio.gz"
	if err := WriteInitramfs(dest, bin, ca, ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("070701")) || !bytes.Contains(body, []byte("init")) || !bytes.Contains(body, []byte("#!/init-bytes")) {
		t.Fatal("cpio missing init")
	}
	if !bytes.Contains(body, []byte("TRAILER!!!")) {
		t.Fatal("missing trailer")
	}
}
