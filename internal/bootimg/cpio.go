// Package bootimg builds the BIOS initramfs and El Torito ISO.
package bootimg

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type entry struct {
	name string
	mode uint32
	body []byte
}

// WriteInitramfs writes a gzip newc cpio: /init, the CA bundle, and any
// kernel modules in modules (*.ko or *.ko.gz). modules may be empty.
func WriteInitramfs(dest, binPath, caPath, modules string) error {
	bin, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	files := []entry{
		{"init", 0o100755, bin},
		{"etc", 0o040755, nil},
		{"etc/ssl", 0o040755, nil},
		{"etc/ssl/certs", 0o040755, nil},
		{"etc/ssl/certs/ca-certificates.crt", 0o100644, ca},
	}
	if modules != "" {
		files = append(files, entry{"lib", 0o040755, nil}, entry{"lib/modules", 0o040755, nil})
		matches, err := filepath.Glob(filepath.Join(modules, "*.ko*"))
		if err != nil {
			return err
		}
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				return err
			}
			files = append(files, entry{"lib/modules/" + filepath.Base(m), 0o100644, b})
		}
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	gz, err := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	if err != nil {
		return err
	}
	if err := writeCPIO(gz, files); err != nil {
		_ = gz.Close()
		return err
	}
	return gz.Close()
}

func writeCPIO(w io.Writer, files []entry) error {
	ino := 1
	for _, f := range files {
		if err := writeEntry(w, ino, f); err != nil {
			return err
		}
		ino++
	}
	return writeEntry(w, ino, entry{name: "TRAILER!!!", mode: 0})
}

func writeEntry(w io.Writer, ino int, f entry) error {
	name := append([]byte(f.name), 0)
	nlink := 1
	if f.mode&0o040000 != 0 {
		nlink = 2
	}
	hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
		ino, f.mode, 0, 0, nlink, 0, len(f.body), 0, 0, 0, 0, len(name), 0)
	if len(hdr) != 110 {
		return fmt.Errorf("cpio header %d", len(hdr))
	}
	if _, err := io.WriteString(w, hdr); err != nil {
		return err
	}
	if _, err := w.Write(name); err != nil {
		return err
	}
	if err := pad(w, 110+len(name)); err != nil {
		return err
	}
	if _, err := w.Write(f.body); err != nil {
		return err
	}
	return pad(w, len(f.body))
}

func pad(w io.Writer, n int) error {
	if r := n % 4; r != 0 {
		_, err := w.Write(make([]byte, 4-r))
		return err
	}
	return nil
}
