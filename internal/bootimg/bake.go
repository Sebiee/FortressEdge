package bootimg

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"

	"github.com/Sebiee/fortressedge/internal/config"
)

// BakedPath is where fortress.yml lands in the initramfs: the edge reads
// it as config.BakedFile.
var BakedPath = strings.TrimPrefix(config.BakedFile, "/")

// Bake writes dest: the ISO at src with fortress.yml added to its
// initramfs. The kernel unpacks concatenated archives in order, so the
// file is a second gzip cpio appended to the release's; the kernel, the
// edge binary, and the boot loader are copied unchanged. dest carries
// src's date, so the same src and fortress.yml give the same bytes.
func Bake(dest, src string, edge []byte) error {
	if abs(dest) == abs(src) {
		return errors.New("bake: output would overwrite the source ISO")
	}
	at, err := VolumeTime(src)
	if err != nil {
		return fmt.Errorf("bake: %w", err)
	}
	dir, err := os.MkdirTemp("", "fortress-bake-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	parts := map[string]string{
		"boot/vmlinuz":          "vmlinuz",
		"boot/initramfs.gz":     "initramfs.gz",
		"isolinux/isolinux.bin": "isolinux.bin",
		"isolinux/ldlinux.c32":  "ldlinux.c32",
	}
	if err := extract(src, dir, parts); err != nil {
		return err
	}
	initrd := filepath.Join(dir, "initramfs.gz")
	baked, err := hasSeed(initrd)
	if err != nil {
		return fmt.Errorf("bake: %s: %w", src, err)
	}
	if baked {
		return fmt.Errorf("bake: %s already has a %s; start from the release ISO", src, config.EdgeFile)
	}
	if err := appendSeed(initrd, edge); err != nil {
		return err
	}
	return WriteISO(dest, filepath.Join(dir, "vmlinuz"), initrd,
		filepath.Join(dir, "isolinux.bin"), filepath.Join(dir, "ldlinux.c32"), at)
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func extract(src, dir string, parts map[string]string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	fsys, err := iso9660.Read(file.New(f, true), st.Size(), 0, 0)
	if err != nil {
		return fmt.Errorf("bake: %s is not an ISO: %w", src, err)
	}
	for from, to := range parts {
		in, err := fsys.OpenFile("/"+from, os.O_RDONLY)
		if err != nil {
			return fmt.Errorf("bake: %s has no /%s; is it a fortressedge ISO? %w", src, from, err)
		}
		b, err := io.ReadAll(in)
		in.Close()
		if err != nil {
			return fmt.Errorf("bake: /%s: %w", from, err)
		}
		if err := os.WriteFile(filepath.Join(dir, to), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// hasSeed reports whether any archive in the initramfs already carries a
// fortress.yml. Baking twice would hide which one the edge reads.
func hasSeed(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f) // multistream: reads every appended archive
	if err != nil {
		return false, err
	}
	b, err := io.ReadAll(gz)
	if err != nil {
		return false, err
	}
	// The cpio entry name, NUL-terminated: Go strings in the edge binary
	// are not.
	return bytes.Contains(b, []byte(BakedPath+"\x00")), nil
}

func appendSeed(path string, edge []byte) error {
	files := []entry{
		{"etc", 0o040755, nil},
		{filepath.Dir(BakedPath), 0o040755, nil},
		{BakedPath, 0o100644, edge},
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	// Stored, not compressed: the file is a few KiB, and stored blocks
	// are the same bytes whatever Go's compressor does in another version.
	gz, err := gzip.NewWriterLevel(f, gzip.NoCompression)
	if err != nil {
		_ = f.Close()
		return err
	}
	if err := writeCPIO(gz, files); err != nil {
		_ = f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
