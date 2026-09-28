// Package seediso writes a NoCloud cidata volume: ISO9660 with Joliet and
// Rock Ridge, volume id "cidata". Cloud-init and fortressedge both look for
// that label.
package seediso

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

// Write builds dest from files. Names are basenames (user-data,
// network-config, fortress.yml, meta-data). meta-data is added when absent.
func Write(dest string, files map[string][]byte) error {
	dir, err := os.MkdirTemp("", "cidata-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if _, ok := files["meta-data"]; !ok {
		if err := os.WriteFile(filepath.Join(dir, "meta-data"), []byte("instance-id: fortressedge\nlocal-hostname: fortressedge\n"), 0o644); err != nil {
			return err
		}
	}
	for name, body := range files {
		if name == "" || strings.ContainsRune(name, '/') || strings.ContainsRune(name, '\\') {
			return fmt.Errorf("cidata: bad name %q", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			return err
		}
	}
	return writeISO(dest, dir, iso9660.FinalizeOptions{
		RockRidge:        true,
		Joliet:           true,
		VolumeIdentifier: "cidata",
	})
}

func writeISO(dest, workspace string, opt iso9660.FinalizeOptions) error {
	// Replace an existing image even when a previous root-owned run left it
	// unwritable. Unlink needs write permission on the directory, not the file.
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	fsys, err := iso9660.Create(file.New(f, false), 0, 0, 2048, workspace)
	if err != nil {
		return err
	}
	if err := fsys.Finalize(opt); err != nil {
		return err
	}
	return padVolume(f)
}

// padVolume extends the image to the sector count in the primary volume
// descriptor. The writer leaves the last sector short, and the kernel
// refuses to mount a CD that ends before that count.
func padVolume(f *os.File) error {
	var b [4]byte
	if _, err := f.ReadAt(b[:], 16*2048+80); err != nil {
		return err
	}
	vol := int64(binary.LittleEndian.Uint32(b[:])) * 2048
	return f.Truncate(vol)
}
