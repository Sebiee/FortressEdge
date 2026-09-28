package bootimg

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

// WriteISO writes a BIOS El Torito ISO. isolinux and ldlinux are the
// syslinux files (isolinux.bin, ldlinux.c32). The image boots as a CD;
// it is not a hybrid USB image. Every date in it is at, so the same files
// at the same time give the same bytes, on any machine.
func WriteISO(dest, kernel, initrd, isolinux, ldlinux string, at time.Time) error {
	if err := writeISO(dest, kernel, initrd, isolinux, ldlinux); err != nil {
		return err
	}
	return stamp(dest, at)
}

func writeISO(dest, kernel, initrd, isolinux, ldlinux string) error {
	dir, err := os.MkdirTemp("", "fortress-iso-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, sub := range []string{"boot", "isolinux"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return err
		}
	}
	if err := copyFile(kernel, filepath.Join(dir, "boot/vmlinuz")); err != nil {
		return err
	}
	if err := copyFile(initrd, filepath.Join(dir, "boot/initramfs.gz")); err != nil {
		return err
	}
	if err := copyFile(isolinux, filepath.Join(dir, "isolinux/isolinux.bin")); err != nil {
		return err
	}
	if err := copyFile(ldlinux, filepath.Join(dir, "isolinux/ldlinux.c32")); err != nil {
		return err
	}
	cfg := []byte("SERIAL 0 115200\nDEFAULT fortressedge\nPROMPT 0\nTIMEOUT 0\nLABEL fortressedge\n\tKERNEL /boot/vmlinuz\n\tINITRD /boot/initramfs.gz\n\tAPPEND quiet console=tty0 console=ttyS0,115200\n")
	if err := os.WriteFile(filepath.Join(dir, "isolinux/isolinux.cfg"), cfg, 0o644); err != nil {
		return err
	}
	// A leftover root-owned image must not block the write.
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	fsys, err := iso9660.Create(file.New(f, false), 0, 0, 2048, dir)
	if err != nil {
		return err
	}
	entry := &iso9660.ElToritoEntry{
		Platform:  iso9660.BIOS,
		Emulation: iso9660.NoEmulation,
		BootFile:  "/isolinux/isolinux.bin",
		BootTable: true,
	}
	entry.SetLoadSize(4)
	// Joliet would push the El Torito boot record past sector 17, which
	// SeaBIOS will not boot. Rock Ridge is enough for the long names. The
	// boot record finds the catalog; a directory entry for it would only
	// add a date go-diskfs takes from the clock.
	if err := fsys.Finalize(iso9660.FinalizeOptions{
		RockRidge:        true,
		VolumeIdentifier: "FORTRESSEDGE",
		ElTorito: &iso9660.ElTorito{
			BootCatalog:     "/isolinux/boot.cat",
			HideBootCatalog: true,
			Entries:         []*iso9660.ElToritoEntry{entry},
		},
	}); err != nil {
		return err
	}
	return f.Close()
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	return os.WriteFile(dst, b, 0o644)
}
