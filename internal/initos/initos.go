//go:build linux

package initos

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"golang.org/x/sys/unix"
)

func Setup() error {
	for _, m := range []struct{ src, dst, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"tmpfs", "/tmp", "tmpfs"},
		{"tmpfs", "/run", "tmpfs"},
	} {
		if err := os.MkdirAll(m.dst, 0o755); err != nil {
			return err
		}
		if err := unix.Mount(m.src, m.dst, m.fs, 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return err
		}
	}
	// Keep printk off the consoles. KERN_ERR and worse are replayed from
	// /dev/kmsg as slog lines, so a kernel message cannot split a log line.
	_ = os.WriteFile("/proc/sys/kernel/printk", []byte("1\t4\t1\t7\n"), 0)
	// PID 1 starts with the kernel's 4096 open files. Each proxied request
	// holds two (the visitor's connection and the leg to frps), so that
	// would cap the edge below its connection limit.
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: 1 << 16, Max: 1 << 16}); err != nil {
		return fmt.Errorf("rlimit nofile: %w", err)
	}
	if err := loadModules(); err != nil {
		return err
	}
	go reap()
	return nil
}

// MountVar mounts the persistent disk at /var, formatting it ext4 if blank.
// An empty dev uses /dev/vda when it exists and /dev/sda otherwise.
// State lives in /var/fortressedge, logs in /var/log/fortressedge. Idempotent.
// The returned path is the device that is mounted.
func MountVar(dev string) (string, error) {
	if src, ok := MountSource("/var"); ok {
		return src, nil
	}
	dev, err := waitDisk(dev)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll("/var", 0o755); err != nil {
		return "", err
	}
	if ok, err := hasExt4Super(dev); err != nil {
		return "", err
	} else if !ok {
		if blank, err := blankDisk(dev); err != nil {
			return "", err
		} else if !blank {
			return "", fmt.Errorf("disk %s is not ext4 and not blank; wipe it", dev)
		}
		slog.Info("blank disk, formatting as ext4", "dev", dev)
		if err := mkfsExt4(dev); err != nil {
			return "", err
		}
	}
	if err := unix.Mount(dev, "/var", "ext4", 0, ""); err != nil {
		return "", fmt.Errorf("mount %s on /var: %w", dev, err)
	}
	slog.Info("persistent disk mounted", "dev", dev, "path", "/var")
	return dev, nil
}

// ponytail: only the first virtio disk and the first SCSI disk; Xen
// (/dev/xvda) and NVMe are not looked for.
var autoDisks = []string{"/dev/vda", "/dev/sda"}

func waitDisk(dev string) (string, error) {
	var last error
	for range 50 {
		if dev != "" {
			if _, last = os.Stat(dev); last == nil {
				return dev, nil
			}
		} else if found, ok := chooseDisk(func(n string) bool {
			_, err := os.Stat(n)
			return err == nil
		}); ok {
			return found, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if dev != "" {
		return "", fmt.Errorf("disk %s: %w", dev, last)
	}
	return "", fmt.Errorf("no data disk: looked for /dev/vda (virtio) and /dev/sda (SCSI)")
}

func chooseDisk(present func(string) bool) (string, bool) {
	for _, n := range autoDisks {
		if present(n) {
			return n, true
		}
	}
	return "", false
}

// MountSource reports what device is mounted at dir, if any.
func MountSource(dir string) (string, bool) {
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return "", false
	}
	return parseMounts(b, dir)
}

func parseMounts(b []byte, dir string) (string, bool) {
	for line := range strings.Lines(string(b)) {
		// dev mountpoint fstype flags ...
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == dir {
			return f[0], true
		}
	}
	return "", false
}

const ext4MagicOff = 0x438

func hasExt4Super(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return ext4Magic(f), nil
}

func ext4Magic(r io.ReaderAt) bool {
	var mag [2]byte
	n, err := r.ReadAt(mag[:], ext4MagicOff)
	return err == nil && n == 2 && mag[0] == 0x53 && mag[1] == 0xEF
}

// ponytail: blank means the first 64 KiB are zero. That covers MBR, GPT,
// FAT, and ISO 9660 headers, not a filesystem that starts further in.
func blankDisk(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	return !slices.ContainsFunc(head[:n], func(b byte) bool { return b != 0 }), nil
}

func mkfsExt4(dev string) error {
	d, err := diskfs.Open(dev)
	if err != nil {
		return fmt.Errorf("open %s: %w", dev, err)
	}
	defer d.Close()
	if _, err := d.CreateFilesystem(disk.FilesystemSpec{FSType: filesystem.TypeExt4}); err != nil {
		return fmt.Errorf("mkfs.ext4 %s: %w", dev, err)
	}
	return nil
}

func loadModules() error {
	// alpine linux-virt; load order is hardcoded.
	for _, name := range []string{
		"crc16", "jbd2", "mbcache", "ext4",
		"failover", "net_failover", "virtio_blk", "virtio_scsi", "sd_mod", "virtio_net",
		"nls_cp437", "nls_iso8859-1", "fat", "vfat", "cdrom", "sr_mod", "isofs",
	} {
		if err := loadModule(name); err != nil {
			return err
		}
	}
	// evdev publishes /dev/input/event*; button emits KEY_POWER. Optional:
	// a machine without ACPI still boots, it just ignores Proxmox Shutdown.
	for _, name := range []string{"evdev", "button"} {
		if err := loadModule(name); err != nil {
			slog.Warn("acpi power button unavailable", "module", name, "err", err)
			return nil
		}
	}
	return nil
}

func loadModule(name string) error {
	path := filepath.Join("/lib/modules", name+".ko.gz")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("/lib/modules", name+".ko")
	}
	return initModule(path)
}

func initModule(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("module %s: %w", path, err)
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return err
		}
		b, err = io.ReadAll(r)
		r.Close()
		if err != nil {
			return err
		}
	}
	if err := unix.InitModule(b, ""); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("init_module %s: %w", path, err)
	}
	return nil
}

func reap() {
	for {
		_, err := unix.Wait4(-1, nil, 0, nil)
		if errors.Is(err, unix.ECHILD) {
			time.Sleep(time.Second)
		}
	}
}
