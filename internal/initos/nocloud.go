//go:build linux

package initos

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/Sebiee/fortressedge/internal/config"
)

// ErrNotBaked is the release ISO booted as it ships: it has no
// fortress.yml, so it trusts nobody.
var ErrNotBaked = errors.New("no " + config.EdgeFile + " in the ISO: this is the release ISO; boot one made with fortressctl bake")

// ErrNoDrive is a machine without a NoCloud drive.
var ErrNoDrive = errors.New("no NoCloud drive: attach a cloud-init drive with user-data (fqdn) and network-config")

var (
	userDataNames    = []string{"user-data", "user_data", "USER-DATA"}
	metaDataNames    = []string{"meta-data", "meta_data", "META-DATA"}
	networkConfNames = []string{"network-config", "network_config", "NETWORK-CONFIG"}
)

// Seed is the config boot reads: fortress.yml from the ISO, user-data and
// network-config from the NoCloud drive. The policy is on the /var disk,
// read once that is mounted.
type Seed struct {
	UserData      []byte
	NetworkConfig []byte
	Edge          []byte
}

// seedWait is how long boot looks for the NoCloud drive: a CD can appear
// a moment after the kernel starts. It is wall time; each look mounts
// every candidate and takes a few hundred milliseconds.
const seedWait = 5 * time.Second

// FindSeed reads fortress.yml from the initramfs and waits for the NoCloud
// drive. The drive stays attached: every boot reads it, as cloud-init
// does, so a change made on the platform (Proxmox's Cloud-Init tab, a
// Terraform apply) takes effect at the next start.
func FindSeed() (Seed, error) {
	edge, err := os.ReadFile(config.BakedFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Seed{}, ErrNotBaked
	}
	if err != nil {
		return Seed{}, err
	}
	for deadline := time.Now().Add(seedWait); time.Now().Before(deadline); {
		if s, err := readNoCloud(); err == nil {
			s.Edge = edge
			return s, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return Seed{}, ErrNoDrive
}

func readNoCloud() (Seed, error) {
	devs, err := blockDevs()
	if err != nil {
		return Seed{}, err
	}
	for _, dev := range devs {
		for _, fs := range []string{"iso9660", "vfat"} {
			if s, err := trySeed(dev, fs); err == nil {
				return s, nil
			}
		}
	}
	return Seed{}, ErrNoDrive
}

func trySeed(dev, fstype string) (Seed, error) {
	mnt, err := os.MkdirTemp("/run", "cidata-")
	if err != nil {
		return Seed{}, err
	}
	defer os.RemoveAll(mnt)
	if err := unix.Mount(dev, mnt, fstype, unix.MS_RDONLY, ""); err != nil {
		return Seed{}, err
	}
	defer unix.Unmount(mnt, unix.MNT_DETACH)
	if _, err := firstFile(mnt, metaDataNames); err != nil {
		return Seed{}, err
	}
	ud, err := firstFile(mnt, userDataNames)
	if err != nil {
		return Seed{}, err
	}
	net, _ := firstFile(mnt, networkConfNames)
	slog.Info("nocloud drive found", "dev", dev, "fs", fstype)
	return Seed{UserData: ud, NetworkConfig: net}, nil
}

func firstFile(dir string, names []string) ([]byte, error) {
	var last error
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err == nil {
			return b, nil
		}
		last = err
	}
	return nil, last
}

func blockDevs() ([]string, error) {
	ents, err := os.ReadDir("/dev")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !isDisk(e.Name()) {
			continue
		}
		out = append(out, filepath.Join("/dev", e.Name()))
	}
	return out, nil
}

// isDisk reports whether a /dev name is a whole disk worth probing for a
// NoCloud drive: sr0 (cdrom), vd/sd/xvd + letter (virtio/scsi/xen), nvmeNnM.
func isDisk(n string) bool {
	if rest, ok := strings.CutPrefix(n, "sr"); ok {
		return rest != "" && allDigits(rest)
	}
	if rest, ok := strings.CutPrefix(n, "nvme"); ok {
		return strings.Contains(rest, "n") && !strings.Contains(rest, "p")
	}
	for _, p := range []string{"xvd", "vd", "sd"} {
		if rest, ok := strings.CutPrefix(n, p); ok {
			return rest != "" && noDigits(rest)
		}
	}
	return false
}

func allDigits(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return !unicode.IsDigit(r) }) < 0
}

func noDigits(s string) bool {
	return !strings.ContainsFunc(s, unicode.IsDigit)
}
