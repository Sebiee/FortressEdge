//go:build linux

package initos

import (
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	evKey          = 1
	keyPower       = 116 // linux/input-event-codes.h KEY_POWER
	inputEventSize = 24  // amd64: timeval + type + code + value
)

// powerSearch is how long WatchPower looks for the power button's device,
// and powerWait how long of that it waits before it returns: the kernel
// drops a press before the device is open, so boot should not go on
// without it, but a machine with no ACPI button should not wait long.
const (
	powerSearch = 10 * time.Second
	powerWait   = 2 * time.Second
)

// WatchPower calls press once when the ACPI power button is pressed.
// Proxmox Shutdown and Reboot are that button (QMP system_powerdown);
// Reboot starts the VM again only after it has powered off. It watches
// every input device, as its node appears, until the one named "Power
// Button" is among them or powerSearch is up: the keyboard's node can
// appear before the button's, which is why it does not stop at the first.
// It returns once the button is watched, or after powerWait, and goes on
// looking in the background. The readers block until the process exits
// on poweroff.
func WatchPower(press func()) {
	found := make(chan struct{})
	go watchPower(press, "/dev/input", "/sys/class/input", powerSearch, found)
	select {
	case <-found:
	case <-time.After(powerWait):
	}
}

// watchPower closes found once the power button is watched.
func watchPower(press func(), devDir, sysDir string, search time.Duration, found chan<- struct{}) {
	var once sync.Once
	opened := map[string]bool{}
	for deadline := time.Now().Add(search); ; {
		paths, _ := filepath.Glob(filepath.Join(devDir, "event*"))
		for _, p := range paths {
			if opened[p] {
				continue
			}
			f, err := os.Open(p)
			if err != nil {
				continue // its node is there, its permissions not yet
			}
			opened[p] = true
			go readPower(f, func() { once.Do(press) })
			if isPowerButton(sysDir, filepath.Base(p)) {
				slog.Debug("acpi power button", "dev", p)
				close(found)
				return
			}
		}
		if time.Now().After(deadline) {
			slog.Warn("acpi power button not found; Proxmox Shutdown and Reboot will time out", "devices", len(opened))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func readPower(f *os.File, press func()) {
	defer f.Close()
	var buf [inputEventSize]byte
	for {
		if _, err := io.ReadFull(f, buf[:]); err != nil {
			return
		}
		if powerPress(buf[:]) {
			press()
			return
		}
	}
}

// isPowerButton reports whether input device event (event2) is the ACPI
// power button, by the name its driver gives it.
func isPowerButton(sysDir, event string) bool {
	b, err := os.ReadFile(filepath.Join(sysDir, event, "device", "name"))
	return err == nil && strings.TrimSpace(string(b)) == "Power Button"
}

func powerPress(b []byte) bool {
	if len(b) < inputEventSize {
		return false
	}
	typ := binary.LittleEndian.Uint16(b[16:])
	code := binary.LittleEndian.Uint16(b[18:])
	val := int32(binary.LittleEndian.Uint32(b[20:]))
	return typ == evKey && code == keyPower && val == 1
}
