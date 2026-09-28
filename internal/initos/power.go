//go:build linux

package initos

import (
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	evKey          = 1
	keyPower       = 116 // linux/input-event-codes.h KEY_POWER
	inputEventSize = 24  // amd64: timeval + type + code + value
)

// WatchPower calls press once when the ACPI power button is pressed.
// Proxmox Shutdown and Reboot are that button (QMP system_powerdown);
// Reboot starts the VM again only after it has powered off. The goroutines
// block in read until the process exits on poweroff.
func WatchPower(press func()) {
	devs := powerDevices()
	if len(devs) == 0 {
		slog.Warn("acpi power button not found")
		return
	}
	var once sync.Once
	for _, path := range devs {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		go func() {
			defer f.Close()
			var buf [inputEventSize]byte
			for {
				if _, err := io.ReadFull(f, buf[:]); err != nil {
					return
				}
				if powerPress(buf[:]) {
					once.Do(press)
					return
				}
			}
		}()
	}
}

func powerDevices() []string {
	for range 20 {
		m, _ := filepath.Glob("/dev/input/event*")
		if len(m) > 0 {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
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
