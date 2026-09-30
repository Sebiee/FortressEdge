//go:build linux

package initos

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPowerPress(t *testing.T) {
	var buf [inputEventSize]byte
	put := func(code uint16, val uint32) {
		binary.LittleEndian.PutUint16(buf[16:], evKey)
		binary.LittleEndian.PutUint16(buf[18:], code)
		binary.LittleEndian.PutUint32(buf[20:], val)
	}
	put(keyPower, 1)
	if !powerPress(buf[:]) {
		t.Fatal("power press")
	}
	put(keyPower, 0)
	if powerPress(buf[:]) {
		t.Fatal("release is not a press")
	}
	put(keyPower, 2)
	if powerPress(buf[:]) {
		t.Fatal("repeat is not a press")
	}
	put(1, 1) // KEY_ESC
	if powerPress(buf[:]) {
		t.Fatal("other key")
	}
	if powerPress(buf[:8]) {
		t.Fatal("short read")
	}
}

// The keyboard's node appears first and the power button's later, as they
// can at boot: the button is still found, and its press still counts.
func TestWatchPowerFindsALateButton(t *testing.T) {
	dev, sys := t.TempDir(), t.TempDir()
	name := func(event, n string) {
		if err := os.MkdirAll(filepath.Join(sys, event, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, event, "device", "name"), []byte(n+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	name("event0", "AT Translated Set 2 keyboard")
	name("event2", "Power Button")
	if err := os.WriteFile(filepath.Join(dev, "event0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var press [inputEventSize]byte
	binary.LittleEndian.PutUint16(press[16:], evKey)
	binary.LittleEndian.PutUint16(press[18:], keyPower)
	binary.LittleEndian.PutUint32(press[20:], 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dev, "event2"), press[:], 0o644)
	}()
	pressed := make(chan struct{})
	done := make(chan struct{})
	found := make(chan struct{})
	go func() {
		watchPower(func() { close(pressed) }, dev, sys, 5*time.Second, found)
		close(done)
	}()
	select {
	case <-pressed:
	case <-time.After(3 * time.Second):
		t.Fatal("the late power button's press was missed")
	}
	select {
	case <-done: // it stopped looking once it had the button
	case <-time.After(time.Second):
		t.Fatal("still searching after the button was found")
	}
	select {
	case <-found:
	default:
		t.Fatal("found not closed")
	}
}
