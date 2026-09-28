//go:build linux

package initos

import (
	"encoding/binary"
	"testing"
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
