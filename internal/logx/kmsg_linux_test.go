//go:build linux

package logx

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKmsgDrainDoesNotBlock(t *testing.T) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skip(err)
	}
	defer unix.Close(fd)
	_, _ = unix.Seek(fd, 0, unix.SEEK_SET)

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	done := make(chan bool, 1)
	go func() { done <- drainKmsg(fd) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("drain failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reading /dev/kmsg blocked; boot would sit on the starting panel")
	}
}
