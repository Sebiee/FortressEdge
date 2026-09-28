//go:build linux

package logx

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func openConsoles() ([]io.Writer, []*ttySink) {
	plain := []io.Writer{}
	ttys := []*ttySink{}
	for _, p := range []string{"/dev/tty0", "/dev/ttyS0"} {
		f := openConsole(p)
		if f == nil {
			continue
		}
		rows, cols := detectSize(f)
		if rows == 0 {
			plain = append(plain, f)
			continue
		}
		ttys = append(ttys, &ttySink{f: f, rows: rows, cols: cols})
	}
	if len(plain) == 0 && len(ttys) == 0 {
		plain = append(plain, os.Stderr)
	}
	return plain, ttys
}

func openConsole(path string) *os.File {
	f, err := os.OpenFile(path, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		f, err = os.OpenFile(path, unix.O_WRONLY|unix.O_NOCTTY, 0)
	}
	if err != nil {
		return nil
	}
	return f
}

// detectSize uses the kernel's idea of the window, then asks the terminal
// on the other end of a serial line. Serial consoles usually report 0×0,
// and a wrong height makes the sticky panel scroll away.
func detectSize(f *os.File) (rows, cols int) {
	fd := int(f.Fd())
	if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil && ws.Row >= 8 && ws.Col >= 40 {
		return int(ws.Row), int(ws.Col)
	}
	if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
		return 0, 0
	}
	if r, c, ok := probeCPR(f); ok {
		return r, c
	}
	return 24, 80
}

func (t *ttySink) measure() {
	fd := int(t.f.Fd())
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil || ws.Row < 8 || ws.Col < 40 {
		return
	}
	t.rows = int(ws.Row)
	t.cols = int(ws.Col)
}

// probeCPR parks the cursor in the far corner and reads the position the
// terminal reports. That position is the window size. No answer (a log
// file, or qemu's pipe) keeps the 24×80 default.
func probeCPR(f *os.File) (rows, cols int, ok bool) {
	fd := int(f.Fd())
	term, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return 0, 0, false
	}
	old := *term
	term.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	term.Cc[unix.VMIN] = 0
	term.Cc[unix.VTIME] = 2 // deciseconds
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, term); err != nil {
		return 0, 0, false
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, &old)

	// unix.Read, not *os.File.Read. The Go poller forces the fd nonblocking
	// and then waits for it; VTIME never fires, so a serial line with no
	// terminal on the other end would sit here forever.
	_ = unix.SetNonblock(fd, false)
	if _, err := unix.Write(fd, []byte("\033[s\033[9999;9999H\033[6n")); err != nil {
		return 0, 0, false
	}
	var buf [64]byte
	n, _ := unix.Read(fd, buf[:])
	_, _ = unix.Write(fd, []byte("\033[u"))
	return parseCPR(buf[:n])
}

func watchKernel(ctx context.Context) {
	// Same poller trap as the console probe: os.File.Read on /dev/kmsg
	// blocks once the ring is drained, even with O_NONBLOCK. Boot was
	// stopping on the first status panel.
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return // dev runs have no kmsg; the consoles stay ours anyway
	}
	_, _ = unix.Seek(fd, 0, unix.SEEK_SET)
	if !drainKmsg(fd) {
		unix.Close(fd)
		return
	}
	go followKmsg(ctx, fd)
}

// drainKmsg reads every record that is already buffered. EAGAIN means the
// reader has caught up; that is the success case.
func drainKmsg(fd int) bool {
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(fd, buf)
		if n > 0 {
			emitKmsg(buf[:n])
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return true
		}
		if err != nil || n == 0 {
			return false
		}
	}
}

func followKmsg(ctx context.Context, fd int) {
	defer unix.Close(fd)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		if !drainKmsg(fd) {
			return
		}
		if _, err := unix.Poll(poll, 500); err != nil && err != unix.EINTR {
			return
		}
	}
}
