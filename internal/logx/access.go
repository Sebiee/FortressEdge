package logx

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// OpenAccess starts dir/current.log for the access log. It rotates at
// maxSize and keeps maxFiles files in all, the current one included, so
// the log never takes more than maxSize*maxFiles. Each file starts with
// the same marker as the edge's log, "# boot <id>", where the id is the
// boot id and, after a rotation, a sequence number; a rotated file is
// named <id>.log. The ops API's cursors name a file by its id.
//
// Open it once per boot: a second one would start its files with the
// same ids.
func OpenAccess(dir string, maxSize int64, maxFiles int) (AccessWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	boot := BootID()
	if boot == "" {
		boot = "boot" // no /proc (dev runs)
	}
	a := &accessFile{dir: dir, boot: boot, max: maxSize, keep: maxFiles}
	a.id = markerID(filepath.Join(dir, "current.log")) // the last boot's file
	if a.id == "" {
		a.id = "previous-" + time.Now().UTC().Format("20060102T150405")
	}
	if err := a.rotate(); err != nil {
		return nil, err
	}
	warnIfLarge(dir, maxSize*int64(maxFiles))
	return a, nil
}

// AccessWriter is the access log's files.
type AccessWriter interface {
	io.Writer
	// SetLimits changes the size at which a file rotates and the files
	// kept, from the next write; files past maxFiles go now.
	SetLimits(maxSize int64, maxFiles int)
}

type accessFile struct {
	mu   sync.Mutex
	dir  string
	boot string
	max  int64
	keep int
	seq  int
	id   string // of current.log
	f    *os.File
	size int64
	head int64 // marker length: a file holding only it never rotates
}

// Write takes whole lines; slog hands each record over in one Write.
func (a *accessFile) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.size+int64(len(p)) > a.max && a.size > a.head {
		if err := a.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := a.f.Write(p)
	a.size += int64(n)
	return n, err
}

func (a *accessFile) SetLimits(maxSize int64, maxFiles int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.max == maxSize && a.keep == maxFiles {
		return
	}
	a.max, a.keep = maxSize, maxFiles
	a.prune()
	warnIfLarge(a.dir, maxSize*int64(maxFiles))
}

// rotate renames current.log to <id>.log, deletes the oldest files past
// keep, and starts a new current.log.
func (a *accessFile) rotate() error {
	if a.f != nil {
		_ = a.f.Close()
	}
	path := filepath.Join(a.dir, "current.log")
	_ = os.Rename(path, filepath.Join(a.dir, a.id+".log"))
	a.prune()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	a.id = a.boot
	if a.seq > 0 {
		a.id = fmt.Sprintf("%s.%d", a.boot, a.seq)
	}
	a.seq++
	n, err := fmt.Fprintf(f, "# boot %s\n", a.id)
	if err != nil {
		_ = f.Close()
		return err
	}
	a.f, a.size, a.head = f, int64(n), int64(n)
	return nil
}

// prune keeps the keep-1 newest rotated files, leaving room for current.log.
func (a *accessFile) prune() {
	old := Rotated(a.dir)
	for _, p := range old[min(len(old), max(a.keep-1, 0)):] {
		if err := os.Remove(p); err != nil {
			slog.Warn("access log: prune", "file", p, "err", err)
		}
	}
}

// Rotated lists dir's *.log files other than current.log, newest first.
func Rotated(dir string) []string {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	type file struct {
		path string
		mod  time.Time
	}
	var files []file
	for _, p := range paths {
		if filepath.Base(p) == "current.log" {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			files = append(files, file{p, st.ModTime()})
		}
	}
	slices.SortFunc(files, func(x, y file) int { return cmp.Compare(y.mod.UnixNano(), x.mod.UnixNano()) })
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out
}

func markerID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	id, ok := strings.CutPrefix(strings.TrimSpace(line), "# boot ")
	if !ok || strings.ContainsAny(id, `/\`) {
		return ""
	}
	return id
}

// warnIfLarge logs when the access log may take more than half of the
// disk under dir, which also holds certificates and the edge's log.
func warnIfLarge(dir string, budget int64) {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return
	}
	if disk := int64(st.Blocks) * int64(st.Bsize); budget > disk/2 {
		slog.Warn("access log may fill the disk: lower access_log_max_size or access_log_max_files",
			"budget_mib", budget>>20, "disk_mib", disk>>20)
	}
}
