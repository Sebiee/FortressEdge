package collect

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// bootPrefix starts the first line of each of an edge's log files: the
// file's id (see internal/ops).
const bootPrefix = "# boot "

// gapMark stands in the index between two files where the edge lost lines
// before the collector read them.
const gapMark = "-"

// A position is a place in one edge's log: a file of the edge, by its id,
// and a byte offset in it. It is the edge's own cursor, "<file-id>:<offset>",
// so it means the same in every copy of that file.
type position struct {
	id  string
	off int64
}

func (p position) String() string {
	if p.id == "" {
		return ""
	}
	return p.id + ":" + strconv.FormatInt(p.off, 10)
}

func parsePosition(s string) (position, error) {
	id, off, ok := strings.Cut(s, ":")
	if !ok || id == "" || id == gapMark || strings.ContainsAny(id, "/,=") {
		return position{}, fmt.Errorf("cursor: want <file-id>:<offset>, got %q", s)
	}
	n, err := strconv.ParseInt(off, 10, 64)
	if err != nil || n < 0 {
		return position{}, fmt.Errorf("cursor: bad offset in %q", s)
	}
	return position{id, n}, nil
}

// A mirror is the collector's copy of one log of one edge: a file per file
// of the edge, named by the edge's id of it, holding the same bytes at the
// same offsets. Two collectors that read the same edge hold the same bytes,
// so a reader's position is good at either.
type mirror struct {
	dir string
	// records marks the access log: the edge serves it without the marker
	// line of each file, so the mirror writes that line itself.
	records bool
	keep    int64 // bytes kept; the oldest files go first

	// pulling lets one pull at a time append: the copy's timer and a
	// reader's own pull must not write the same bytes twice.
	pulling sync.Mutex

	mu   sync.Mutex
	ids  []string // the files, oldest first; gapMark where lines were lost
	gaps int64
}

func openMirror(dir string, records bool, keep int64) (*mirror, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	m := &mirror{dir: dir, records: records, keep: keep}
	b, err := os.ReadFile(filepath.Join(dir, "index"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, id := range strings.Fields(string(b)) {
		if id == gapMark {
			m.ids = append(m.ids, id)
		} else if _, err := os.Stat(m.path(id)); err == nil {
			m.ids = append(m.ids, id)
		}
	}
	return m, nil
}

func (m *mirror) path(id string) string { return filepath.Join(m.dir, id+".log") }

// saveIndex writes the index whole, through a temporary file.
func (m *mirror) saveIndex() error {
	tmp := filepath.Join(m.dir, "index.tmp")
	if err := os.WriteFile(tmp, []byte(strings.Join(m.ids, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(m.dir, "index"))
}

// end is where the mirror's copy ends: the position to ask the edge for
// more from. Empty when it holds nothing yet.
func (m *mirror) end() position {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.endLocked()
}

func (m *mirror) endLocked() position {
	if len(m.ids) == 0 {
		return position{}
	}
	id := m.ids[len(m.ids)-1]
	return position{id, pathSize(m.path(id))}
}

// begin starts the copy of a file of the edge, after a gap when lines were
// lost before it.
func (m *mirror) begin(id string, gap bool) error {
	if strings.ContainsAny(id, "/,=") || id == "" || id == gapMark {
		return fmt.Errorf("edge sent a file id the collector cannot keep: %q", id)
	}
	head := ""
	if m.records {
		head = bootPrefix + id + "\n"
	}
	if err := os.WriteFile(m.path(id), []byte(head), 0o644); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if gap {
		m.ids = append(m.ids, gapMark)
		m.gaps++
	}
	m.ids = append(m.ids, id)
	return m.saveIndex()
}

// A page is one answer of an edge's log API: the bytes after the position
// asked for, where to ask next (X-Log-Cursor), and whether the edge had
// lost the file asked for (X-Log-Gap) and sent its current one from the
// start.
type page struct {
	body io.ReadCloser
	next string
	gap  bool
}

// pull asks the edge for what follows the copy and appends it. more means
// the edge has a newer file to read at once.
func (m *mirror) pull(fetch func(cursor string) (*page, error)) (more bool, err error) {
	m.pulling.Lock()
	defer m.pulling.Unlock()
	at := m.end()
	p, err := fetch(at.String())
	if err != nil {
		return false, err
	}
	defer p.body.Close()
	next, err := parsePosition(p.next)
	if err != nil {
		return false, fmt.Errorf("edge: %w", err)
	}
	target := at.id
	if at.id == "" || p.gap {
		// The bytes are the edge's current file, from its start.
		target = next.id
		if err := m.begin(target, p.gap && at.id != ""); err != nil {
			return false, err
		}
	}
	f, err := os.OpenFile(m.path(target), os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(f, p.body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err // what arrived is kept: the next pull goes on after it
	}
	if next.id != target {
		// The file is whole on the edge, and a newer one follows.
		if err := m.begin(next.id, false); err != nil {
			return false, err
		}
		more = true
	} else if size := pathSize(m.path(target)); size != next.off {
		err = fmt.Errorf("copy of %s is %d bytes, the edge says %d", target, size, next.off)
	}
	m.prune()
	return more, err
}

// prune deletes the oldest files while the copy is over its size, never
// the newest.
func (m *mirror) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var total int64
	for _, id := range m.ids {
		if id != gapMark {
			total += pathSize(m.path(id))
		}
	}
	changed := false
	for total > m.keep && len(m.ids) > 1 {
		id := m.ids[0]
		if id != gapMark {
			total -= pathSize(m.path(id))
			_ = os.Remove(m.path(id))
		}
		m.ids = m.ids[1:]
		changed = true
	}
	for len(m.ids) > 0 && m.ids[0] == gapMark {
		m.ids = m.ids[1:]
		changed = true
	}
	if changed {
		_ = m.saveIndex()
	}
}

// size is the bytes the copy holds.
func (m *mirror) size() (total int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.ids {
		if id != gapMark {
			total += pathSize(m.path(id))
		}
	}
	return total
}

// read calls emit with each whole line after from, oldest first, until the
// copy's end or until budget bytes are spent.
// It returns where the next read continues. gap means lines between from
// and there are lost: the edge lost them before the collector read them,
// or from names a file the copy no longer has, or never had. An empty from
// starts at the oldest line kept; now starts at the end.
//
// A position never moves backward. One that is ahead of the copy (another
// collector of the same edge gave it) gets no line and stays as it is,
// until the copy has reached it. fresh says the copy was brought up to the
// edge just now: only then is a file the copy does not have a lost one,
// and not one the copy has yet to reach.
func (m *mirror) read(from position, now, fresh bool, budget *int64, emit func(line []byte)) (to position, gap bool, err error) {
	m.mu.Lock()
	ids := slices.Clone(m.ids)
	m.mu.Unlock()
	if len(ids) == 0 {
		return from, false, nil
	}
	if now {
		id := ids[len(ids)-1]
		f, err := os.Open(m.path(id))
		if err != nil {
			return from, false, err
		}
		defer f.Close()
		return position{id, lastNewlineEnd(f, fileSize(f))}, false, nil
	}
	i, off := slices.Index(ids, from.id), from.off
	switch {
	case from.id == "":
		i, off = 0, 0
	case i < 0 && !fresh:
		return from, false, nil
	case i < 0:
		i, off, gap = 0, 0, true
	}
	to = from
	for ; i < len(ids); i++ {
		id := ids[i]
		if id == gapMark {
			gap = true
			continue
		}
		f, err := os.Open(m.path(id))
		if err != nil {
			gap = true // pruned since the index was read
			continue
		}
		last := i == len(ids)-1
		end := fileSize(f)
		if last {
			end = lastNewlineEnd(f, end) // its last line may be half copied
			if off > end {
				_ = f.Close()
				return to, gap, nil // ahead of the copy
			}
		}
		off = min(off, end)
		if m.records {
			off = max(off, int64(len(bootPrefix)+len(id)+1))
			end = max(end, off)
		}
		n, full, err := lines(f, off, end, budget, emit)
		_ = f.Close()
		to = position{id, off + n}
		if err != nil || full || last {
			return to, gap, err
		}
		off = 0
	}
	return to, gap, nil
}

// lines calls emit with the whole lines of f in [off, end) while budget
// lasts; the line that uses it up still goes. n is the bytes emitted; full
// means the budget ended first.
func lines(f *os.File, off, end int64, budget *int64, emit func([]byte)) (n int64, full bool, err error) {
	r := bufio.NewReaderSize(io.NewSectionReader(f, off, end-off), 64<<10)
	for {
		if *budget <= 0 {
			return n, true, nil
		}
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			emit(line)
			n += int64(len(line))
			*budget -= int64(len(line))
		}
		if errors.Is(err, io.EOF) {
			return n, false, nil
		}
		if err != nil {
			return n, false, err
		}
	}
}

// lastNewlineEnd is the offset just past the last '\n' in the file's tail.
func lastNewlineEnd(f *os.File, size int64) int64 {
	const tail = 1 << 20
	start := max(size-tail, 0)
	buf := make([]byte, size-start)
	n, _ := f.ReadAt(buf, start)
	i := bytes.LastIndexByte(buf[:n], '\n')
	if i < 0 {
		return 0
	}
	return start + int64(i) + 1
}

func fileSize(f *os.File) int64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return st.Size()
}

func pathSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}
