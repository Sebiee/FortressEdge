// Package logx fans fortressedge logs out to the places an edge operator can
// see them: the VGA console, the serial console, stderr, and — once the
// persistent disk is mounted — a log file under /var/log.
//
// Real consoles keep a status panel pinned at the top. Log lines scroll
// underneath it. Kernel printk and foreign loggers do not write those
// consoles themselves; their lines are slog records, so one line cannot
// split another.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const timeLayout = "15:04:05.000"

// fan is the process-wide fan-out; stderr is always present so early-boot
// and fatal messages land somewhere even before Setup runs.
var fan = &fanout{plain: []io.Writer{os.Stderr}}

type fanout struct {
	mu      sync.Mutex
	plain   []io.Writer
	ttys    []*ttySink
	st      Status
	cpuPrev cpuSample
	cpuTopo string
	conns   func() int
	active  bool
}

// Status is the pinned console grid. Ready and Connected are the only
// fields painted green or red. Notes are extra lines under the grid
// (why the edge cannot start) and stay in the default color.
type Status struct {
	Stage, Tunnel, ACME, QUIC, Disk, NTP string
	Iface, Addr, Gateway, DNS            string
	Frps, Listen, Blocked                string
	Ready, Connected                     bool
	Notes                                []string
}

func (s Status) equal(o Status) bool {
	return s.Stage == o.Stage && s.Tunnel == o.Tunnel && s.ACME == o.ACME && s.QUIC == o.QUIC &&
		s.Disk == o.Disk && s.NTP == o.NTP && s.Iface == o.Iface && s.Addr == o.Addr &&
		s.Gateway == o.Gateway && s.DNS == o.DNS && s.Frps == o.Frps &&
		s.Listen == o.Listen && s.Blocked == o.Blocked && s.Ready == o.Ready &&
		s.Connected == o.Connected && slices.Equal(s.Notes, o.Notes)
}

func (f *fanout) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.plain {
		_, _ = w.Write(p)
	}
	for _, t := range f.ttys {
		t.writeLog(p)
	}
	return len(p), nil
}

func (f *fanout) add(w io.Writer) {
	f.mu.Lock()
	f.plain = append(f.plain, w)
	f.mu.Unlock()
}

func (f *fanout) replace(plain []io.Writer, ttys []*ttySink) {
	f.mu.Lock()
	f.plain = plain
	f.ttys = ttys
	f.active = true
	f.mu.Unlock()
}

func replaceTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		a.Value = slog.StringValue(a.Value.Time().Format(timeLayout))
	}
	return a
}

// Setup installs the default slog logger on the fan-out and points it at the
// VGA and serial consoles. Call it after initos.Setup has mounted devtmpfs.
// PID 1's stderr is /dev/console, which already ends up on these consoles, so
// when at least one opens, stderr drops out to keep lines unduplicated; on
// dev runs (no consoles) stderr stays.
func Setup() {
	plain, ttys := openConsoles()
	fan.replace(plain, ttys)
	slog.SetDefault(slog.New(slog.NewTextHandler(fan, &slog.HandlerOptions{
		ReplaceAttr: replaceTime,
	})))
	SetStatus(Status{Stage: "starting"})
}

// Watch replays kernel errors that printk is no longer allowed to paint,
// then follows new ones. The status header refreshes until ctx ends.
func Watch(ctx context.Context) {
	watchKernel(ctx)
	go refresh(ctx)
}

// statusEvery is the header refresh. CPU percent is the average since the
// previous sample. A tick sends a few changed characters; on KVM an idle
// edge costs its host no more at 1s than at 5s.
const statusEvery = time.Second

func refresh(ctx context.Context) {
	fan.mu.Lock()
	n := len(fan.ttys)
	fan.mu.Unlock()
	if n == 0 {
		return
	}
	tick := time.NewTicker(statusEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			fan.mu.Lock()
			fan.repaint()
			fan.mu.Unlock()
		}
	}
}

// Active reports whether Setup has taken the consoles. Fatal messages use
// it so they scroll with the log instead of painting over the status panel.
func Active() bool {
	fan.mu.Lock()
	defer fan.mu.Unlock()
	return fan.active
}

// SetStatus pins the console grid. CPU and memory are sampled on each
// redraw and are not part of the logged snapshot.
func SetStatus(st Status) {
	fan.mu.Lock()
	defer fan.mu.Unlock()
	next := st
	next.Notes = append([]string{}, st.Notes...)
	same := fan.st.equal(next)
	fan.st = next
	host := fan.repaint()
	if same {
		return
	}
	p := []byte(panelPlain(next, host))
	for _, w := range fan.plain {
		_, _ = w.Write(p)
	}
}

// repaint samples the machine once and draws every console. Caller holds fan.mu.
func (f *fanout) repaint() machine {
	host := f.machine()
	for _, t := range f.ttys {
		t.paint(host)
	}
	return host
}

// machine reads CPU and memory. Core speed is fixed, so it is read once.
func (f *fanout) machine() machine {
	if f.cpuTopo == "" {
		if text, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			f.cpuTopo = formatCPUTopo(parseCPUInfo(string(text)))
		}
	}
	m := sampleMachine(&f.cpuPrev, f.cpuTopo)
	if f.conns != nil {
		m.conns = formatConns(f.conns())
	}
	return m
}

// SetConnections names the source of the header's connection count: open
// TCP connections on 80 and 443. The header shows none until it is set.
func SetConnections(n func() int) {
	fan.mu.Lock()
	defer fan.mu.Unlock()
	fan.conns = n
}

// AddFile tees the log into dir/current.log, keeping the previous boot as
// previous.log. Call once the persistent disk is mounted.
func AddFile(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "current.log")
	_ = os.Rename(path, filepath.Join(dir, "previous.log"))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	// Boot marker, file only: the ops API reads it back to tell which boot
	// wrote a log file, so a fetcher's cursor survives a reboot exactly.
	fmt.Fprintf(f, "# boot %s\n", BootID())
	fan.add(f)
	return nil
}

// BootID is the kernel's per-boot UUID; ops log cursors are scoped to it.
func BootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "" // no /proc (dev runs): cursors degrade to plain offsets
	}
	return strings.TrimSpace(string(b))
}

// Writer exposes the fan-out for text that is already whole lines, such as
// the last words before a power-off. Loggers use Forward or Zap instead.
func Writer() io.Writer { return fan }
