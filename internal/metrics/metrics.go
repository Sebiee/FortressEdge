// Package metrics writes the Prometheus text format for the ops API's
// /~!ops/metrics. The edge counts with atomics where the work happens;
// this package only renders them, so a request pays no registry lookup.
package metrics

import (
	"bufio"
	"io"
	"math"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ContentType is the text exposition format, version 0.0.4.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Writer writes metric families. Each family's samples must follow its
// Family call, before the next family starts.
type Writer struct {
	w   *bufio.Writer
	buf []byte
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: bufio.NewWriter(w)} }

// Family starts a family: typ is counter, gauge, or histogram.
func (w *Writer) Family(name, typ, help string) {
	w.w.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n")
}

// Sample writes one sample of name, with labels as name, value pairs.
func (w *Writer) Sample(name string, v float64, labels ...string) {
	b := append(w.buf[:0], name...)
	b = appendLabels(b, labels)
	b = append(b, ' ')
	b = appendValue(b, v)
	b = append(b, '\n')
	w.buf = b
	w.w.Write(b)
}

// Int writes a sample with an integer value.
func (w *Writer) Int(name string, v int64, labels ...string) { w.Sample(name, float64(v), labels...) }

// Flush writes what is buffered.
func (w *Writer) Flush() error { return w.w.Flush() }

func appendLabels(b []byte, labels []string) []byte {
	first := true
	for i := 0; i+1 < len(labels); i += 2 {
		if labels[i+1] == "" {
			continue // an empty label is no label
		}
		if first {
			b = append(b, '{')
			first = false
		} else {
			b = append(b, ',')
		}
		b = append(b, labels[i]...)
		b = append(b, '=', '"')
		b = append(b, escaper.Replace(labels[i+1])...)
		b = append(b, '"')
	}
	if !first {
		b = append(b, '}')
	}
	return b
}

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func appendValue(b []byte, v float64) []byte {
	switch {
	case math.IsInf(v, 1):
		return append(b, "+Inf"...)
	case math.IsInf(v, -1):
		return append(b, "-Inf"...)
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.AppendInt(b, int64(v), 10)
	}
	return strconv.AppendFloat(b, v, 'g', -1, 64)
}

// DurationBuckets are the upper bounds, in seconds, of every duration
// histogram the edge keeps: few and fixed, so a histogram is 11 series.
var DurationBuckets = [...]float64{0.005, 0.025, 0.1, 0.25, 1, 2.5, 10, 60}

// Histogram counts durations into DurationBuckets. The zero value is ready.
type Histogram struct {
	counts [len(DurationBuckets) + 1]atomic.Int64 // the last is above every bound
	sumNS  atomic.Int64
}

func (h *Histogram) Observe(d time.Duration) {
	s := d.Seconds()
	i := 0
	for i < len(DurationBuckets) && s > DurationBuckets[i] {
		i++
	}
	h.counts[i].Add(1)
	h.sumNS.Add(int64(d))
}

// Write writes h's buckets, sum, and count as name, with labels on each.
func (h *Histogram) Write(w *Writer, name string, labels ...string) {
	var cum int64
	le := make([]string, 0, len(labels)+2)
	le = append(le, labels...)
	le = append(le, "le", "")
	for i, bound := range DurationBuckets {
		cum += h.counts[i].Load()
		le[len(le)-1] = strconv.FormatFloat(bound, 'g', -1, 64)
		w.Int(name+"_bucket", cum, le...)
	}
	cum += h.counts[len(DurationBuckets)].Load()
	le[len(le)-1] = "+Inf"
	w.Int(name+"_bucket", cum, le...)
	w.Sample(name+"_sum", time.Duration(h.sumNS.Load()).Seconds(), labels...)
	w.Int(name+"_count", cum, labels...)
}

// Started is when the process started: at boot, on the edge. Its wall
// time is from before boot steps the clock; since(Started) is exact, as
// Go measures it on the monotonic clock.
var Started = time.Now()

var ready atomic.Pointer[time.Time]

// MarkReady records the first moment the edge accepts connections.
func MarkReady() {
	now := time.Now()
	ready.CompareAndSwap(nil, &now)
}

// since is when something that started d ago started, by the clock as it
// is now: stepped, if boot stepped it since.
func since(d time.Duration) float64 {
	return float64(time.Now().Add(-d).UnixMilli()) / 1e3
}

// BootTime is when the process started, by the clock as it is now.
func BootTime() float64 { return since(time.Since(Started)) }

// ReadyTime is when the edge first accepted connections, by the clock as
// it is now, or false before then.
func ReadyTime() (float64, bool) {
	r := ready.Load()
	if r == nil {
		return 0, false
	}
	return since(time.Since(*r)), true
}

// KernelBootTime is when the kernel started, uptime seconds ago.
func KernelBootTime(uptime float64) float64 {
	return since(time.Duration(uptime * float64(time.Second)))
}

// Version is the edge's module version as the build stamped it: a tag
// such as v0.3.0, a pseudo-version between tags, or (devel).
func Version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
