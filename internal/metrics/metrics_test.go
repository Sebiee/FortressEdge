package metrics

import (
	"bytes"
	"math"
	"testing"
	"time"
)

func TestWriter(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	w.Family("x_total", "counter", "An x.")
	w.Int("x_total", 7)
	w.Int("x_total", 1, "site", `a"b\c`+"\n", "empty", "")
	w.Sample("x_total", 0.25, "k", "v")
	w.Sample("x_total", math.Inf(1))
	w.Flush()
	want := "# HELP x_total An x.\n# TYPE x_total counter\n" +
		"x_total 7\n" +
		`x_total{site="a\"b\\c\n"} 1` + "\n" +
		`x_total{k="v"} 0.25` + "\n" +
		"x_total +Inf\n"
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestHistogram(t *testing.T) {
	var h Histogram
	h.Observe(time.Millisecond)       // first bucket
	h.Observe(300 * time.Millisecond) // le 1
	h.Observe(2 * time.Minute)        // past every bound
	var b bytes.Buffer
	w := NewWriter(&b)
	h.Write(w, "d_seconds", "site", "a")
	w.Flush()
	want := `d_seconds_bucket{site="a",le="0.005"} 1
d_seconds_bucket{site="a",le="0.025"} 1
d_seconds_bucket{site="a",le="0.1"} 1
d_seconds_bucket{site="a",le="0.25"} 1
d_seconds_bucket{site="a",le="1"} 2
d_seconds_bucket{site="a",le="2.5"} 2
d_seconds_bucket{site="a",le="10"} 2
d_seconds_bucket{site="a",le="60"} 2
d_seconds_bucket{site="a",le="+Inf"} 3
d_seconds_sum{site="a"} 120.301
d_seconds_count{site="a"} 3
`
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}
