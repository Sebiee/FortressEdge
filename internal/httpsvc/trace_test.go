package httpsvc

import (
	"net/http"
	"strings"
	"testing"
)

const visitorTP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestParseTraceparent(t *testing.T) {
	good := parseTraceparent([]string{visitorTP})
	if good.traceID != "4bf92f3577b34da6a3ce929d0e0e4736" || good.spanID != "00f067aa0ba902b7" || good.flags != 1 {
		t.Fatalf("parsed %+v", good)
	}
	// A later version is read as version 00, with its extra fields ignored.
	if later := parseTraceparent([]string{"cc" + visitorTP[2:] + "-what-comes-next"}); later.traceID != good.traceID {
		t.Fatalf("later version: %+v", later)
	}
	for _, bad := range [][]string{
		nil,
		{visitorTP, visitorTP}, // two
		{strings.ToUpper(visitorTP)},
		{"ff" + visitorTP[2:]},
		{visitorTP + "-extra"}, // version 00 has no more fields
		{"00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"},
		{"00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01"},
		{"00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0x"},
	} {
		if sc := parseTraceparent(bad); sc.valid() {
			t.Errorf("%q parsed as %+v", bad, sc)
		}
	}
}

func TestStartTrace(t *testing.T) {
	visitor := func() http.Header {
		return http.Header{traceparentHeader: {visitorTP}, tracestateHeader: {"vendor=x"}}
	}

	// Trusted: the visitor's trace goes on, under the edge's span.
	h := visitor()
	tr := startTrace(h, true)
	if tr.traceID != "4bf92f3577b34da6a3ce929d0e0e4736" || tr.parent != "00f067aa0ba902b7" || tr.link.valid() {
		t.Fatalf("trusted: %+v", tr)
	}
	if got := h.Get(traceparentHeader); got != "00-"+tr.traceID+"-"+tr.spanID+"-01" || tr.spanID == tr.parent {
		t.Fatalf("trusted: origin gets %q", got)
	}
	if h.Get(tracestateHeader) != "vendor=x" {
		t.Fatal("trusted: tracestate dropped")
	}

	// Not trusted: a trace of the edge's own, and the visitor's as a link.
	h = visitor()
	tr = startTrace(h, false)
	if tr.traceID == "4bf92f3577b34da6a3ce929d0e0e4736" || tr.parent != "" || tr.link.traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("untrusted: %+v", tr)
	}
	if got := h.Get(traceparentHeader); got != "00-"+tr.traceID+"-"+tr.spanID+"-01" || len(tr.traceID) != 32 || len(tr.spanID) != 16 {
		t.Fatalf("untrusted: origin gets %q", got)
	}
	if _, ok := h[tracestateHeader]; ok {
		t.Fatal("untrusted: the visitor's tracestate reached the origin")
	}

	// Trusted, but nothing valid came: a new trace, no link.
	h = http.Header{traceparentHeader: {"garbage"}}
	if tr = startTrace(h, true); tr.parent != "" || tr.link.valid() || !parseTraceparent(h.Values(traceparentHeader)).valid() {
		t.Fatalf("garbage: %+v %v", tr, h)
	}
}
