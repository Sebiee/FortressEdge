package httpsvc

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// W3C Trace Context (traceparent, tracestate). The edge is one hop of a
// trace: it gives the request a span id of its own and sends the origin a
// traceparent whose parent is that span, so the origin's spans hang under
// the edge's. The edge exports no spans: its access log line has what one
// needs (trace, span, and parent ids, start, duration), and a collector
// rebuilds the span from it.
const (
	traceparentHeader = "Traceparent"
	tracestateHeader  = "Tracestate"
	// traceIDHeader returns the trace id to the visitor, as
	// requestIDHeader returns the request id.
	traceIDHeader = "Fortress-Trace-Id"
)

// spanContext is one traceparent: ids in lowercase hex.
type spanContext struct {
	traceID string // 32
	spanID  string // 16
	flags   byte
}

func (s spanContext) valid() bool { return s.traceID != "" }

// trace is what the edge's hop of a request is in its trace.
type trace struct {
	spanContext        // the edge's span
	parent      string // the visitor's span id, when the edge continued its trace
	// link is the visitor's traceparent when the edge did not trust it:
	// its trace, as a span link, not as the edge's parent.
	link spanContext
}

// startTrace gives r's hop of its trace and sets the traceparent the
// origin gets. trust continues a visitor's valid traceparent (and keeps
// its tracestate); otherwise every request starts a trace of its own,
// sampled, and the visitor's tracestate is dropped with it.
func startTrace(h http.Header, trust bool) trace {
	var t trace
	in := parseTraceparent(h.Values(traceparentHeader))
	// The traceparent is one string; the ids are slices of it.
	var rnd [24]byte
	rand.Read(rnd[:])
	b := make([]byte, 0, 55)
	b = append(b, "00-"...)
	if trust && in.valid() {
		b = append(b, in.traceID...)
		t.flags, t.parent = in.flags, in.spanID
	} else {
		b = hex.AppendEncode(b, rnd[:16])
		t.flags, t.link = 0x01, in
		h.Del(tracestateHeader)
	}
	b = append(b, '-')
	b = hex.AppendEncode(b, rnd[16:])
	b = append(b, '-')
	b = hex.AppendEncode(b, []byte{t.flags})
	tp := string(b)
	t.traceID, t.spanID = tp[3:35], tp[36:52]
	h[traceparentHeader] = []string{tp}
	return t
}

// parseTraceparent reads the header's one value, as the spec's version 00
// reads it; a later version is read the same way, and anything that does
// not parse is no traceparent.
func parseTraceparent(vals []string) spanContext {
	if len(vals) != 1 {
		return spanContext{} // two are as good as none
	}
	v := vals[0]
	if len(v) < 55 || v[2] != '-' || v[35] != '-' || v[52] != '-' || !lowerHex(v[:2]) || v[:2] == "ff" {
		return spanContext{}
	}
	if v[:2] == "00" && len(v) != 55 || len(v) > 55 && v[55] != '-' {
		return spanContext{}
	}
	traceID, spanID, flags := v[3:35], v[36:52], v[53:55]
	if !lowerHex(traceID) || !lowerHex(spanID) || !lowerHex(flags) || allZero(traceID) || allZero(spanID) {
		return spanContext{}
	}
	f, _ := hex.DecodeString(flags)
	return spanContext{traceID: traceID, spanID: spanID, flags: f[0]}
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}
