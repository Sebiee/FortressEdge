package httpsvc

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// leaveTime is how long an edge that stops goes on serving while its
// health check fails. A load balancer that checks every second or two has
// taken the edge out by then, so no new visitor meets its closed port.
const leaveTime = 3 * time.Second

// Leave is the first stage of an orderly stop: the edge serves as before,
// but answers 503 itself for the site the policy marks as a load
// balancer's health check (sites: health_check), and closes each
// visitor's connection after its response. The balancer then sends new
// visitors, and those connections' next requests, to the other edges, and
// the stop's second stage, closing the ports, refuses nobody.
//
// The zero value is ready to use. A nil *Leave never leaves.
type Leave struct {
	// For is how long the stage lasts; 0 is leaveTime.
	For time.Duration

	mu      sync.Mutex
	checked func() bool // whether a health check is in force; nil until the servers listen
	leaving atomic.Bool
	end     sync.Once
}

// serving says the edge listens, and how to ask whether its policy has a
// health check now.
func (l *Leave) serving(checked func() bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.checked = checked
	l.mu.Unlock()
}

// Begin starts the stop and calls end, once, when the edge may close: after
// the leave stage, or at once when nobody would see it (the edge does not
// listen yet, or its policy has no health check). A second Begin, a second
// signal, ends the stage at once.
func (l *Leave) Begin(end func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.leaving.Load() || l.checked == nil || !l.checked() {
		l.end.Do(end)
		return
	}
	d := l.For
	if d <= 0 {
		d = leaveTime
	}
	l.leaving.Store(true)
	slog.Info("fortressedge: leaving: the health check fails, and the edge serves until it closes", "closes_in", d.String())
	time.AfterFunc(d, func() { l.end.Do(end) })
}

// Leaving reports whether the edge is in the leave stage, or past it.
func (l *Leave) Leaving() bool { return l != nil && l.leaving.Load() }

// left answers the health check of an edge that leaves.
var left = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "edge is stopping", http.StatusServiceUnavailable)
})
