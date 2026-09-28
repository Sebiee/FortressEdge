//go:build pprof

package ops

import (
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
)

// Built with -tags pprof, as make waf-bench builds its ISO, the ops API
// serves net/http/pprof's profiles to an operator. Release builds leave
// them out.
func init() {
	serve := func(h http.Handler) func(*Handler, http.ResponseWriter, *http.Request) {
		return func(_ *Handler, w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }
	}
	ops := []ca.Role{ca.RoleOps}
	get := "GET " + config.OpsPathPrefix + "pprof/"
	routes[get+"profile"] = route{ops, serve(http.HandlerFunc(pprof.Profile))}
	routes[get+"trace"] = route{ops, serve(http.HandlerFunc(pprof.Trace))}
	// The bench's reference: TLS and net/http on this VM, with nothing
	// proxied (TestCeiling).
	routes[get+"null"] = route{ops, func(_ *Handler, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}}
	// What the edge process has spent so far: CPU and allocations. The
	// bench's perf guard reads it before and after a replay.
	routes[get+"metrics"] = route{ops, func(_ *Handler, w http.ResponseWriter, _ *http.Request) {
		var ru syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
		s := []metrics.Sample{{Name: "/gc/heap/allocs:objects"}, {Name: "/gc/heap/allocs:bytes"},
			{Name: "/gc/cycles/total:gc-cycles"}, {Name: "/gc/heap/live:bytes"}}
		metrics.Read(s)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]uint64{
			"cpu_ns":        uint64(ru.Utime.Nano() + ru.Stime.Nano()),
			"alloc_objects": s[0].Value.Uint64(),
			"alloc_bytes":   s[1].Value.Uint64(),
			"gc_cycles":     s[2].Value.Uint64(),
			// The heap the last GC kept, and the most memory the process
			// has held since it started (VmHWM), in bytes.
			"heap_live_bytes": s[3].Value.Uint64(),
			"rss_peak_bytes":  procStatusKiB("VmHWM") << 10,
		})
	}}
	for _, p := range []string{"heap", "allocs", "goroutine", "mutex", "block"} {
		routes[get+p] = route{ops, serve(pprof.Handler(p))}
	}
}

// procStatusKiB is a "kB" field of /proc/self/status, or 0.
func procStatusKiB(field string) uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for l := range strings.Lines(string(b)) {
		if k, v, ok := strings.Cut(l, ":"); ok && k == field {
			n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			return n
		}
	}
	return 0
}
