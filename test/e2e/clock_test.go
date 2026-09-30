//go:build e2e

package e2e

import (
	"bufio"
	"flag"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

var (
	clockFor = flag.Duration("clock", 0, "how long TestClockSoak keeps an edge on real NTP servers; 0 skips it (make clock-soak sets it)")
	clockNTP = flag.String("clock-ntp", "ntp11.metas.ch,ntp12.metas.ch,ntp13.metas.ch", "the servers TestClockSoak's edge keeps to")
)

// An edge on real NTP servers for -clock, printing its clock metrics each
// minute: how fast the kernel's discipline pulls the offset in, and where
// it settles. It needs the internet; it fails when the last offset is
// over a millisecond.
func TestClockSoak(t *testing.T) {
	if *clockFor == 0 {
		t.Skip("make clock-soak runs it")
	}
	e := lab.BootEdge(t, lab.EdgeOptions{NTP: strings.Split(*clockNTP, ",")})
	crt, key := e.Cert(ca.RoleLogs, "shipper")
	logs := e.VM.Client(t, e.Roots, crt, key)
	var offset float64
	for end := time.Now().Add(*clockFor); ; {
		_, body, err := lab.Get(logs, lab.OpsURL+"metrics")
		require.NoError(t, err)
		m := map[string]string{}
		for sc := bufio.NewScanner(strings.NewReader(body)); sc.Scan(); {
			name, v, ok := strings.Cut(sc.Text(), " ")
			if ok && (strings.HasPrefix(name, "fortressedge_clock_") || strings.HasPrefix(name, "fortressedge_ntp_round_trip")) {
				m[name] = v
			}
		}
		offset, _ = strconv.ParseFloat(m["fortressedge_clock_offset_seconds"], 64)
		t.Logf("offset %+.3f ms  frequency %s ppm  poll %ss  steps %s  rtt %v",
			offset*1e3, m["fortressedge_clock_frequency_ppm"], m["fortressedge_clock_poll_seconds"], m["fortressedge_clock_steps_total"], rtts(m))
		if time.Now().After(end) {
			break
		}
		time.Sleep(time.Minute)
	}
	require.Less(t, abs(offset), 1e-3, "the last offset")
}

func rtts(m map[string]string) []string {
	var out []string
	for k, v := range m {
		if s, ok := strings.CutPrefix(k, "fortressedge_ntp_round_trip_seconds{server=\""); ok {
			f, _ := strconv.ParseFloat(v, 64)
			out = append(out, strings.TrimSuffix(s, "\"}")+"="+strconv.FormatFloat(f*1e3, 'f', 1, 64)+"ms")
		}
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
