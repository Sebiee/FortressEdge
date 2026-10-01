//go:build e2e

package e2e

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Sebiee/fortressedge/test/e2e/lab"
)

// The first ARP request a machine sends after its link comes up can go
// unanswered: a bridge port or switch not forwarding yet, a router busy.
// Linux asks again only after a second, and the edge's boot waits on its
// clock sync, whose every packet needs that answer. On a tap, this host
// drops the edge's first ARP request after each boot, and boot must not
// take a second longer for it.
func TestBootSurvivesALostARP(t *testing.T) {
	if !lab.HasTap() {
		t.Skip("needs -tap: run in os/netns.sh")
	}
	// A request from the edge is dropped unless it asked in the last 3
	// seconds: the first of each boot, which comes more than 3 s after the
	// last of the one before.
	nft := `table arp lab {
	set asked { type ipv4_addr; flags timeout; timeout 3s; }
	chain in {
		type filter hook input priority 0; policy accept;
		arp operation request arp saddr ip @asked accept
		arp operation request arp saddr ip ` + lab.TapGuest + ` add @asked { arp saddr ip } counter drop
	}
}`
	cmd := exec.Command("/usr/sbin/nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nft)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "nft: %s", out)
	t.Cleanup(func() { exec.Command("/usr/sbin/nft", "delete", "table", "arp", "lab").Run() })

	e := lab.BootEdge(t, lab.EdgeOptions{Tap: true})
	vm, ops := e.VM, e.Ops
	for i := range 4 {
		if i > 0 {
			vm.PowerDown(t)
			vm.Restart(t)
			// Nothing from this host until the edge has booted: an ARP
			// request of this host's would teach the edge its address,
			// and the edge would never ask.
			time.Sleep(8 * time.Second)
		}
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			ops.CloseIdleConnections()
			_, _, err := lab.Get(ops, lab.OpsURL+"status")
			require.NoError(c, err)
		}, lab.Until(t), 50*time.Millisecond)
		_, body, err := lab.Get(ops, lab.OpsURL+"metrics")
		require.NoError(t, err)
		kernel, ready := metric(body, "fortressedge_kernel_boot_time_seconds"), metric(body, "fortressedge_ready_time_seconds")
		_, logs, err := lab.Get(ops, lab.OpsURL+"logs")
		require.NoError(t, err)
		var sync string
		for l := range strings.Lines(logs) {
			if strings.Contains(l, `msg="clock: boot sync"`) {
				sync = strings.TrimSpace(l[strings.Index(l, "took="):])
			}
		}
		took := time.Duration((ready - kernel) * float64(time.Second))
		if i == 0 {
			// The first boot formats the disk and obtains certificates.
			t.Logf("boot 0 (first): kernel to ready %s; %s", took.Round(time.Millisecond), sync)
			continue
		}
		t.Logf("boot %d: kernel to ready %s; %s; dropped ARP %s", i, took.Round(time.Millisecond), sync, dropped(t))
		synced, err := time.ParseDuration(strings.TrimPrefix(strings.Fields(sync)[0], "took="))
		require.NoError(t, err)
		assert.Less(t, synced, 500*time.Millisecond, "a lost ARP request held the clock sync")
	}
}

// metric is the value of the sample named name in a metrics body.
func metric(body, name string) float64 {
	for l := range strings.Lines(body) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), name+" "); ok {
			f, _ := strconv.ParseFloat(v, 64)
			return f
		}
	}
	return 0
}

// dropped is how many ARP requests the rule has dropped so far.
func dropped(t *testing.T) string {
	out, _ := exec.Command("/usr/sbin/nft", "list", "chain", "arp", "lab", "in").CombinedOutput()
	f := strings.Fields(string(out))
	for i, w := range f {
		if w == "packets" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return "?"
}

// A link that is not passing traffic yet when boot brings the network up
// (a NIC whose carrier comes late): boot waits for carrier, says how long,
// and its clock sync is quick once the link is up.
func TestBootWaitsForCarrier(t *testing.T) {
	t.Parallel()
	e := lab.BootEdge(t, lab.EdgeOptions{})
	vm, ops := e.VM, e.Ops
	const loaded = `msg="config loaded"` // logged just before the network comes up
	before := vm.ConsoleCount(t, loaded)
	vm.PowerDown(t)
	vm.Restart(t)
	vm.SetLink(t, false)
	require.Eventually(t, func() bool { return vm.ConsoleCount(t, loaded) > before }, lab.Until(t), 10*time.Millisecond)
	time.Sleep(time.Second)
	vm.SetLink(t, true)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		ops.CloseIdleConnections()
		_, _, err := lab.Get(ops, lab.OpsURL+"status")
		require.NoError(c, err)
	}, lab.Until(t), 50*time.Millisecond)
	_, logs, err := lab.Get(ops, lab.OpsURL+"logs")
	require.NoError(t, err)
	var up, sync string
	for l := range strings.Lines(logs) {
		switch {
		case strings.Contains(l, `msg="network up`):
			up = strings.TrimSpace(l)
		case strings.Contains(l, `msg="clock: boot sync"`):
			sync = strings.TrimSpace(l[strings.Index(l, "took="):])
		}
	}
	t.Logf("%s; %s", up, sync)
	require.Contains(t, up, "carrier_ms=")
	ms, _ := strconv.Atoi(strings.Fields(up[strings.Index(up, "carrier_ms=")+len("carrier_ms="):])[0])
	// The link is down for a second from when the host sees "config
	// loaded"; seeing it late, under load, takes up to a few hundred ms
	// of that.
	assert.Greater(t, ms, 500, "boot did not wait for the link")
	took, err := time.ParseDuration(strings.TrimPrefix(strings.Fields(sync)[0], "took="))
	require.NoError(t, err)
	assert.Less(t, took, 500*time.Millisecond, "the clock sync waited on the link too")
}
