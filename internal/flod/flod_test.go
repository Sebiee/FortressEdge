//go:build linux

package flod

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestAttachLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	f, err := Attach("lo", nil, false, SYNRate{64, 128})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestLPMBlock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	cidr := netip.MustParsePrefix("192.0.2.0/24")
	v6 := netip.MustParsePrefix("2001:db8::/32")
	f, err := Attach("lo", []netip.Prefix{cidr, v6}, false, SYNRate{64, 128})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var hit flodBlockval
	if err := f.objs.Block4.Lookup(&flodLpm4{Prefixlen: 32, Addr: netip.MustParseAddr("192.0.2.10").As4()}, &hit); err != nil {
		t.Fatalf("v4 lpm: %v", err)
	}
	if hit.ExpireNs != 0 {
		t.Fatal("config block should be forever")
	}
	if err := f.objs.Block6.Lookup(&flodLpm6{Prefixlen: 128, Addr: netip.MustParseAddr("2001:db8::1").As16()}, &hit); err != nil {
		t.Fatalf("v6 lpm: %v", err)
	}

	ip := netip.MustParseAddr("203.0.113.9")
	if err := f.Ban(ip, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.objs.Block4.Lookup(&flodLpm4{Prefixlen: 32, Addr: ip.As4()}, &hit); err != nil {
		t.Fatalf("ban lookup: %v", err)
	}
	if hit.ExpireNs == 0 {
		t.Fatal("ban should expire")
	}

	// An IPv6 ban covers the source's /64.
	if err := f.Ban(netip.MustParseAddr("2001:db9::1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.objs.Block6.Lookup(&flodLpm6{Prefixlen: 128, Addr: netip.MustParseAddr("2001:db9::ffff:1").As16()}, &hit); err != nil || hit.ExpireNs == 0 {
		t.Fatalf("v6 ban /64: %v %+v", err, hit)
	}
	if err := f.objs.Block6.Lookup(&flodLpm6{Prefixlen: 128, Addr: netip.MustParseAddr("2001:db9:0:1::1").As16()}, &hit); err == nil {
		t.Fatal("v6 ban leaked past its /64")
	}
}

func TestSetBlockKeepsBan(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	old := netip.MustParsePrefix("192.0.2.0/24")
	next := netip.MustParsePrefix("198.51.100.0/24")
	f, err := Attach("lo", []netip.Prefix{old}, false, SYNRate{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ban := netip.MustParseAddr("203.0.113.9")
	if err := f.Ban(ban, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := f.SetBlock([]netip.Prefix{next}); err != nil {
		t.Fatal(err)
	}
	var hit flodBlockval
	if err := f.objs.Block4.Lookup(&flodLpm4{Prefixlen: 32, Addr: netip.MustParseAddr("192.0.2.10").As4()}, &hit); err == nil {
		t.Fatal("old prefix still present")
	}
	if err := f.objs.Block4.Lookup(&flodLpm4{Prefixlen: 32, Addr: netip.MustParseAddr("198.51.100.1").As4()}, &hit); err != nil || hit.ExpireNs != 0 {
		t.Fatalf("new prefix: %v %+v", err, hit)
	}
	if err := f.objs.Block4.Lookup(&flodLpm4{Prefixlen: 32, Addr: ban.As4()}, &hit); err != nil || hit.ExpireNs == 0 {
		t.Fatalf("ban: %v %+v", err, hit)
	}
}

func TestSetSYNRate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	f, err := Attach("lo", nil, false, SYNRate{64, 128})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got flodSynRateCfg
	check := func(ns uint64, burst uint32) {
		t.Helper()
		if err := f.objs.SynCfg.Lookup(uint32(0), &got); err != nil || got.Ns != ns || got.Burst != burst {
			t.Fatalf("syn_cfg=%+v err=%v, want ns=%d burst=%d", got, err, ns, burst)
		}
	}
	check(uint64(time.Second/64), 128)
	if err := f.SetSYNRate(SYNRate{PerSecond: 0, Burst: 0}); err != nil {
		t.Fatal(err)
	}
	check(0, 1) // off
}

// Each kind of frame drop_other used to hide lands under a reason of its
// own, and EtherTypes names what the non-IP frames were.
func TestDropReasons(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	f, err := Attach("lo", nil, false, SYNRate{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	eth := func(typ uint16, payload ...byte) []byte {
		b := make([]byte, 12, 14+len(payload))
		b = append(b, byte(typ>>8), byte(typ))
		return append(b, payload...)
	}
	ipv4 := func(proto byte, fragOff uint16, l4 ...byte) []byte {
		h := []byte{0x45, 0, 0, 0, 0, 0, byte(fragOff >> 8), byte(fragOff), 64, proto, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2}
		return append(h, l4...)
	}
	for _, tc := range []struct {
		name, reason string
		frame        []byte
	}{
		{"LLDP", "drop_ethertype", eth(0x88cc, make([]byte, 46)...)},
		{"STP (802.3)", "drop_ethertype", eth(0x0026, make([]byte, 46)...)},
		{"an IPv4 fragment", "drop_fragment", eth(0x0800, ipv4(17, 185, make([]byte, 8)...)...)},
		{"GRE", "drop_proto", eth(0x0800, ipv4(47, 0, make([]byte, 8)...)...)},
		{"an ICMP echo", "drop_icmp", eth(0x0800, ipv4(1, 0, 8, 0, 0, 0, 0, 0, 0, 0)...)},
		{"a cut IPv4 header", "drop_truncated", eth(0x0800, 0x45, 0, 0, 0)},
	} {
		before := f.Stats()[tc.reason]
		if _, err := f.objs.Flod.Run(&ebpf.RunOptions{Data: tc.frame}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := f.Stats()[tc.reason]; got != before+1 {
			t.Errorf("%s: %s went from %d to %d", tc.name, tc.reason, before, got)
		}
	}
	if et := f.EtherTypes(); et["0x88cc"] != 1 || et["llc"] != 1 {
		t.Fatalf("ethertypes: %v", et)
	}
}

var (
	edge4 = netip.MustParseAddr("192.0.2.200")
	edge6 = netip.MustParseAddr("2001:db8:e::1")
)

// frame is an Ethernet frame with an IP packet from src to dst.
func frame(src, dst netip.Addr, proto byte, payload []byte) []byte {
	b := make([]byte, 12, 128)
	if src.Is4() {
		b = append(b, 0x08, 0x00, 0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0)
	} else {
		b = append(b, 0x86, 0xdd, 0x60, 0, 0, 0, byte(len(payload)>>8), byte(len(payload)), proto, 64)
	}
	b = append(b, src.AsSlice()...)
	b = append(b, dst.AsSlice()...)
	return append(b, payload...)
}

// syn is a TCP SYN from src to the edge's port 443.
func syn(src netip.Addr) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12], tcp[13] = 0x50, 0x02
	dst := edge4
	if src.Is6() {
		dst = edge6
	}
	return frame(src, dst, 6, tcp)
}

// datagram is a UDP datagram from src to dst.
func datagram(src, dst netip.AddrPort) []byte {
	u := make([]byte, 9)
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	return frame(src.Addr(), dst.Addr(), 17, u)
}

// run passes frame through the filter n times and returns how many runs
// each reason counted.
func run(t *testing.T, f *Filter, frame []byte, n uint32) map[string]uint64 {
	t.Helper()
	before := f.Stats()
	if _, err := f.objs.Flod.Run(&ebpf.RunOptions{Data: frame, Repeat: n}); err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for k, v := range f.Stats() {
		if d := v - before[k]; d > 0 {
			out[k] = d
		}
	}
	return out
}

// reason is what the filter counted one frame as.
func reason(t *testing.T, f *Filter, frame []byte) string {
	t.Helper()
	for k := range run(t, f, frame, 1) {
		return k
	}
	t.Fatal("no reason counted")
	return ""
}

func attach(t *testing.T, block []netip.Prefix, syn SYNRate) *Filter {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	f, err := Attach("lo", block, false, syn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

// A stranger who forges a source's address cannot spend that source's
// SYN allowance while the edge is not flooded.
func TestForgedSYNsDoNotCutOffASource(t *testing.T) {
	f := attach(t, nil, SYNRate{PerSecond: 1, Burst: 4})
	for _, victim := range []netip.Addr{netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8:7::7")} {
		run(t, f, syn(victim), 200)
		if got := reason(t, f, syn(victim)); got != "pass" {
			t.Errorf("%s after 200 forged SYNs: %s, want pass", victim, got)
		}
	}
}

// In a flood, more SYNs than the edge takes from all sources at once, each
// source is held to its own rate again.
func TestSYNFloodIsLimitedPerSource(t *testing.T) {
	f := attach(t, nil, SYNRate{PerSecond: 1, Burst: 4})
	run(t, f, syn(netip.MustParseAddr("198.51.100.1")), 20000)
	got := run(t, f, syn(netip.MustParseAddr("198.51.100.2")), 10000)
	if got["pass"] < 4 || got["drop_synrate"] < 9000 {
		t.Fatalf("one source's 10000 SYNs in a flood: %v, want 4 or a few more through", got)
	}
}

// The edge's own NTP and DNS queries get their replies; a datagram from
// port 123 or 53 to a port it sent no query from is dropped.
func TestRepliesOnlyToQueries(t *testing.T) {
	f := attach(t, nil, SYNRate{})
	for _, tc := range []struct {
		network, server, reason string
	}{
		{"udp4", "127.0.0.53:53", "pass_dns"},
		{"udp6", "[::1]:53", "pass_dns"},
		{"udp4", "127.0.0.123:123", "pass_ntp"},
	} {
		c, err := net.Dial(tc.network, tc.server)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		server := netip.MustParseAddrPort(tc.server)
		local := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if got := reason(t, f, datagram(server, local)); got != tc.reason {
			t.Errorf("%s reply to its query: %s, want %s", tc.server, got, tc.reason)
		}
		closed := netip.AddrPortFrom(local.Addr(), local.Port()+1)
		if got := reason(t, f, datagram(server, closed)); got != "drop_port" {
			t.Errorf("%s datagram to a port with no query: %s, want drop_port", tc.server, got)
		}
		// A stranger forging the server's replies cannot crowd out the real one.
		run(t, f, datagram(server, closed), 1000)
		if got := reason(t, f, datagram(server, local)); got != tc.reason {
			t.Errorf("%s reply after 1000 forged ones: %s, want %s", tc.server, got, tc.reason)
		}
	}
}

// A policy update that cannot load leaves the previous block list in force,
// in both address families.
func TestSetBlockFailureKeepsTheList(t *testing.T) {
	old := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/48")}
	f := attach(t, old, SYNRate{})
	tooMany := func(v6 bool) []netip.Prefix {
		out := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		for i := range 20000 {
			a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
			if v6 {
				a = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, 14: byte(i >> 8), 15: byte(i)})
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
		return out
	}
	for _, v6 := range []bool{false, true} {
		if err := f.SetBlock(tooMany(v6)); err == nil {
			t.Fatalf("v6=%v: 20001 prefixes loaded", v6)
		}
		for src, want := range map[string]string{"192.0.2.9": "drop_block", "2001:db8:1::9": "drop_block", "198.51.100.9": "pass", "10.0.0.9": "pass"} {
			if got := reason(t, f, syn(netip.MustParseAddr(src))); got != want {
				t.Errorf("v6=%v: after the failed update, %s: %s, want %s", v6, src, got, want)
			}
		}
	}
}

// The edge can move from one full block list to another: 8192 prefixes of
// each family, none shared.
func TestSetBlockSwapsFullLists(t *testing.T) {
	list := func(n byte) []netip.Prefix {
		var out []netip.Prefix
		for i := range 8192 {
			out = append(out,
				netip.PrefixFrom(netip.AddrFrom4([4]byte{10, n, byte(i >> 8), byte(i)}), 32),
				netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, n, 14: byte(i >> 8), 15: byte(i)}), 128))
		}
		return out
	}
	f := attach(t, list(1), SYNRate{})
	if err := f.SetBlock(list(2)); err != nil {
		t.Fatal(err)
	}
	for src, want := range map[string]string{"10.1.0.7": "pass", "2001:db8:100::7": "pass", "10.2.0.7": "drop_block", "2001:db8:200::7": "drop_block"} {
		if got := reason(t, f, syn(netip.MustParseAddr(src))); got != want {
			t.Errorf("%s: %s, want %s", src, got, want)
		}
	}
}

// Bans do not use up the block list: thousands of banned sources leave
// room for every prefix a policy may list.
func TestBansLeaveTheBlockList(t *testing.T) {
	f := attach(t, nil, SYNRate{})
	for i := range 4000 {
		if err := f.Ban(netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}), time.Minute); err != nil {
			t.Fatalf("ban %d: %v", i, err)
		}
	}
	var block []netip.Prefix
	for i := range 8192 {
		block = append(block, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 3, byte(i >> 8), byte(i)}), 32))
	}
	if err := f.SetBlock(block); err != nil {
		t.Fatal(err)
	}
	for src, want := range map[string]string{"100.64.15.159": "drop_block", "10.3.31.255": "drop_block", "100.64.15.160": "pass"} {
		if got := reason(t, f, syn(netip.MustParseAddr(src))); got != want {
			t.Errorf("%s: %s, want %s", src, got, want)
		}
	}
}

// A ban drops its source until it ends, then the source passes again.
func TestBanEnds(t *testing.T) {
	f := attach(t, nil, SYNRate{})
	src := netip.MustParseAddr("203.0.113.9")
	if err := f.Ban(src, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := reason(t, f, syn(src)); got != "drop_block" {
		t.Fatalf("banned: %s", got)
	}
	time.Sleep(300 * time.Millisecond)
	if got := reason(t, f, syn(src)); got != "pass" {
		t.Fatalf("after the ban: %s", got)
	}
}

// With QUIC on, every datagram to UDP 443 passes: a stranger forging a dark
// node's address has no allowance of the node's to spend.
func TestQUICPasses(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	node := netip.MustParseAddrPort("203.0.113.1:50000")
	initial := datagram(node, netip.AddrPortFrom(edge4, 443))
	initial[14+20+8] = 0xc0
	for _, quic := range []bool{true, false} {
		f, err := Attach("lo", nil, quic, SYNRate{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[bool]string{true: "pass", false: "drop_port"}[quic]
		if got := run(t, f, initial, 5000); got[want] < 5000 || len(got) != 1 {
			t.Errorf("quic=%v: 5000 long-header packets from one node: %v, want all %s", quic, got, want)
		}
		f.Close()
	}
}
