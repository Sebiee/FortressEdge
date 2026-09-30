//go:build linux

package flod

import (
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
