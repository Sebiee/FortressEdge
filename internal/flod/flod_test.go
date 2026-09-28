//go:build linux

package flod

import (
	"net/netip"
	"os"
	"testing"
	"time"
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
