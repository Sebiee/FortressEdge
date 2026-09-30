//go:build linux

package flod

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux flod ../../bpf/flod.c -- -I../../bpf/headers

// Must match REASON_* in bpf/flod.c.
var reasonNames = []string{
	"pass",
	"drop_block",
	"drop_port",
	"drop_synrate",
	"drop_ntprate",
	"drop_truncated",
	"pass_arp",
	"pass_icmp6",
	"pass_icmp3",
	"pass_ntp",
	"pass_reply",
	"pass_dns",
	"drop_dnsrate",
	"drop_ethertype",
	"drop_fragment",
	"drop_proto",
	"drop_icmp",
}

// Filter is a loaded XDP program and its maps. Close detaches it.
type Filter struct {
	objs flodObjects
	l    link.Link
	mode string
}

// SYNRate is how many new TCP connections one source may open: perSecond
// sustained, burst at once. PerSecond 0 means no limit.
type SYNRate struct{ PerSecond, Burst int }

// Attach loads the XDP filter onto ifaceName. Driver mode first, generic (SKB) as fallback.
func Attach(ifaceName string, block []netip.Prefix, quic bool, syn SYNRate) (*Filter, error) {
	// don't import cilium/ebpf/rlimit; its init() reads /proc before we mount it.
	f := &Filter{}
	if err := loadFlodObjects(&f.objs, nil); err != nil {
		return nil, fmt.Errorf("load xdp: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			f.objs.Close()
		}
	}()
	if quic {
		if err := f.objs.AllowQuic.Put(uint32(0), uint8(1)); err != nil {
			return nil, fmt.Errorf("quic xdp: %w", err)
		}
	}
	if err := f.SetSYNRate(syn); err != nil {
		return nil, err
	}
	for _, p := range block {
		if err := f.putBlock(p, 0); err != nil {
			return nil, err
		}
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	f.mode = "driver"
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   f.objs.Flod,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		// virtio-net, for one, takes driver mode only with a spare TX
		// queue per CPU.
		f.mode = "generic"
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   f.objs.Flod,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("attach xdp: %w", err)
	}
	f.l = l
	ok = true
	return f, nil
}

// Mode is how the filter attached: driver (in the NIC driver, before the
// kernel allocates for a packet) or generic (after, slower).
func (f *Filter) Mode() string { return f.mode }

func (f *Filter) Close() {
	if f == nil {
		return
	}
	if f.l != nil {
		f.l.Close()
	}
	f.objs.Close()
}

// SetBlock replaces the permanent drop list (expire_ns == 0). Runtime bans
// (expire_ns != 0) stay. The XDP program keeps running.
func (f *Filter) SetBlock(block []netip.Prefix) error {
	if f == nil {
		return nil
	}
	keep4 := map[flodLpm4]struct{}{}
	keep6 := map[flodLpm6]struct{}{}
	for _, p := range block {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		addr := p.Addr().Unmap()
		bits := p.Bits()
		if addr.Is4() {
			if bits > 32 {
				bits = 32
			}
			keep4[flodLpm4{Prefixlen: uint32(bits), Addr: addr.As4()}] = struct{}{}
			continue
		}
		if addr.Is6() {
			keep6[flodLpm6{Prefixlen: uint32(bits), Addr: addr.As16()}] = struct{}{}
		}
	}
	if err := syncStatic(f.objs.Block4, keep4); err != nil {
		return err
	}
	return syncStatic(f.objs.Block6, keep6)
}

func syncStatic[K comparable](m *ebpf.Map, keep map[K]struct{}) error {
	var key K
	var val flodBlockval
	it := m.Iterate()
	var drop []K
	for it.Next(&key, &val) {
		if val.ExpireNs != 0 {
			continue
		}
		if _, ok := keep[key]; !ok {
			drop = append(drop, key)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range drop {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	zero := flodBlockval{}
	for k := range keep {
		if err := m.Put(k, zero); err != nil {
			return err
		}
	}
	return nil
}

// SetSYNRate changes the SYN limit while XDP runs. Sources keep the
// tokens they have; they refill at the new rate.
func (f *Filter) SetSYNRate(syn SYNRate) error {
	if f == nil {
		return nil
	}
	cfg := flodSynRateCfg{Burst: uint32(max(syn.Burst, 1))}
	if syn.PerSecond > 0 {
		cfg.Ns = uint64(time.Second) / uint64(syn.PerSecond)
	}
	if err := f.objs.SynCfg.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("xdp syn rate: %w", err)
	}
	return nil
}

// Ban pins addr until ttl elapses (monotonic clock, same as BPF): the
// address itself for IPv4, its /64 for IPv6, which is what one user
// usually holds. ttl <= 0 is forever. XDP then drops that source before
// its next handshake.
func (f *Filter) Ban(addr netip.Addr, ttl time.Duration) error {
	if f == nil || !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	var expire uint64
	if ttl > 0 {
		now := monotonicNS()
		if now == 0 {
			return fmt.Errorf("ban: monotonic clock")
		}
		expire = now + uint64(ttl)
	}
	p := netip.PrefixFrom(addr, 32)
	if addr.Is6() {
		p, _ = addr.Prefix(64) // bpf/flod.c deletes an expired IPv6 ban by this key
	}
	return f.putBlock(p, expire)
}

func (f *Filter) Stats() map[string]uint64 {
	out := make(map[string]uint64, len(reasonNames))
	if f == nil {
		return out
	}
	for i, name := range reasonNames {
		var vals []uint64
		if err := f.objs.Counts.Lookup(uint32(i), &vals); err != nil {
			continue
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		out[name] = sum
	}
	return out
}

// EtherTypes counts the frames dropped for their EtherType (drop_ethertype),
// by EtherType as 0x88cc, or llc for an IEEE 802.3 frame, whose type field
// is a length. The program tracks up to 64 types.
func (f *Filter) EtherTypes() map[string]uint64 {
	out := map[string]uint64{}
	if f == nil {
		return out
	}
	var (
		t uint16
		n uint64
	)
	it := f.objs.Ethertypes.Iterate()
	for it.Next(&t, &n) {
		name := fmt.Sprintf("0x%04x", t)
		if t == 0 {
			name = "llc"
		}
		out[name] = n
	}
	return out
}

func (f *Filter) putBlock(p netip.Prefix, expire uint64) error {
	if !p.IsValid() {
		return nil
	}
	addr := p.Addr().Unmap()
	bits := p.Bits()
	if addr.Is4() && bits > 32 {
		bits = 32
	}
	val := flodBlockval{ExpireNs: expire}
	if addr.Is4() {
		return f.objs.Block4.Put(&flodLpm4{Prefixlen: uint32(bits), Addr: addr.As4()}, &val)
	}
	if addr.Is6() {
		return f.objs.Block6.Put(&flodLpm6{Prefixlen: uint32(bits), Addr: addr.As16()}, &val)
	}
	return nil
}

func monotonicNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
