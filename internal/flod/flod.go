//go:build linux

package flod

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
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
	"drop_truncated",
	"pass_arp",
	"pass_icmp6",
	"pass_icmp3",
	"pass_ntp",
	"pass_reply",
	"pass_dns",
	"drop_ethertype",
	"drop_fragment",
	"drop_proto",
	"drop_icmp",
}

// sweepEvery is how often ended bans leave the bans map.
const sweepEvery = time.Minute

// Filter is a loaded XDP program and its maps. Close detaches it.
type Filter struct {
	objs flodObjects
	l    link.Link
	mode string

	// banMu serializes Ban and sweep, the only writers of the bans map, so
	// a sweep never deletes a ban made after it read the map.
	banMu sync.Mutex
	stop  chan struct{}
	swept chan struct{}
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
	if err := f.SetBlock(block); err != nil {
		return nil, err
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
	f.stop, f.swept = make(chan struct{}), make(chan struct{})
	go f.sweepBans()
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
	if f.stop != nil {
		close(f.stop)
		<-f.swept
	}
	if f.l != nil {
		f.l.Close()
	}
	f.objs.Close()
}

// SetBlock replaces the block list while the XDP program runs. The new
// prefixes go in before the old ones leave, so no source either list
// blocks slips through meanwhile, and a failure puts the previous list
// back as it was.
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
	add4, drop4, err := diff(f.objs.Block4, keep4)
	if err != nil {
		return err
	}
	add6, drop6, err := diff(f.objs.Block6, keep6)
	if err != nil {
		return err
	}
	ops := slices.Concat(add4, add6, drop4, drop6)
	for i, op := range ops {
		if err := op.do(); err != nil {
			for _, done := range slices.Backward(ops[:i]) {
				if uerr := done.undo().do(); uerr != nil {
					err = fmt.Errorf("%w; restoring the previous list: %w", err, uerr)
				}
			}
			return fmt.Errorf("xdp block list: %w", err)
		}
	}
	return nil
}

// blockOp adds one prefix to a block map, or removes it.
type blockOp struct {
	m   *ebpf.Map
	key any
	add bool
}

func (op blockOp) do() error {
	if op.add {
		return op.m.Put(op.key, uint8(1))
	}
	return op.m.Delete(op.key)
}

func (op blockOp) undo() blockOp {
	op.add = !op.add
	return op
}

// diff returns the operations that turn m's keys into keep's.
func diff[K comparable](m *ebpf.Map, keep map[K]struct{}) (add, drop []blockOp, err error) {
	var (
		key K
		val uint8
	)
	have := map[K]struct{}{}
	it := m.Iterate()
	for it.Next(&key, &val) {
		have[key] = struct{}{}
		if _, ok := keep[key]; !ok {
			drop = append(drop, blockOp{m: m, key: key})
		}
	}
	if err := it.Err(); err != nil {
		return nil, nil, err
	}
	for k := range keep {
		if _, ok := have[k]; !ok {
			add = append(add, blockOp{m: m, key: k, add: true})
		}
	}
	return add, drop, nil
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

// Ban drops addr's packets in XDP until ttl elapses (monotonic clock, same
// as BPF): the address itself for IPv4, its /64 for IPv6, which is what one
// user usually holds.
func (f *Filter) Ban(addr netip.Addr, ttl time.Duration) error {
	if f == nil || !addr.IsValid() {
		return nil
	}
	if ttl <= 0 {
		return fmt.Errorf("ban: ttl %v", ttl)
	}
	now := monotonicNS()
	if now == 0 {
		return fmt.Errorf("ban: monotonic clock")
	}
	f.banMu.Lock()
	defer f.banMu.Unlock()
	return f.objs.Bans.Put(sourceKey(addr), now+uint64(ttl))
}

// sourceKey is addr's source in XDP: the address for IPv4, its /64 for
// IPv6.
func sourceKey(addr netip.Addr) flodSrcKey {
	addr = addr.Unmap()
	if addr.Is4() {
		k := flodSrcKey{Family: 4}
		a := addr.As4()
		copy(k.Ip[:], a[:])
		return k
	}
	k := flodSrcKey{Family: 6}
	a := addr.As16()
	copy(k.Ip[:8], a[:8])
	return k
}

func (f *Filter) sweepBans() {
	defer close(f.swept)
	tick := time.NewTicker(sweepEvery)
	defer tick.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-tick.C:
			if err := f.sweep(); err != nil {
				slog.Warn("xdp: sweeping ended bans", "err", err)
			}
		}
	}
}

// sweep deletes the bans that have ended, so they leave room for new ones.
func (f *Filter) sweep() error {
	f.banMu.Lock()
	defer f.banMu.Unlock()
	now := monotonicNS()
	var (
		key   flodSrcKey
		until uint64
		ended []flodSrcKey
	)
	it := f.objs.Bans.Iterate()
	for it.Next(&key, &until) {
		if until <= now {
			ended = append(ended, key)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range ended {
		if err := f.objs.Bans.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
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

func monotonicNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
