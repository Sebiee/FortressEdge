//go:build linux

package netup

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Sebiee/fortressedge/internal/config"
)

// Boot's neighbor discovery (ARP, and IPv6's) asks every bootRetrans, up
// to bootSolicit times, where Linux asks 3 times a second apart: boot
// waits on its first packets, its clock sync's, before the edge listens,
// and a first request that goes unanswered (a bridge port or a switch not
// forwarding yet) would hold it a second. The many tries keep a packet
// queued while the link is not passing traffic yet, where 3 fast ones
// would give up and drop it. RestoreNeighbors puts Linux's back.
const (
	bootRetrans = "100" // ms
	bootSolicit = "30"
	// carrierWait bounds how long BringUp waits for the link's carrier.
	carrierWait = 3 * time.Second
)

// BringUp configures lo and cfg.Iface, and returns once the link has
// carrier, or after carrierWait. restore puts back the neighbor
// discovery settings boot changed; call it once boot's first exchanges
// are done.
func BringUp(cfg config.Config) (restore func(), err error) {
	restore = fastNeighbors(cfg.Iface)
	if err := bringUp(cfg); err != nil {
		restore()
		return func() {}, err
	}
	return restore, nil
}

// fastNeighbors sets boot's neighbor discovery on iface, for IPv4 and
// IPv6, and returns what puts the old values back.
func fastNeighbors(iface string) (restore func()) {
	type old struct{ path, val string }
	var saved []old
	for _, fam := range []string{"ipv4", "ipv6"} {
		for key, val := range map[string]string{"retrans_time_ms": bootRetrans, "mcast_solicit": bootSolicit} {
			p := filepath.Join("/proc/sys/net", fam, "neigh", iface, key)
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if os.WriteFile(p, []byte(val), 0) == nil {
				saved = append(saved, old{p, strings.TrimSpace(string(b))})
			}
		}
	}
	return func() {
		for _, s := range saved {
			_ = os.WriteFile(s.path, []byte(s.val), 0)
		}
	}
}

func bringUp(cfg config.Config) error {
	if lo, err := netlink.LinkByName("lo"); err == nil {
		if err := netlink.LinkSetUp(lo); err != nil {
			return fmt.Errorf("lo: %w", err)
		}
		if err := netlink.AddrReplace(lo, &netlink.Addr{
			IPNet: &net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
		}); err != nil {
			return fmt.Errorf("lo addr: %w", err)
		}
	}
	l, err := netlink.LinkByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("iface %s: %w", cfg.Iface, err)
	}
	start := time.Now()
	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}
	if err := apply(l, cfg.Addr, cfg.Gateway, cfg.DNS); err != nil {
		return err
	}
	carrier, ok := waitCarrier(cfg.Iface, start, carrierWait)
	attrs := []any{"iface", cfg.Iface, "addr", cfg.Addr, "gateway", cfg.Gateway, "dns", cfg.DNS}
	if !ok {
		slog.Warn("network up, no carrier yet: packets wait for the link", append(attrs, "waited", carrierWait)...)
		return nil
	}
	slog.Info("network up", append(attrs, "carrier_ms", carrier.Milliseconds())...)
	return nil
}

// waitCarrier polls iface until it is running (the kernel's carrier flag,
// set once the link is passing traffic), and returns how long after since
// it was, or false after wait.
func waitCarrier(iface string, since time.Time, wait time.Duration) (time.Duration, bool) {
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if l, err := netlink.LinkByName(iface); err == nil && l.Attrs().RawFlags&unix.IFF_RUNNING != 0 {
			return time.Since(since), true
		}
	}
	return 0, false
}
func apply(l netlink.Link, prefix netip.Prefix, gw netip.Addr, dns []netip.Addr) error {
	if err := netlink.AddrReplace(l, &netlink.Addr{IPNet: prefixToIPNet(prefix)}); err != nil {
		return err
	}
	if gw.IsValid() {
		// Some providers hand out a /32 with a gateway outside it (Hetzner's
		// 172.31.1.1). The kernel needs a route to the gateway on the link
		// before it takes one via it.
		if !prefix.Masked().Contains(gw) {
			if err := netlink.RouteReplace(&netlink.Route{
				LinkIndex: l.Attrs().Index,
				Dst:       prefixToIPNet(netip.PrefixFrom(gw, gw.BitLen())),
				Scope:     netlink.SCOPE_LINK,
			}); err != nil {
				return fmt.Errorf("route to gateway %s: %w", gw, err)
			}
		}
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        gw.AsSlice(),
		}); err != nil {
			return fmt.Errorf("default route: %w", err)
		}
	}
	if len(dns) == 0 {
		return nil
	}
	var b strings.Builder
	for _, d := range dns {
		fmt.Fprintf(&b, "nameserver %s\n", d)
	}
	if err := os.MkdirAll("/etc", 0o755); err != nil {
		return err
	}
	return os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0o644)
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	ip := p.Addr()
	n := 32
	if ip.Is6() {
		n = 128
	}
	return &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(p.Bits(), n)}
}
