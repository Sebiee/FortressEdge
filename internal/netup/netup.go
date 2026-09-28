//go:build linux

package netup

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/Sebiee/fortressedge/internal/config"
)

func BringUp(cfg config.Config) error {
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
	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}
	if err := apply(l, cfg.Addr, cfg.Gateway, cfg.DNS); err != nil {
		return err
	}
	slog.Info("network up", "iface", cfg.Iface, "addr", cfg.Addr, "gateway", cfg.Gateway, "dns", cfg.DNS)
	return nil
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
