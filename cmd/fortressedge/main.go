//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Sebiee/fortressedge/internal/clock"
	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/flod"
	"github.com/Sebiee/fortressedge/internal/frpsvc"
	"github.com/Sebiee/fortressedge/internal/httpsvc"
	"github.com/Sebiee/fortressedge/internal/initos"
	"github.com/Sebiee/fortressedge/internal/logx"
	"github.com/Sebiee/fortressedge/internal/metrics"
	"github.com/Sebiee/fortressedge/internal/netup"
	"github.com/Sebiee/fortressedge/internal/ops"
)

func main() {
	tuneGC()
	if err := run(); err != nil {
		say("fortressedge: %v", err)
		if os.Getpid() == 1 {
			say("fortressedge: rebooting in 30s")
			time.Sleep(30 * time.Second)
			reboot()
		}
		os.Exit(1)
	}
}

// tuneGC collects at five times the live heap rather than twice. Under
// load the edge allocates quickly but keeps little (about 16 MiB live in
// make waf-bench), and collecting less often gave 13% more requests a
// second there. The memory limit, half the machine, makes the collector
// work harder before memory runs short. GOGC and GOMEMLIMIT in the
// environment win.
func tuneGC() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(400)
	}
	var si unix.Sysinfo_t
	if os.Getenv("GOMEMLIMIT") == "" && unix.Sysinfo(&si) == nil {
		debug.SetMemoryLimit(int64(si.Totalram) * int64(si.Unit) / 2)
	}
}

// say is the last-resort printer for fatal errors and power events: it works
// even if logging never came up, and appends to the persistent log if the
// boot got far enough to create it.
func say(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	if logx.Active() {
		_, _ = logx.Writer().Write([]byte(msg))
		return
	}
	_, _ = os.Stderr.WriteString(msg)
	for _, p := range []string{"/dev/tty0", "/dev/ttyS0", "/dev/console"} {
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			continue
		}
		_, _ = f.WriteString(msg)
		_ = f.Close()
	}
	if f, err := os.OpenFile(config.LogFile, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		_, _ = f.WriteString(msg)
		_ = f.Close()
	}
}

func run() error {
	pid1 := os.Getpid() == 1
	if pid1 {
		if err := initos.Setup(); err != nil {
			return err
		}
	}
	logx.Setup()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logx.Watch(ctx)
	slog.Info("fortressedge: starting")

	if pid1 {
		initos.WatchPower(stop)
	}

	seed, err := initos.FindSeed()
	var cfg config.Config
	if err == nil {
		cfg, err = config.Parse(seed.UserData, seed.NetworkConfig, seed.Edge, nil)
	}
	if err != nil {
		if !pid1 {
			return err
		}
		cannotStart(ctx, err)
		return nil
	}
	if pid1 {
		if cfg.Disk, err = initos.MountVar(""); err != nil {
			return err
		}
		if err := logx.AddFile(config.LogDir); err != nil {
			slog.Warn("persistent log unavailable", "err", err)
		}
	}
	policy, err := initos.LoadPolicy(config.PolicyFile)
	if err != nil {
		return err
	}
	if p, err := config.ParsePolicy(policy); err != nil {
		// Not a reason to stay down: the next apply replaces it, and until
		// then diff shows the edge has none.
		slog.Error("stored policy invalid; running the defaults until the next apply", "err", err)
		policy = nil
	} else {
		cfg.Policy = p
	}
	slog.Info("config loaded", "tunnel", cfg.Tunnel, "acme", acmeName(cfg), "cert_store", certStoreName(cfg), "quic", cfg.QUIC,
		"disk", cfg.Disk, "ntp", cfg.NTP, "policy", policy != nil, "blocked", len(cfg.Block))
	// frps reads its trust anchor from a file. The edge holds the CA's
	// certificate only, never its key.
	if err := os.MkdirAll(filepath.Dir(config.RunClientCA), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(config.RunClientCA, cfg.ClientCA, 0o644); err != nil {
		return err
	}
	cfg.ClientCAPath = config.RunClientCA
	consoleStatus(false, false, cfg)
	restoreNeighbors, err := netup.BringUp(cfg)
	if err != nil {
		return err
	}
	consoleStatus(false, true, cfg)
	// The clock is stepped before anything that checks a certificate
	// starts, then kept in step while the edge runs.
	clk := clock.New(cfg.NTP, ipNetwork(cfg))
	syncCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = clk.Sync(syncCtx)
	cancel()
	// Boot's first exchanges are done: Linux's own neighbor discovery.
	restoreNeighbors()
	if err != nil {
		return err
	}
	go clk.Run(ctx)
	syn := flod.SYNRate{PerSecond: cfg.Limits.NewConnsPerSecond, Burst: cfg.Limits.NewConnBurst}
	filt, err := flod.Attach(cfg.Iface, cfg.Block, cfg.QUIC, syn)
	if err != nil {
		return err
	}
	defer filt.Close()
	slog.Info("xdp filter up", "iface", cfg.Iface, "mode", filt.Mode(), "blocked", len(cfg.Block), "quic", cfg.QUIC,
		"new_connections_per_second", syn.PerSecond, "new_connection_burst", syn.Burst)

	domains := httpsvc.NewDomains(cfg.Tunnel)
	var quic *frpsvc.QUIC
	if cfg.QUIC {
		cert, err := httpsvc.QUICCertificate(ctx, cfg, domains)
		if err != nil {
			return err
		}
		quic = &frpsvc.QUIC{ClientCA: cfg.ClientCAPath, Certificate: cert, Verify: httpsvc.NodeOnly(cfg.Tunnel)}
	}
	frps, err := frpsvc.Start(ctx, frpsvc.Options{
		QUIC: quic,
		// The default; each site request carries its site's (httpsvc).
		HeaderTimeout: cfg.Limits.ResponseHeaderTimeout,
		OnDomain:      domains.Domain,
		OnProxyError:  httpsvc.ProxyError,
		Node:          httpsvc.NodeName(cfg.Tunnel),
	})
	if err != nil {
		return err
	}
	defer frps.Stop()
	consoleStatus(true, true, cfg)
	var wantReboot atomic.Bool
	var applyMu sync.Mutex
	err = httpsvc.Serve(ctx, cfg, policy, filt, domains, frps.Control, frps.Vhost, func(b []byte) (ops.Outcome, error) {
		applyMu.Lock()
		defer applyMu.Unlock()
		p, aerr := config.ParsePolicy(b)
		if aerr != nil {
			return ops.Outcome{}, &config.InvalidError{Err: aerr}
		}
		if aerr = initos.StorePolicy(config.PolicyFile, b); aerr != nil {
			return ops.Outcome{}, aerr
		}
		next := cfg
		next.Policy = p
		if p.RebootFrom(cfg.Policy) {
			return ops.Outcome{Reboot: true, Cfg: next}, nil
		}
		if aerr = filt.SetBlock(p.Block); aerr != nil {
			return ops.Outcome{}, aerr
		}
		// httpsvc puts the other limits in force when this returns.
		if aerr = filt.SetSYNRate(flod.SYNRate{PerSecond: p.Limits.NewConnsPerSecond, Burst: p.Limits.NewConnBurst}); aerr != nil {
			return ops.Outcome{}, aerr
		}
		cfg = next
		consoleStatus(true, true, cfg)
		return ops.Outcome{Cfg: next}, nil
	}, func() {
		wantReboot.Store(true)
		stop()
	}, httpsvc.Extras{
		Metrics: []func(*metrics.Writer){frps.WriteMetrics, clk.WriteMetrics},
		Status: map[string]func() any{
			"clock":         func() any { return clk.Status() },
			"tunnel_groups": func() any { return frps.Groups() },
		},
		Ready: func() bool { return domains.TunnelCertValid(time.Now()) && len(frps.Groups()) > 0 },
	})
	if pid1 && wantReboot.Load() {
		say("fortressedge: rebooting into the new policy")
		reboot()
		return nil
	}
	if pid1 {
		poweroff(ctx)
	}
	return err
}

func consoleStatus(ready, connected bool, cfg config.Config) {
	dns := make([]string, 0, len(cfg.DNS))
	for _, d := range cfg.DNS {
		dns = append(dns, d.String())
	}
	quic := "off"
	if cfg.QUIC {
		quic = "on"
	}
	stage := "starting"
	if ready {
		stage = "up"
	}
	logx.SetStatus(logx.Status{
		Stage:     stage,
		Ready:     ready,
		Connected: connected,
		Tunnel:    cfg.Tunnel,
		ACME:      acmeName(cfg),
		QUIC:      quic,
		Disk:      cfg.Disk,
		NTP:       ntpName(cfg.NTP),
		Iface:     cfg.Iface,
		Addr:      cfg.Addr.String(),
		Gateway:   cfg.Gateway.String(),
		DNS:       strings.Join(dns, ","),
		Frps:      config.ControlAddr(),
		Listen:    ":80 :443",
		Blocked:   strconv.Itoa(len(cfg.Block)),
	})
}

// ntpName fits the servers in a console cell: the first, and how many more.
func ntpName(servers []string) string {
	if len(servers) < 2 {
		return strings.Join(servers, "")
	}
	return fmt.Sprintf("%s +%d", servers[0], len(servers)-1)
}

// ipNetwork is the address family the edge reaches NTP servers over: its
// own address's.
func ipNetwork(cfg config.Config) string {
	if cfg.Addr.Addr().Is4() {
		return "ip4"
	}
	return "ip6"
}

// acmeName is the host of the ACME directory, for the console and log.
// certStoreName is where the certificates are kept: the disk, or the
// disk and a Vault path. Never the AppRole.
func certStoreName(cfg config.Config) string {
	if v := cfg.Vault; v != nil {
		return "vault " + v.URL + "/" + v.Mount + "/" + v.Path
	}
	return "disk"
}

func acmeName(cfg config.Config) string {
	if cfg.ACME == "" {
		return "letsencrypt"
	}
	if u, err := url.Parse(cfg.ACME); err == nil {
		return u.Host
	}
	return cfg.ACME
}

// cannotStart shows why the config does not boot, and keeps it on the
// console until the operator powers the machine off: a reboot would read
// the same config again. The fix is on the platform (the VM's name or DNS
// domain, its IP config) or a new ISO, and both take effect at the next
// start.
func cannotStart(ctx context.Context, err error) {
	say("fortressedge: cannot start: %v", err)
	logx.SetStatus(logx.Status{
		Stage: "stopped",
		Notes: []string{
			"cannot start: " + err.Error(),
			"fix it and start the machine again; the power button powers it off",
		},
	})
	<-ctx.Done()
	say("fortressedge: powering off")
	halt()
}

// poweroff ends PID 1: power off when the operator signalled, reboot otherwise.
func poweroff(ctx context.Context) {
	if ctx.Err() != nil {
		say("fortressedge: powering off")
		halt()
		return
	}
	say("fortressedge: rebooting")
	reboot()
}

func halt() {
	unix.Sync()
	// POWER_OFF, not HALT. HALT stops the CPUs and leaves QEMU running, so
	// Proxmox Shutdown and Reboot time out waiting for the VM to exit.
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

func reboot() {
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
}
