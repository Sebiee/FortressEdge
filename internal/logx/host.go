package logx

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// userHZ is the Linux USER_HZ for /proc/stat. Every architecture we boot uses 100.
const userHZ = 100

type cpuSample struct {
	total, idle uint64
	ok          bool
}

type machine struct {
	uptime string
	cpu    string
	conns  string
	cpuUse string
	ramUse string
}

func sampleMachine(prev *cpuSample, cpuTopo string) machine {
	m := machine{
		uptime: uptimeLabel(),
		cpu:    cpuTopo,
		cpuUse: "n/a",
		ramUse: "n/a",
	}
	if text, err := os.ReadFile("/proc/meminfo"); err == nil {
		if total, avail, ok := parseMeminfo(string(text)); ok && total > 0 {
			used := total - avail
			if avail > total {
				used = 0
			}
			m.ramUse = formatMemUse(used, total)
		}
	}
	if text, err := os.ReadFile("/proc/stat"); err == nil {
		if total, idle, ok := parseCPUStat(string(text)); ok {
			m.cpuUse = takeCPU(prev, total, idle)
		}
	}
	return m
}

func takeCPU(prev *cpuSample, total, idle uint64) string {
	out := "n/a"
	if prev.ok && total > prev.total {
		idleDelta := uint64(0)
		if idle > prev.idle {
			idleDelta = idle - prev.idle
		}
		out = formatCPUUse(total-prev.total, idleDelta, userHZ)
	}
	*prev = cpuSample{total: total, idle: idle, ok: true}
	return out
}

func identityLine(m machine) string {
	s := "fortressedge: " + m.uptime
	if m.cpu != "" {
		s += ", " + m.cpu
	}
	if m.conns != "" {
		s += ", " + m.conns
	}
	return s
}

func usageLine(m machine) string {
	return "CPU " + m.cpuUse + ", RAM " + m.ramUse
}

func headerLine(m machine) string {
	return identityLine(m) + ", " + usageLine(m)
}

func parseCPUStat(text string) (total, idle uint64, ok bool) {
	for line := range strings.Lines(text) {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return 0, 0, false
		}
		nums := make([]uint64, 0, 8)
		for _, f := range fields[1:] {
			n, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				break
			}
			nums = append(nums, n)
		}
		// user nice system idle iowait irq softirq steal. guest is already inside user.
		if len(nums) < 5 {
			return 0, 0, false
		}
		n := min(len(nums), 8)
		for _, v := range nums[:n] {
			total += v
		}
		idle = nums[3] + nums[4]
		return total, idle, true
	}
	return 0, 0, false
}

func parseMeminfo(text string) (total, avail uint64, ok bool) {
	var gotTotal, gotAvail bool
	for line := range strings.Lines(text) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = n * 1024
			gotTotal = true
		case "MemAvailable:":
			avail = n * 1024
			gotAvail = true
		}
	}
	return total, avail, gotTotal && gotAvail
}

func parseCPUInfo(text string) (n int, mhz float64) {
	for line := range strings.Lines(text) {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "processor" {
			n++
		}
		if key == "cpu MHz" && mhz == 0 {
			mhz, _ = strconv.ParseFloat(val, 64)
		}
	}
	return n, mhz
}

func formatCPUTopo(n int, mhz float64) string {
	if n < 1 {
		return ""
	}
	if mhz <= 0 {
		return fmt.Sprintf("%d cpu", n)
	}
	return fmt.Sprintf("%dx%.2fGHz", n, mhz/1000)
}

func formatCPUUse(totalDelta, idleDelta, hz uint64) string {
	if totalDelta == 0 || hz == 0 {
		return "n/a"
	}
	if idleDelta > totalDelta {
		idleDelta = totalDelta
	}
	busy := totalDelta - idleDelta
	ms := 1000 * float64(busy) / float64(hz)
	pct := 100 * float64(busy) / float64(totalDelta)
	raw := "<1ms"
	if ms >= 1 {
		raw = fmt.Sprintf("%.0fms", ms)
	}
	return fmt.Sprintf("%s (%.1f%%)", raw, pct)
}

func formatMemUse(used, total uint64) string {
	if total == 0 {
		return "n/a"
	}
	pct := 100 * float64(used) / float64(total)
	return fmt.Sprintf("%s of %s (%.1f%%)", formatBytes(used), formatBytes(total), pct)
}

func formatBytes(n uint64) string {
	const (
		mib = 1024 * 1024
		gib = 1024 * mib
	)
	if n >= gib {
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(gib))
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/float64(mib))
}

func formatConns(n int) string {
	if n == 1 {
		return "1 connection"
	}
	return fmt.Sprintf("%d connections", n)
}

func uptimeLabel() string {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "uptime n/a"
	}
	field, _, _ := strings.Cut(string(b), " ")
	sec, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return "uptime n/a"
	}
	return formatUptime(sec)
}

func formatUptime(sec float64) string {
	if sec < 0 {
		sec = 0
	}
	n := int(sec)
	h := n / 3600
	m := (n % 3600) / 60
	s := n % 60
	switch {
	case h > 0:
		return fmt.Sprintf("uptime %dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("uptime %dm%02ds", m, s)
	default:
		return fmt.Sprintf("uptime %ds", s)
	}
}
