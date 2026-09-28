package logx

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAddFileRotatesPreviousBoot(t *testing.T) {
	dir := t.TempDir()
	if err := AddFile(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Writer().Write([]byte("boot one\n")); err != nil {
		t.Fatal(err)
	}
	if err := AddFile(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Writer().Write([]byte("boot two\n")); err != nil {
		t.Fatal(err)
	}
	prev, err := os.ReadFile(filepath.Join(dir, "previous.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prev), "boot one") {
		t.Fatalf("previous.log = %q", prev)
	}
	cur, err := os.ReadFile(filepath.Join(dir, "current.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cur), "boot two") {
		t.Fatalf("current.log = %q", cur)
	}
}

func TestLogTimeHasMilliseconds(t *testing.T) {
	when := time.Date(2026, 9, 22, 16, 53, 23, 833000000, time.UTC)
	got := replaceTime(nil, slog.Time(slog.TimeKey, when))
	if got.Value.String() != "16:53:23.833" {
		t.Fatalf("time = %s", got.Value.String())
	}
}

func testHost() machine {
	return machine{
		uptime: "uptime 12s",
		cpu:    "1x3.59GHz",
		conns:  "3 connections",
		cpuUse: "8ms (0.8%)",
		ramUse: "64.0 MiB of 512.0 MiB (12.5%)",
	}
}

func TestRenderStatusColor(t *testing.T) {
	up := renderStatus(24, 100, 0, 0, 0, true, Status{
		Stage:     "up",
		Ready:     true,
		Connected: true,
		Tunnel:    "tunnel.example.com",
		Addr:      "10.0.2.15/24",
	}, testHost())
	text := string(up.bytes)
	if !strings.Contains(text, "CPU 8ms (0.8%)") || !strings.Contains(text, "RAM 64.0 MiB of 512.0 MiB (12.5%)") {
		t.Fatalf("host line:\n%s", text)
	}
	if !strings.Contains(text, "3 connections") || !strings.Contains(text, strings.Repeat("-", 40)) {
		t.Fatalf("header or rule:\n%s", text)
	}
	if !strings.Contains(text, "\033[32mTrue") || !strings.Contains(text, "\033[32mOK") {
		t.Fatalf("ready/connectivity:\n%s", text)
	}
	if strings.Contains(text, "\033[32mtunnel.example.com") || strings.Contains(text, "\033[32m10.0.2.15/24") {
		t.Fatalf("identity was colored:\n%s", text)
	}
	if !strings.Contains(text, fmt.Sprintf("\033[%d;24r", up.panel+1)) || up.row != up.panel+1 {
		t.Fatalf("scroll region row=%d panel=%d\n%s", up.row, up.panel, text)
	}

	down := renderStatus(24, 100, 0, 0, 0, true, Status{
		Stage: "stopped",
		Notes: []string{"cannot start: abc"},
	}, testHost())
	bad := string(down.bytes)
	if !strings.Contains(bad, "\033[31mFalse") || !strings.Contains(bad, "\033[31mDOWN") {
		t.Fatalf("down:\n%s", bad)
	}
	if strings.Contains(bad, "\033[32m") || !strings.Contains(bad, "stopped") {
		t.Fatalf("down:\n%s", bad)
	}
	if !strings.Contains(bad, "cannot start: abc") {
		t.Fatalf("note:\n%s", bad)
	}
}

func TestRenderStatusCursor(t *testing.T) {
	host := testHost()
	st := Status{Stage: "up", Ready: true, Connected: true}
	first := renderStatus(24, 100, 0, 0, 0, true, st, host)
	same := renderStatus(24, 100, first.panel+5, 3, first.panel, false, st, host)
	got := string(same.bytes)
	if !strings.Contains(got, "\0337") || !strings.Contains(got, "\0338") || same.row != first.panel+5 {
		t.Fatalf("row=%d panel=%d\n%s", same.row, same.panel, got)
	}
	grown := renderStatus(24, 100, 2, 0, 1, false, Status{
		Stage: "stopped",
		Notes: []string{"a", "b", "c", "d", "e"},
	}, host)
	if grown.row != grown.panel+1 || strings.Contains(string(grown.bytes), "\0338") {
		t.Fatalf("parked row=%d panel=%d\n%s", grown.row, grown.panel, grown.bytes)
	}
}

func TestDeltaSkipsUnchangedLines(t *testing.T) {
	st := Status{Stage: "up", Ready: true, Connected: true, Tunnel: "tunnel.example.com"}
	lines := panelView(24, 100, st, testHost())
	if deltaBytes(lines, lines) != nil {
		t.Fatal("unchanged panel was rewritten")
	}
	next := testHost()
	next.uptime = "uptime 17s"
	next.cpuUse = "4ms (0.4%)"
	changed := panelView(24, 100, st, next)
	text := string(deltaBytes(lines, changed))
	if !strings.Contains(text, "4ms (0.4") || !strings.Contains(text, "\0337") || !strings.Contains(text, "\0338") {
		t.Fatalf("delta:\n%s", text)
	}
	if strings.Contains(text, "STAGE") || strings.Contains(text, "\033[2J") || strings.Contains(text, ";24r") {
		t.Fatalf("full redraw:\n%s", text)
	}
}

func TestDeltaSendsOnlyChangedCharacters(t *testing.T) {
	old := []dashLine{textLine("fortressedge: uptime 12s, CPU 20ms (0.4%)")}
	got := string(deltaBytes(old, []dashLine{textLine("fortressedge: uptime 17s, CPU 30ms (0.4%)")}))
	if got != "\0337\033[1;23H7s, CPU 3\0338" {
		t.Fatalf("same length: %q", got)
	}
	got = string(deltaBytes(old, []dashLine{textLine("fortressedge: uptime 1m00s")}))
	if got != "\0337\033[1;23Hm00s\033[K\0338" {
		t.Fatalf("shorter: %q", got)
	}
	colored := []dashLine{{spans: []span{{s: "READY "}, {s: "True", color: "\033[32m"}}}}
	flipped := []dashLine{{spans: []span{{s: "READY "}, {s: "False", color: "\033[31m"}}}}
	if got := string(deltaBytes(colored, flipped)); !strings.Contains(got, "\033[2K") || !strings.Contains(got, "\033[31mFalse") {
		t.Fatalf("colored line not rewritten whole: %q", got)
	}
}

// Why an edge cannot start is longer than a console line: it wraps, and
// all of it shows on an 80-column console with the grid.
func TestCannotStartFits(t *testing.T) {
	notes := []string{
		`cannot start: user-data: fqdn "edge1": not a DNS name with a domain; on Proxmox, name the VM edge1.example.com or give it a DNS domain`,
		"fix it and start the machine again; the power button powers it off",
	}
	p := renderStatus(24, 80, 0, 0, 0, true, Status{Stage: "stopped", Notes: notes}, testHost())
	text := string(p.bytes)
	for _, want := range []string{"cannot start: user-data", "give it a DNS domain", "the power button powers it off"} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q clipped, panel=%d\n%s", want, p.panel, text)
		}
	}
	if !strings.Contains(text, "CPU 8ms (0.8%)") || !strings.Contains(text, "RAM 64.0 MiB of 512.0 MiB (12.5%)") {
		t.Fatalf("usage clipped:\n%s", text)
	}
}

func TestHostMath(t *testing.T) {
	total, idle, ok := parseCPUStat("cpu  10 20 30 40 5 1 2 3 9 9\ncpu0 1 0 0 1 0 0 0 0 0 0\n")
	if !ok || total != 111 || idle != 45 {
		t.Fatalf("total=%d idle=%d ok=%v", total, idle, ok)
	}
	if got := formatCPUUse(100, 50, 100); got != "500ms (50.0%)" {
		t.Fatalf("cpu use %s", got)
	}
	memTotal, avail, ok := parseMeminfo("MemTotal: 524288 kB\nMemAvailable: 262144 kB\n")
	if !ok || memTotal != 524288*1024 || avail != 262144*1024 {
		t.Fatalf("mem %d %d %v", memTotal, avail, ok)
	}
	if got := formatMemUse(memTotal-avail, memTotal); got != "256.0 MiB of 512.0 MiB (50.0%)" {
		t.Fatalf("mem use %s", got)
	}
	if formatConns(1) != "1 connection" || formatConns(8) != "8 connections" {
		t.Fatalf("conns %s %s", formatConns(1), formatConns(8))
	}
	n, mhz := parseCPUInfo("processor : 0\ncpu MHz : 3590.000\nprocessor : 1\n")
	if n != 2 || formatCPUTopo(n, mhz) != "2x3.59GHz" {
		t.Fatalf("topo n=%d mhz=%v %s", n, mhz, formatCPUTopo(n, mhz))
	}
}

func TestParseCPR(t *testing.T) {
	rows, cols, ok := parseCPR([]byte("\033[40;120R"))
	if !ok || rows != 40 || cols != 120 {
		t.Fatalf("rows=%d cols=%d ok=%v", rows, cols, ok)
	}
	if _, _, ok := parseCPR([]byte("garbage")); ok {
		t.Fatal("accepted garbage")
	}
}

func TestFormatUptime(t *testing.T) {
	if formatUptime(90) != "uptime 1m30s" || formatUptime(3661) != "uptime 1h01m" || formatUptime(0) != "uptime 0s" {
		t.Fatalf("%s %s %s", formatUptime(90), formatUptime(3661), formatUptime(0))
	}
}

func TestKmsgRecord(t *testing.T) {
	lvl, msg, pri, ok := kmsgRecord("3,339,5140900,-;FAT-fs (sr0): bogus number of reserved sectors\n")
	if !ok || lvl != slog.LevelError || pri != 3 || !strings.Contains(msg, "FAT-fs") {
		t.Fatalf("ok=%v lvl=%v pri=%d msg=%q", ok, lvl, pri, msg)
	}
	if _, _, _, ok := kmsgRecord("6,1,1,-;NET: Registered protocol family 10\n"); ok {
		t.Fatal("kernel info should stay off the console")
	}
}

func TestClassifyForeign(t *testing.T) {
	lvl, msg := classifyForeign("2026-09-22 16:53:23.833 [I] frps tcp listen on 127.0.0.1:7000")
	if lvl != slog.LevelInfo || msg != "frps tcp listen on 127.0.0.1:7000" {
		t.Fatalf("%v %q", lvl, msg)
	}
	lvl, msg = classifyForeign("2026-09-22 16:53:23.833 [W] slow handshake")
	if lvl != slog.LevelWarn || msg != "slow handshake" {
		t.Fatalf("%v %q", lvl, msg)
	}
	lvl, msg = classifyForeign("2026-09-22 16:53:23.833 [E] bind failed")
	if lvl != slog.LevelError || msg != "bind failed" {
		t.Fatalf("%v %q", lvl, msg)
	}
}

func TestForwardHoldsPartialLines(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: replaceTime})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	w := Forward("frp")
	if _, err := io.WriteString(w, "2026-09-22 16:53:23.833 [I] frps tcp listen"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("partial line flushed: %s", buf.String())
	}
	if _, err := io.WriteString(w, " on 127.0.0.1:7000\n"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, `msg="frps tcp listen on 127.0.0.1:7000"`) || !strings.Contains(got, "src=frp") {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, "2026-09-22") {
		t.Fatalf("foreign clock leaked: %s", got)
	}
	i := strings.Index(got, "time=")
	if i < 0 || len(got) < i+17 || got[i+13] != '.' {
		t.Fatalf("time = %q", got)
	}
}

func TestFanoutLinesStayIntact(t *testing.T) {
	var buf bytes.Buffer
	f := &fanout{plain: []io.Writer{&buf}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 50 {
			_, _ = f.Write([]byte("AAAA AAAA AAAA\n"))
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			_, _ = f.Write([]byte("BBBB BBBB BBBB\n"))
		}
	}()
	wg.Wait()
	n := 0
	for line := range strings.Lines(buf.String()) {
		n++
		if line != "AAAA AAAA AAAA\n" && line != "BBBB BBBB BBBB\n" {
			t.Fatalf("torn line %q", line)
		}
	}
	if n != 100 {
		t.Fatalf("lines = %d", n)
	}
}
