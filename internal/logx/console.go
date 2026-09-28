package logx

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// ttySink is one real console. The top lines are the status panel; the
// rest is a scrolling region so log lines cannot push the panel away.
type ttySink struct {
	f         *os.File
	rows      int
	cols      int
	panel     int
	row       int
	col       int
	painted   bool
	drawnRows int
	drawnCols int
	prev      []dashLine // last panel, so a tick sends only what changed
}

func (t *ttySink) writeLog(p []byte) {
	if !t.painted {
		t.paint(fan.machine())
	}
	// A panel repaint leaves the pen colored on some terminals. One write:
	// each one is a trip through the tty layer and, on serial, the UART.
	_, _ = t.f.Write(append([]byte("\033[0m"), p...))
	t.advance(p)
}

func (t *ttySink) advance(p []byte) {
	for _, c := range p {
		switch c {
		case '\n':
			t.row++
			t.col = 0
		case '\r':
			t.col = 0
			continue
		default:
			t.col++
			if t.cols > 0 && t.col >= t.cols {
				t.row++
				t.col = 0
			}
		}
		if t.row > t.rows {
			t.row = t.rows
		}
	}
}

// paint redraws the panel. The caller holds fan.mu. A later tick sends
// only the characters that changed. Under a hypervisor every character is
// a trap (VGA text memory, the UART), so console output is most of what
// an idle edge costs its host.
func (t *ttySink) paint(host machine) {
	t.measure()
	lines := panelView(t.rows, t.cols, fan.st, host)
	full := !t.painted || t.rows != t.drawnRows || t.cols != t.drawnCols || len(lines) != len(t.prev)
	if full {
		p := renderStatus(t.rows, t.cols, t.row, t.col, t.panel, !t.painted, fan.st, host)
		t.panel = p.panel
		t.row = p.row
		t.col = p.col
		t.painted = true
		_, _ = t.f.Write(p.bytes)
	} else if b := deltaBytes(t.prev, lines); len(b) > 0 {
		_, _ = t.f.Write(b)
	}
	t.prev = lines
	t.drawnRows = t.rows
	t.drawnCols = t.cols
}

type painted struct {
	bytes      []byte
	panel, row int
	col        int
}

type tone int

const (
	toneNone tone = iota
	toneGood
	toneBad
)

type cell struct {
	key, val string
	tone     tone
}

type span struct {
	s, color string
}

type dashLine struct {
	spans []span
}

// renderStatus builds the escape sequence for one panel draw.
// first clears the screen. Otherwise the cursor is saved and put back,
// unless the panel grew over it — then it is parked just under the panel.
func panelView(rows, cols int, st Status, host machine) []dashLine {
	if rows < 8 {
		rows = 24
	}
	if cols < 40 {
		cols = 80
	}
	lines := dashboard(cols, st, host)
	maxPanel := rows - 3
	if maxPanel < 1 {
		maxPanel = 1
	}
	if len(lines) > maxPanel {
		return lines[:maxPanel]
	}
	return lines
}

func renderStatus(rows, cols, curRow, curCol, prev int, first bool, st Status, host machine) painted {
	if rows < 8 {
		rows = 24
	}
	if cols < 40 {
		cols = 80
	}
	lines := panelView(rows, cols, st, host)
	var b bytes.Buffer
	if first {
		b.WriteString("\033[2J\033[H")
	} else {
		b.WriteString("\0337")
	}
	for i, line := range lines {
		writeLine(&b, i+1, line)
	}
	for i := len(lines); i < prev; i++ {
		fmt.Fprintf(&b, "\033[%d;1H\033[2K", i+1)
	}
	panel := len(lines)
	fmt.Fprintf(&b, "\033[%d;%dr", panel+1, rows)
	row, col := curRow, curCol
	if first || row < panel+1 {
		row = panel + 1
		col = 0
		fmt.Fprintf(&b, "\033[%d;1H", row)
	} else {
		b.WriteString("\0338")
	}
	return painted{bytes: b.Bytes(), panel: panel, row: row, col: col}
}

func dashboard(cols int, st Status, host machine) []dashLine {
	if cols < 20 {
		cols = 20
	}
	// A full-width line wraps and would shove the next panel row down.
	width := cols - 1
	lines := headerDash(host, width)
	lines = append(lines, textLine(""))
	nCols := 1
	if cols >= 80 {
		nCols = 2
	}
	if cols >= 120 {
		nCols = 3
	}
	groups := splitCols(statusCells(st), nCols)
	rowsN := 0
	for _, g := range groups {
		if len(g) > rowsN {
			rowsN = len(g)
		}
	}
	colW := width / nCols
	for r := 0; r < rowsN; r++ {
		var spans []span
		for c := range nCols {
			f := cell{}
			if r < len(groups[c]) {
				f = groups[c][r]
			}
			spans = append(spans, formatCell(colW, f)...)
		}
		lines = append(lines, dashLine{spans: spans})
	}
	if len(st.Notes) > 0 {
		lines = append(lines, textLine(""))
		for _, note := range st.Notes {
			for _, w := range wrap(note, width) {
				lines = append(lines, textLine(w))
			}
		}
	}
	lines = append(lines, textLine(strings.Repeat("-", width)))
	return lines
}

func headerDash(host machine, width int) []dashLine {
	full := headerLine(host)
	if len(full) <= width {
		return []dashLine{textLine(full)}
	}
	return []dashLine{textLine(fit(identityLine(host), width)), textLine(fit(usageLine(host), width))}
}

func lineText(line dashLine) string {
	if len(line.spans) == 1 {
		return line.spans[0].s
	}
	var b strings.Builder
	for _, sp := range line.spans {
		b.WriteString(sp.s)
	}
	return b.String()
}

// deltaBytes rewrites what changed and leaves the cursor where the log had
// it. Unchanged lines are not sent. A plain line (the header, whose uptime
// and CPU move every tick) sends only the changed run of characters.
func deltaBytes(prev, lines []dashLine) []byte {
	var b bytes.Buffer
	for i, line := range lines {
		was := dashLine{}
		if i < len(prev) {
			was = prev[i]
		}
		old, cur := lineText(was), lineText(line)
		if i < len(prev) && old == cur && sameColors(was, line) {
			continue
		}
		if b.Len() == 0 {
			b.WriteString("\0337")
		}
		if i < len(prev) && plain(was) && plain(line) {
			writeChange(&b, i+1, old, cur)
		} else {
			writeLine(&b, i+1, line)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	b.WriteString("\0338")
	return b.Bytes()
}

// writeChange sends the run between the common prefix and, for equal
// lengths, the common suffix. A shorter line clears its old tail.
func writeChange(b *bytes.Buffer, row int, old, cur string) {
	p := 0
	for p < len(old) && p < len(cur) && old[p] == cur[p] {
		p++
	}
	end := len(cur)
	if len(old) == len(cur) {
		for end > p && old[end-1] == cur[end-1] {
			end--
		}
	}
	fmt.Fprintf(b, "\033[%d;%dH", row, p+1)
	b.WriteString(cur[p:end])
	if len(cur) < len(old) {
		b.WriteString("\033[K")
	}
}

// plain is one uncolored ASCII span, so byte offsets are columns.
func plain(line dashLine) bool {
	if len(line.spans) != 1 || line.spans[0].color != "" {
		return false
	}
	for _, c := range []byte(line.spans[0].s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func sameColors(a, b dashLine) bool {
	if len(a.spans) != len(b.spans) {
		return false
	}
	for i := range a.spans {
		if a.spans[i].color != b.spans[i].color {
			return false
		}
	}
	return true
}

func writeLine(b *bytes.Buffer, row int, line dashLine) {
	fmt.Fprintf(b, "\033[%d;1H\033[2K", row)
	for _, sp := range line.spans {
		if sp.color != "" {
			b.WriteString(sp.color)
		}
		b.WriteString(sp.s)
		if sp.color != "" {
			b.WriteString("\033[0m")
		}
	}
}

func textLine(s string) dashLine {
	return dashLine{spans: []span{{s: s}}}
}

func fit(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width < 1 {
		return ""
	}
	return s[:width]
}

func statusCells(st Status) []cell {
	ready, readyTone := "False", toneBad
	if st.Ready {
		ready, readyTone = "True", toneGood
	}
	conn, connTone := "DOWN", toneBad
	if st.Connected {
		conn, connTone = "OK", toneGood
	}
	var out []cell
	add := func(key, val string) {
		if val == "" {
			return
		}
		out = append(out, cell{key: key, val: val})
	}
	add("STAGE", st.Stage)
	out = append(out, cell{key: "READY", val: ready, tone: readyTone})
	add("ACME", st.ACME)
	add("QUIC", st.QUIC)
	add("DISK", st.Disk)
	add("BLOCKED", st.Blocked)
	add("TUNNEL", st.Tunnel)
	add("FRPS", st.Frps)
	add("LISTEN", st.Listen)
	add("NTP", st.NTP)
	add("IFACE", st.Iface)
	add("ADDR", st.Addr)
	add("GATEWAY", st.Gateway)
	out = append(out, cell{key: "CONNECTIVITY", val: conn, tone: connTone})
	add("DNS", st.DNS)
	return out
}

func splitCols(all []cell, n int) [][]cell {
	if n < 1 {
		n = 1
	}
	rows := (len(all) + n - 1) / n
	out := make([][]cell, n)
	for i, f := range all {
		c := i / rows
		if c >= n {
			c = n - 1
		}
		out[c] = append(out[c], f)
	}
	return out
}

const cellKeyW = 14

func formatCell(colW int, f cell) []span {
	if colW < 1 {
		colW = 1
	}
	if f.key == "" {
		return []span{{s: strings.Repeat(" ", colW)}}
	}
	key := f.key
	if len(key) > cellKeyW {
		key = key[:cellKeyW]
	}
	key = fmt.Sprintf("%-*s ", cellKeyW, key)
	room := colW - len(key)
	if room < 1 {
		return []span{{s: fit(key, colW)}}
	}
	val := f.val
	if len(val) > room {
		val = val[:room]
	}
	pad := room - len(val)
	spans := []span{{s: key}}
	valSpan := span{s: val}
	switch f.tone {
	case toneGood:
		valSpan.color = "\033[32m"
	case toneBad:
		valSpan.color = "\033[31m"
	}
	spans = append(spans, valSpan)
	if pad > 0 {
		spans = append(spans, span{s: strings.Repeat(" ", pad)})
	}
	return spans
}

func panelPlain(st Status, host machine) string {
	lines := dashboard(80, st, host)
	var b strings.Builder
	b.WriteString("==================================================\n")
	for _, line := range lines {
		for _, sp := range line.spans {
			b.WriteString(sp.s)
		}
		b.WriteByte('\n')
	}
	b.WriteString("==================================================\n")
	return b.String()
}

func parseCPR(b []byte) (rows, cols int, ok bool) {
	i := indexESC(b)
	if i < 0 {
		return 0, 0, false
	}
	b = b[i+2:]
	rows, n, ok := atoiPrefix(b)
	if !ok || n >= len(b) || b[n] != ';' {
		return 0, 0, false
	}
	cols, m, ok := atoiPrefix(b[n+1:])
	if !ok || n+1+m >= len(b) || b[n+1+m] != 'R' {
		return 0, 0, false
	}
	if rows < 8 || cols < 40 || rows > 500 || cols > 500 {
		return 0, 0, false
	}
	return rows, cols, true
}

func indexESC(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == 0x1b && b[i+1] == '[' {
			return i
		}
	}
	return -1
}

func atoiPrefix(b []byte) (int, int, bool) {
	if len(b) == 0 || b[0] < '0' || b[0] > '9' {
		return 0, 0, false
	}
	n := 0
	i := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		n = n*10 + int(b[i]-'0')
		i++
		if n > 10000 {
			return 0, 0, false
		}
	}
	return n, i, i > 0
}

func wrap(line string, cols int) []string {
	if cols < 1 {
		cols = 1
	}
	if line == "" || len(line) <= cols {
		return []string{line}
	}
	out := []string{}
	for len(line) > cols {
		out = append(out, line[:cols])
		line = line[cols:]
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
