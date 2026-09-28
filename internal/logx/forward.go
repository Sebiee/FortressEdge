package logx

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Forward returns a writer that turns another logger's lines into slog
// records. src is stored on each record. Bytes are held until a newline
// so a foreign logger cannot split a fortressedge line on the console.
func Forward(src string) *lineForward {
	return &lineForward{src: src}
}

type lineForward struct {
	mu    sync.Mutex
	buf   []byte
	src   string
	quiet func(msg string) bool
}

// Quiet logs at debug the lines whose message quiet reports true for,
// whatever level the other logger gave them: what it rates higher than an
// operator needs to see. Call it before the first Write.
func (w *lineForward) Quiet(quiet func(msg string) bool) *lineForward {
	w.quiet = quiet
	return w
}

func (w *lineForward) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf = append(w.buf, p...)
	var lines []string
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, strings.TrimRight(string(w.buf[:i]), "\r"))
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > 64*1024 {
		lines = append(lines, string(w.buf))
		w.buf = nil
	}
	w.mu.Unlock()
	for _, line := range lines {
		if line == "" {
			continue
		}
		lvl, msg := classifyForeign(line)
		if w.quiet != nil && w.quiet(msg) {
			lvl = slog.LevelDebug
		}
		slog.Log(context.Background(), lvl, msg, "src", w.src)
	}
	return len(p), nil
}

// classifyForeign strips a golib/frp prefix
// ("2006-01-02 15:04:05.000 [I] message") so slog supplies the only clock.
func classifyForeign(line string) (slog.Level, string) {
	const stamp = len("2006-01-02 15:04:05.000")
	if len(line) < stamp+5 || line[4] != '-' || line[10] != ' ' || line[19] != '.' ||
		line[stamp] != ' ' || line[stamp+1] != '[' || line[stamp+3] != ']' || line[stamp+4] != ' ' {
		return slog.LevelInfo, line
	}
	lvl := slog.LevelInfo
	switch line[stamp+2] {
	case 'W':
		lvl = slog.LevelWarn
	case 'E':
		lvl = slog.LevelError
	case 'D', 'T':
		lvl = slog.LevelDebug
	}
	return lvl, line[stamp+5:]
}
