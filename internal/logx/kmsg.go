package logx

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
)

func emitKmsg(b []byte) {
	for line := range strings.Lines(string(b)) {
		lvl, msg, pri, ok := kmsgRecord(line)
		if !ok {
			continue
		}
		slog.Log(context.Background(), lvl, msg, "src", "kernel", "pri", pri)
	}
}

// kmsgRecord parses one /dev/kmsg record. Info, notice, and warning are
// dropped: those used to stay off the console, and replaying them would
// paint the boot with driver chatter. KERN_ERR and worse are kept.
func kmsgRecord(line string) (slog.Level, string, int, bool) {
	line = strings.TrimRight(line, "\r\n")
	semi := strings.IndexByte(line, ';')
	if semi < 0 {
		return 0, "", 0, false
	}
	msg := line[semi+1:]
	if msg == "" {
		return 0, "", 0, false
	}
	priStr, _, ok := strings.Cut(line[:semi], ",")
	if !ok {
		return 0, "", 0, false
	}
	pri, err := strconv.Atoi(priStr)
	if err != nil {
		return 0, "", 0, false
	}
	level := pri & 7
	if level > 3 {
		return 0, "", 0, false
	}
	return slog.LevelError, msg, level, true
}
