package httpsvc

import (
	"os"
	"strconv"
	"strings"
)

// kernelTCP are the kernel's TCP counters that say whether it, rather
// than the edge, refused or reset connections: accept queue overflows,
// SYN cookies, resets sent. They are totals since boot.
func kernelTCP() map[string]uint64 {
	want := map[string]string{
		"TcpExt:ListenOverflows": "listen_overflows", // accept queue full: a handshake's last ACK was dropped
		"TcpExt:ListenDrops":     "listen_drops",
		"TcpExt:SyncookiesSent":  "syncookies_sent", // SYN queue full
		"TcpExt:TCPBacklogDrop":  "backlog_drops",
		"Tcp:PassiveOpens":       "passive_opens",
		"Tcp:AttemptFails":       "attempt_fails",
		"Tcp:EstabResets":        "estab_resets",
		"Tcp:OutRsts":            "out_rsts",
	}
	out := make(map[string]uint64, len(want))
	for _, path := range []string{"/proc/net/netstat", "/proc/net/snmp"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		readProcPairs(string(b), func(key string, v uint64) {
			if name, ok := want[key]; ok {
				out[name] = v
			}
		})
	}
	return out
}

// readProcPairs reads /proc/net/{netstat,snmp}: a line of field names,
// then a line of values, both starting with the same "Group:".
func readProcPairs(text string, each func(key string, v uint64)) {
	lines := strings.Split(text, "\n")
	for i := 0; i+1 < len(lines); i++ {
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(names) < 2 || len(names) != len(values) || names[0] != values[0] {
			continue
		}
		for j := 1; j < len(names); j++ {
			if v, err := strconv.ParseUint(values[j], 10, 64); err == nil {
				each(names[0]+names[j], v)
			}
		}
		i++
	}
}
