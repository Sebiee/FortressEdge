package httpsvc

import "testing"

func TestReadProcPairs(t *testing.T) {
	text := "TcpExt: SyncookiesSent ListenOverflows ListenDrops\n" +
		"TcpExt: 1 2 3\n" +
		"Tcp: RtoAlgorithm MaxConn OutRsts\n" +
		"Tcp: 1 -1 7\n"
	got := map[string]uint64{}
	readProcPairs(text, func(k string, v uint64) { got[k] = v })
	if got["TcpExt:ListenOverflows"] != 2 || got["TcpExt:ListenDrops"] != 3 || got["Tcp:OutRsts"] != 7 {
		t.Fatalf("got %v", got)
	}
	if _, ok := got["Tcp:MaxConn"]; ok {
		t.Fatal("a negative value parsed")
	}
}

func TestKernelTCPHere(t *testing.T) {
	if _, ok := kernelTCP()["passive_opens"]; !ok {
		t.Skip("no /proc/net/snmp")
	}
}
