package clock

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

const ntpEpochDelta = 2208988800

func TestQuery(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	want := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	go func() {
		buf := make([]byte, 48)
		// The first request is lost, as UDP may be.
		if _, _, err := pc.ReadFrom(buf); err != nil {
			return
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 48 {
			return
		}
		resp := make([]byte, 48)
		resp[0] = 0x24                // LI=0 VN=4 Mode=4 (server)
		resp[1] = 1                   // stratum 1, or Validate rejects the answer
		copy(resp[24:32], buf[40:48]) // originate = client transmit
		putNTPTime(resp[16:24], want) // reference
		putNTPTime(resp[32:40], want) // receive
		putNTPTime(resp[40:48], want) // transmit
		_, _ = pc.WriteTo(resp, addr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := query(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if diff := got.Sub(want); diff < -time.Second || diff > time.Second {
		t.Fatalf("got %s, want ~%s", got, want)
	}
}

func putNTPTime(b []byte, t time.Time) {
	binary.BigEndian.PutUint32(b[:4], uint32(t.Unix()+ntpEpochDelta))
	// fraction left zero; whole-second test times don't need it
}
