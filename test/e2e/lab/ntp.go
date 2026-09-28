//go:build e2e

package lab

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

// ntp is the clock every VM syncs from at boot, so a boot does not depend
// on pool.ntp.org or on internet access. Main starts it.
var ntp *ntpServer

// ntpServer answers SNTP queries with the host's time: stratum 1, no leap
// warning, so the edge's validation accepts it.
type ntpServer struct {
	pcs  []net.PacketConn
	port int
}

// startNTP listens on loopback, where slirp's 10.0.2.2 lands, and on each
// of also, at the same port.
func startNTP(also ...string) (*ntpServer, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &ntpServer{pcs: []net.PacketConn{pc}, port: pc.LocalAddr().(*net.UDPAddr).Port}
	for _, a := range also {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(a, strconv.Itoa(s.port)))
		if err != nil {
			s.Close()
			return nil, err
		}
		s.pcs = append(s.pcs, pc)
	}
	for _, pc := range s.pcs {
		go s.serve(pc)
	}
	return s, nil
}

func (s *ntpServer) serve(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil || n < 48 {
			continue
		}
		recv := time.Now()
		resp := make([]byte, 48)
		resp[0] = 0x24                // LI=0 VN=4 Mode=4 (server)
		resp[1] = 1                   // stratum 1
		copy(resp[12:16], "LAB\x00")  // reference ID
		copy(resp[24:32], buf[40:48]) // originate = client transmit
		putNTPTime(resp[16:24], recv) // reference
		putNTPTime(resp[32:40], recv) // receive
		putNTPTime(resp[40:48], time.Now())
		_, _ = pc.WriteTo(resp, addr)
	}
}

func (s *ntpServer) Close() error {
	for _, pc := range s.pcs {
		pc.Close()
	}
	return nil
}

// ntpEpoch is 1900-01-01, where NTP timestamps start.
var ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

func putNTPTime(b []byte, t time.Time) {
	d := t.Sub(ntpEpoch)
	sec := d / time.Second
	frac := (d % time.Second) << 32 / time.Second
	binary.BigEndian.PutUint32(b[:4], uint32(sec))
	binary.BigEndian.PutUint32(b[4:], uint32(frac))
}

// NTP is the lab's NTP server as vm reaches it: fortress.yml's ntp.
func (vm *VM) NTP() string {
	return net.JoinHostPort(vm.host(), strconv.Itoa(ntp.port))
}
