//go:build e2e

// Package lab boots FortressEdge VMs and talks to them: QEMU, an NTP
// server for the guests, Pebble for ACME, and frpc for dark nodes. The
// scenarios live next door, one file each.
package lab

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	flog "github.com/fatedier/frp/pkg/util/log"
	glog "github.com/fatedier/golib/log"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/Sebiee/fortressedge/internal/ca"
	"github.com/Sebiee/fortressedge/internal/config"
	"github.com/Sebiee/fortressedge/internal/seediso"
)

const (
	Tunnel = "tunnel.example.com"
	OpsURL = "https://" + Tunnel + config.OpsPathPrefix
	Tick   = 250 * time.Millisecond
	// Attempt bounds one request or frp login. slirp accepts a forwarded
	// connection before the guest does, so a probe the guest never answers
	// would otherwise sit in slirp's SYN retries.
	Attempt = 10 * time.Second
)

var (
	iso         = flag.String("iso", "", "fortressedge.iso to boot")
	fortressctl = flag.String("fortressctl", "", "fortressctl binary; empty builds one")
	frpLog      = flag.String("frplog", "", "file for the in-process frpc logs; empty discards them")
	tapDev      = flag.String("tap", "", "tap device for VMs that call UseTap, made by os/netns.sh; "+
		"empty keeps every VM on QEMU's user-mode network")
	accel = "tcg"
	// tapFree holds the one VM a tap can carry at a time.
	tapFree = make(chan struct{}, 1)
)

// HasTap reports whether a -tap device was given: VMs that UseTap are then
// peers of the host's TCP, not behind QEMU's user-mode network, which
// answers for them while they are down.
func HasTap() bool { return *tapDev != "" }

// TapHost is the host's address on the -tap device, and TapGuest a VM's.
const (
	TapHost  = "10.77.0.1"
	TapGuest = "10.77.0.2"
)

// TapDevice is the -tap device's name.
func TapDevice() string { return *tapDev }

// Tap reports whether -tap names a device.
func Tap() bool { return *tapDev != "" }

// Main parses flags, picks kvm when the device is writable, and builds
// fortressctl when -fortressctl was not passed.
func Main(m *testing.M) int {
	flag.Parse()
	if *iso == "" {
		fmt.Fprintln(os.Stderr, "e2e: -iso is required")
		return 2
	}
	if unix.Access("/dev/kvm", unix.W_OK) == nil {
		accel = "kvm"
	}
	fmt.Fprintf(os.Stderr, "e2e: QEMU_ACCEL=%s\n", accel)
	// frpc logs to stdout by default, which would bury the test results.
	frpOut := io.Discard
	if *frpLog != "" {
		f, err := os.Create(*frpLog)
		if err != nil {
			fmt.Fprintln(os.Stderr, "e2e: frplog:", err)
			return 1
		}
		defer f.Close()
		frpOut = f
	}
	flog.Logger = glog.New(glog.WithOutput(frpOut), glog.WithLevel(glog.InfoLevel))
	var err error
	var ntpAlso []string
	if Tap() {
		ntpAlso = append(ntpAlso, TapHost)
	}
	if ntp, err = startNTP(ntpAlso...); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: ntp:", err)
		return 1
	}
	defer ntp.Close()
	if *fortressctl != "" {
		return m.Run()
	}
	dir, err := os.MkdirTemp("", "fortressctl-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	*fortressctl = filepath.Join(dir, "fortressctl")
	// fortressctl builds in the repository's own module, not this one.
	build := exec.Command("go", "-C", "../..", "build", "-o", *fortressctl, "./cmd/fortressctl")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: build fortressctl:", err)
		return 1
	}
	return m.Run()
}

// ReleaseISO is the ISO under test, as a release ships it.
func ReleaseISO() string { return *iso }

// Accel is how QEMU runs the guests: kvm, or tcg when it emulates the CPU.
func Accel() string { return accel }

// Until is how long a poll may wait: most of what -timeout leaves. The rest
// lets a failed poll report its last attempt and cleanup kill QEMU before
// the test binary panics at the deadline itself.
func Until(t *testing.T) time.Duration {
	t.Helper()
	d, ok := t.Deadline()
	if !ok {
		return math.MaxInt64
	}
	return time.Until(d) * 9 / 10
}

// VM is one QEMU guest started through os/qemu.sh. HTTP, HTTPS and Ctl are
// the ports at Addr for the guest's 80, 443 (TCP and UDP) and 7000: host
// ports forwarded to it, or its own ports on a tap device.
type VM struct {
	HTTP, HTTPS, Ctl int
	// Addr is where the host reaches those ports: 127.0.0.1, or TapGuest.
	Addr string
	// ISO replaces the suite's -iso for this VM, such as a baked copy.
	ISO string
	// CPUs and MemMiB size the guest; zero is os/qemu.sh's 1 vCPU and 512 MiB.
	CPUs, MemMiB int

	disk, cidata, guest string
	sock, serial        string
	tap                 bool
	cmd                 *exec.Cmd
	done                chan struct{}
	err                 error
}

// UseTap puts vm on the -tap device at TapGuest, before Restart starts
// it. Its drive must then carry vm.NetworkConfig, and its fortress.yml
// vm.NTP. VMs take turns on the tap: this waits for the one before to be
// gone.
func (vm *VM) UseTap(t *testing.T) {
	t.Helper()
	require.True(t, Tap(), "no -tap device: run the test in os/netns.sh")
	select {
	case tapFree <- struct{}{}:
	case <-t.Context().Done():
		t.Fatal("the tap never came free")
	}
	vm.tap, vm.Addr = true, TapGuest
	vm.HTTP, vm.HTTPS, vm.Ctl = 80, 443, 7000
	t.Cleanup(func() {
		if vm.cmd != nil {
			_ = syscall.Kill(-vm.cmd.Process.Pid, syscall.SIGKILL)
			<-vm.done
		}
		<-tapFree
	})
}

// Visitor is the address the edge sees a connection from the host come
// from: slirp's 10.0.2.2, or TapHost.
func (vm *VM) Visitor() string {
	if vm.tap {
		return TapHost
	}
	return "10.0.2.2"
}

// host is the host as vm's guest reaches it: slirp's 10.0.2.2, or TapHost.
func (vm *VM) host() string { return vm.Visitor() }

// NetworkConfig is the network-config Proxmox writes for vm's address: on
// slirp 10.0.2.15, on a tap TapGuest, with the host as gateway.
func (vm *VM) NetworkConfig() []byte {
	addr, gw := "10.0.2.15", hostAlias
	if vm.tap {
		addr, gw = TapGuest, TapHost
	}
	return fmt.Appendf(nil, `version: 1
config:
    - type: physical
      name: eth0
      mac_address: '52:54:00:12:34:56'
      subnets:
      - type: static
        address: '%s'
        netmask: '255.255.255.0'
        gateway: '%s'
    - type: nameserver
      address:
      - '1.1.1.1'
      search:
      - 'example.com'
`, addr, gw)
}

// UserData is what Proxmox writes for a VM named fqdn's first label in
// fqdn's DNS domain: fqdn is all the edge reads.
func UserData(fqdn string) []byte {
	host, _, _ := strings.Cut(fqdn, ".")
	return fmt.Appendf(nil, `#cloud-config
hostname: %s
manage_etc_hosts: true
fqdn: %s
user: root
disable_root: False
chpasswd:
  expire: False
package_upgrade: true
`, host, fqdn)
}

// Drive writes a NoCloud drive to path as Proxmox makes one: meta-data,
// user-data, and network-config.
func Drive(t *testing.T, path string, userData, networkConfig []byte) {
	t.Helper()
	require.NoError(t, seediso.Write(path, map[string][]byte{
		"meta-data":      fmt.Appendf(nil, "instance-id: %x\n", sha256.Sum256(slices.Concat(userData, networkConfig))),
		"user-data":      userData,
		"network-config": networkConfig,
	}))
}

// Boot starts QEMU on disk, with cidata attached when set. guest is the
// address the port forwards target; empty is QEMU's DHCP address.
func Boot(t *testing.T, disk, cidata, guest string) *VM {
	t.Helper()
	vm := New(t, disk, cidata, guest)
	vm.Restart(t)
	return vm
}

// New picks the host ports without starting QEMU, for a test that needs
// them in the config it boots with. Restart starts it.
func New(t *testing.T, disk, cidata, guest string) *VM {
	t.Helper()
	vm := &VM{
		HTTP: freePort(t), HTTPS: freePort(t), Ctl: freePort(t), Addr: "127.0.0.1",
		disk: disk, cidata: cidata, guest: guest,
		sock:   filepath.Join(t.TempDir(), "qmp.sock"),
		serial: filepath.Join(t.ArtifactDir(), "serial.log"),
	}
	t.Logf("vm %s http=:%d https=:%d ctl=:%d", accel, vm.HTTP, vm.HTTPS, vm.Ctl)
	t.Cleanup(func() {
		if vm.cmd == nil {
			return
		}
		_ = syscall.Kill(-vm.cmd.Process.Pid, syscall.SIGKILL)
		<-vm.done
		if t.Failed() {
			b, _ := os.ReadFile(vm.serial)
			lines := strings.Split(string(b), "\n")
			t.Logf("serial.log, last lines:\n%s", strings.Join(lines[max(0, len(lines)-40):], "\n"))
		}
	})
	return vm
}

// Restart starts QEMU again once it has exited. An ejected cidata stays out.
func (vm *VM) Restart(t *testing.T) {
	t.Helper()
	log, err := os.OpenFile(vm.serial, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	cmd := exec.Command("../../os/qemu.sh")
	boot := *iso
	if vm.ISO != "" {
		boot = vm.ISO
	}
	cmd.Env = append(os.Environ(),
		"ISO="+boot, "DISK="+vm.disk, "CIDATA="+vm.cidata, "GUEST_ADDR="+vm.guest,
		"QEMU_ACCEL="+accel, "QMP="+vm.sock,
		"HTTP_FWD="+strconv.Itoa(vm.HTTP), "HTTPS_FWD="+strconv.Itoa(vm.HTTPS), "CTL_FWD="+strconv.Itoa(vm.Ctl))
	if vm.CPUs > 0 {
		cmd.Env = append(cmd.Env, "QEMU_SMP="+strconv.Itoa(vm.CPUs))
	}
	if vm.MemMiB > 0 {
		cmd.Env = append(cmd.Env, "QEMU_MEM="+strconv.Itoa(vm.MemMiB))
	}
	if vm.tap {
		cmd.Env = append(cmd.Env, "TAP="+*tapDev)
	}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		log.Close()
		require.NoError(t, err)
	}
	vm.cmd, vm.done = cmd, make(chan struct{})
	go func() {
		vm.err = cmd.Wait()
		log.Close()
		close(vm.done)
	}()
}

// Eject detaches the cidata drive, as Proxmox "detach cloud-init drive" does.
func (vm *VM) Eject(t *testing.T) {
	t.Helper()
	vm.monitor(t, `{"execute":"eject","arguments":{"device":"cidata","force":true}}`)
	vm.cidata = ""
}

// PowerDown presses the ACPI power button and waits for QEMU to exit cleanly.
func (vm *VM) PowerDown(t *testing.T) {
	t.Helper()
	vm.monitor(t, `{"execute":"system_powerdown"}`)
	require.Eventually(t, vm.exited, Until(t), Tick, "qemu still running after ACPI powerdown")
	require.NoError(t, vm.err, "qemu exit status")
}

// Reset resets the machine, as a hard reset does: no ACPI, no shutdown,
// nothing closed. QEMU keeps running and the edge boots again.
func (vm *VM) Reset(t *testing.T) {
	t.Helper()
	vm.monitor(t, `{"execute":"system_reset"}`)
}

// SetLink takes the machine's network link down or up, as a cable pulled
// or plugged: its NIC loses or regains carrier.
//
// Right after Restart, QEMU's monitor may not listen yet: it is tried
// until it does.
func (vm *VM) SetLink(t *testing.T, up bool) {
	t.Helper()
	cmd := []byte(fmt.Sprintf(`{"execute":"set_link","arguments":{"name":"n0","up":%t}}`, up))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		mon, err := qmp.NewSocketMonitor("unix", vm.sock, Attempt)
		require.NoError(c, err)
		require.NoError(c, mon.Connect())
		defer mon.Disconnect()
		_, err = mon.Run(cmd)
		require.NoError(c, err)
	}, Until(t), 10*time.Millisecond)
}

func (vm *VM) exited() bool {
	select {
	case <-vm.done:
		return true
	default:
		return false
	}
}

func (vm *VM) monitor(t *testing.T, cmd string) {
	t.Helper()
	mon, err := qmp.NewSocketMonitor("unix", vm.sock, Attempt)
	require.NoError(t, err)
	require.NoError(t, mon.Connect())
	defer mon.Disconnect()
	_, err = mon.Run([]byte(cmd))
	require.NoError(t, err)
}

// Console waits until vm's console shows want, and returns all it shows.
// QEMU exiting first fails at once.
// ConsoleCount is how many times vm's console has shown s, across its
// boots: the serial log keeps every boot's lines.
func (vm *VM) ConsoleCount(t *testing.T, s string) int {
	t.Helper()
	b, err := os.ReadFile(vm.serial)
	require.NoError(t, err)
	return strings.Count(string(b), s)
}

func (vm *VM) Console(t *testing.T, want string) string {
	t.Helper()
	for {
		b, err := os.ReadFile(vm.serial)
		require.NoError(t, err)
		if strings.Contains(string(b), want) {
			return string(b)
		}
		select {
		case <-vm.done:
			require.FailNow(t, "qemu exited before the console showed "+want, "%s", b)
		case <-t.Context().Done():
			require.FailNow(t, "the console never showed "+want, "%s", b)
		case <-time.After(Tick):
		}
	}
}

// Exited reports whether QEMU has exited: the guest powered off.
func (vm *VM) Exited() bool { return vm.exited() }

// Ports for QEMU's forwards come from below the kernel's ephemeral range
// (32768-60999), where no ":0" listener of this process (Pebble, origins,
// httptest) can take one between the check and QEMU binding it. A counter
// keeps parallel VMs apart. Each port is free on TCP and UDP, because the
// HTTPS forward carries QUIC too.
var (
	portMu   sync.Mutex
	nextPort = 20000 + os.Getpid()%10000
)

func freePort(t *testing.T) int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()
	for range 1000 {
		p := nextPort
		nextPort++
		if nextPort > 32767 {
			nextPort = 20000
		}
		addr := net.JoinHostPort("", strconv.Itoa(p))
		l, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		pc, err := net.ListenPacket("udp", addr)
		l.Close()
		if err != nil {
			continue
		}
		pc.Close()
		return p
	}
	require.FailNow(t, "no free port between 20000 and 32767")
	return 0
}

// Client sends every request to the VM's forward for the URL's port, so
// https://tunnel.example.com/ reaches the guest's 443 with that SNI.
// caFile verifies the server when set; crt and key are the client cert.
// Redirects are returned, not followed.
func (vm *VM) Client(t *testing.T, caFile, crt, key string) *http.Client {
	t.Helper()
	cfg := &tls.Config{}
	if caFile != "" {
		pool, err := ca.LoadPool(caFile)
		require.NoError(t, err)
		cfg.RootCAs = pool
	}
	if crt != "" {
		cert, err := tls.LoadX509KeyPair(crt, key)
		require.NoError(t, err)
		cfg.Certificates = []tls.Certificate{cert}
	}
	fwd := map[string]int{"80": vm.HTTP, "443": vm.HTTPS}
	return &http.Client{
		Timeout:       Attempt,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: cfg,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(vm.Addr, strconv.Itoa(fwd[port])))
			},
		},
	}
}

// Get performs req and returns the status-bearing response plus its body.
func Get(c *http.Client, url string) (*http.Response, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	return Do(c, req)
}

// Do sends req and returns the response plus its body. A connection
// reset, or closed, before any response is sent again, twice at most, when
// req can be: QEMU's user-mode network now and then drops a forwarded
// connection when the host is busy. An answer, whatever its status, is
// never retried.
func Do(c *http.Client, req *http.Request) (*http.Response, string, error) {
	for tries := 1; ; tries++ {
		resp, err := c.Do(req)
		if err != nil {
			if tries < 3 && dropped(err) {
				if again, ok := rewind(req); ok {
					req = again
					continue
				}
			}
			return nil, "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp, string(b), err
	}
}

// dropped reports whether err is a connection that ended before an answer.
func dropped(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// rewind returns req ready to send again, when its body can be read again.
func rewind(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	again := req.Clone(req.Context())
	again.Body = body
	return again, true
}

// Redirects checks that plain HTTP for the tunnel name answers 308 to the
// same URL on HTTPS. Plain HTTP answers only the names HTTPS serves, and
// the tunnel is the one that needs no dark node.
func Redirects(t require.TestingT, c *http.Client) {
	resp, _, err := Get(c, "http://"+Tunnel+"/x")
	require.NoError(t, err)
	assert.Equal(t, http.StatusPermanentRedirect, resp.StatusCode)
	assert.Equal(t, "https://"+Tunnel+"/x", resp.Header.Get("Location"))
}

// BootID is /status's boot_id, read with c's ops certificate.
func BootID(t require.TestingT, c *http.Client) string {
	resp, body, err := Get(c, OpsURL+"status")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var s struct {
		BootID string `json:"boot_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &s))
	return s.BootID
}

// Tunnel publishes site over proto (see Publish) to a fresh origin and
// waits until a fetch of that site returns the origin's random body.
func (vm *VM) Tunnel(t *testing.T, fetch *http.Client, proto, site, caFile, crt, key string) (stop func()) {
	t.Helper()
	body := rand.Text()
	stop = vm.Publish(t, proto, caFile, crt, key, Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body)
	})), site)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, got, err := Get(fetch, "https://"+site+"/")
		require.NoError(c, err)
		assert.Equal(c, body, got)
	}, Until(t), Tick)
	return stop
}

// DialTLS opens TLS to the guest's 443 with sni, trusting caFile. It offers
// only http/1.1, as a WebSocket client does.
func (vm *VM) DialTLS(t *testing.T, sni, caFile string) *tls.Conn {
	t.Helper()
	pool, err := ca.LoadPool(caFile)
	require.NoError(t, err)
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: Attempt},
		Config:    &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: []string{"http/1.1"}},
	}
	c, err := d.DialContext(t.Context(), "tcp", net.JoinHostPort(vm.Addr, strconv.Itoa(vm.HTTPS)))
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c.(*tls.Conn)
}

// Leaf is the certificate url's name is served with, read from a new
// connection: a reused one would show an old handshake.
func Leaf(t require.TestingT, c *http.Client, url string) *x509.Certificate {
	tr := c.Transport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	resp, _, err := Get(&http.Client{Transport: tr, Timeout: c.Timeout, CheckRedirect: c.CheckRedirect}, url)
	require.NoError(t, err)
	return resp.TLS.PeerCertificates[0]
}

// Serial is Leaf's serial number.
func Serial(t require.TestingT, c *http.Client, url string) string {
	return Leaf(t, c, url).SerialNumber.String()
}

// QUICSerial is the serial of the certificate the guest's UDP 443 presents
// for the tunnel name, as frpc over QUIC sees it. crt and key are a dark
// node's client certificate.
func (vm *VM) QUICSerial(t require.TestingT, caFile, crt, key string) string {
	pool, err := ca.LoadPool(caFile)
	require.NoError(t, err)
	cert, err := tls.LoadX509KeyPair(crt, key)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), Attempt)
	defer cancel()
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(vm.Addr, strconv.Itoa(vm.HTTPS)), &tls.Config{
		ServerName: Tunnel, RootCAs: pool, Certificates: []tls.Certificate{cert}, NextProtos: []string{"frp"},
	}, nil)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	return conn.ConnectionState().TLS.PeerCertificates[0].SerialNumber.String()
}

// Origin serves h on the host and returns its port: a dark node's site.
func Origin(t *testing.T, h http.Handler) int {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.Listener.Addr().(*net.TCPAddr).Port
}

// Publish runs frpc in-process, logged in over proto with the node cert
// crt/key, with one HTTP proxy from domains to 127.0.0.1:port. It returns
// once frpc is started, not once the route is up. stop closes frpc and
// waits for it; cleanup calls it too.
func (vm *VM) Publish(t *testing.T, proto, caFile, crt, key string, port int, domains ...string) (stop func()) {
	t.Helper()
	return vm.PublishAs(t, Member{}, proto, caFile, crt, key, port, domains...)
}

// Member tells apart frpc that publish the same names with one node
// certificate, as fortresskube's replicas do.
type Member struct {
	User    string // frp's user: each replica's own
	LocalIP string // the address frpc dials the edge from; "" for any
}

// PublishAs is Publish as member m.
func (vm *VM) PublishAs(t *testing.T, m Member, proto, caFile, crt, key string, port int, domains ...string) (stop func()) {
	t.Helper()
	svc := FRPC(t, &v1.ClientCommonConfig{
		User:          m.User,
		ServerAddr:    vm.Addr,
		ServerPort:    vm.HTTPS,
		LoginFailExit: new(false),
		Transport: v1.ClientTransportConfig{
			Protocol:             proto,
			WireProtocol:         "v2",
			ConnectServerLocalIP: m.LocalIP,
			// fortresskube's defaults.
			DeadServerTimeout: 3,
			DialServerTimeout: 2,
			TLS: v1.TLSClientConfig{TLSConfig: v1.TLSConfig{
				CertFile: crt, KeyFile: key, TrustedCaFile: caFile, ServerName: Tunnel,
			}},
		},
	}, &v1.HTTPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: domains[0], Type: "http", ProxyBackend: v1.ProxyBackend{
			LocalIP: "127.0.0.1", LocalPort: port,
		}},
		DomainConfig: v1.DomainConfig{CustomDomains: domains},
	})
	// Own the lifetime: Close and wait so Run's stop does not race the next
	// parallel subtest (t.Context alone cancels without joining).
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = svc.Run(context.Background())
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			svc.Close()
			<-done
		})
	}
	t.Cleanup(stop)
	return stop
}

// Login runs frpc over proto with the client certificate crt/key, without
// retries, and returns frps's refusal. nil means it logged in and was
// still connected when a few seconds were up.
// tls, when given, changes frpc's TLS settings before it starts.
func (vm *VM) Login(t *testing.T, proto, caFile, crt, key string, tls ...func(*v1.TLSClientConfig)) error {
	t.Helper()
	cfg := &v1.ClientCommonConfig{
		ServerAddr:    vm.Addr,
		ServerPort:    vm.HTTPS,
		LoginFailExit: new(true),
		Transport: v1.ClientTransportConfig{
			Protocol:     proto,
			WireProtocol: "v2",
			TLS: v1.TLSClientConfig{TLSConfig: v1.TLSConfig{
				CertFile: crt, KeyFile: key, TrustedCaFile: caFile, ServerName: Tunnel,
			}},
		},
	}
	for _, f := range tls {
		f(&cfg.Transport.TLS)
	}
	svc := FRPC(t, cfg)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	return svc.Run(ctx)
}

// FRPC builds an in-process frp client from common plus proxies.
func FRPC(t *testing.T, common *v1.ClientCommonConfig, proxies ...v1.ProxyConfigurer) *client.Service {
	t.Helper()
	src := source.NewConfigSource()
	require.NoError(t, src.ReplaceAll(proxies, nil))
	svc, err := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(src)})
	require.NoError(t, err)
	return svc
}

// Ctl runs fortressctl. Its output is shown only when it fails.
func Ctl(t *testing.T, args ...string) {
	t.Helper()
	CtlOut(t, args...)
}

// CtlOut runs fortressctl, requires it to succeed, and returns its output.
func CtlOut(t *testing.T, args ...string) string {
	t.Helper()
	out, code := ctl(t, args...)
	require.Zero(t, code, "fortressctl %s\n%s", strings.Join(args, " "), out)
	return out
}

// ctl runs fortressctl and returns its output and exit status.
func ctl(t *testing.T, args ...string) (string, int) {
	t.Helper()
	t.Logf("fortressctl %s", strings.Join(args, " "))
	out, err := exec.CommandContext(t.Context(), *fortressctl, args...).CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode()
	}
	require.NoError(t, err, "fortressctl %s", strings.Join(args, " "))
	return string(out), 0
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

// PKI writes a client CA into dir/tls with one client certificate per
// role, for the fqdn Tunnel: node/node1, ops/alice, and logs/shipper. It
// returns that directory.
func PKI(t *testing.T, dir string) string {
	t.Helper()
	pki := filepath.Join(dir, "tls")
	Ctl(t, "ca", "init", pki)
	Ctl(t, "ca", "client", pki, ca.ID(Tunnel, ca.RoleNode, "node1"))
	Ctl(t, "ca", "client", pki, ca.ID(Tunnel, ca.RoleOps, "alice"))
	Ctl(t, "ca", "client", pki, ca.ID(Tunnel, ca.RoleLogs, "shipper"))
	return pki
}

// BlankDisk is a blank 64 MiB data disk in dir, which the edge formats.
func BlankDisk(t *testing.T, dir string) string {
	t.Helper()
	disk := filepath.Join(dir, "data.img")
	require.NoError(t, os.WriteFile(disk, nil, 0o644))
	require.NoError(t, os.Truncate(disk, 64<<20))
	return disk
}

// Bake writes fortress.yml into a copy of iso with fortressctl bake, and
// returns the copy's path.
func Bake(t *testing.T, dir, iso string, edge []byte) string {
	t.Helper()
	out := filepath.Join(dir, "edge.iso")
	Ctl(t, "bake", "-o", out, "-c", Write(t, dir, "fortress.yml", edge), iso)
	return out
}

// Cert is the certificate and key fortressctl ca client wrote for
// role/name in pki.
func Cert(pki string, role ca.Role, name string) (crt, key string) {
	return ca.ClientFiles(pki, role, name)
}

// Read loads a file from the suite's testdata directory.
func Read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

// Write stores b at dir/name and returns that path.
func Write(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, b, 0o644))
	return path
}
