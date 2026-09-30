package config

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sebiee/fortressedge/internal/ca"
)

// testUserData is what Proxmox writes for a VM named edge1 in the DNS
// domain example.com: only fqdn is read.
const testUserData = `#cloud-config
hostname: edge1
manage_etc_hosts: true
fqdn: edge1.example.com
user: root
ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCTIxAVhBdzJawC9S/Nlog/fcF+sMAqnsayBlXKyZMM me@laptop
chpasswd:
  expire: False
mounts:
  - [/dev/vdb, /var]
ntp:
  servers: [time.example.com]
package_upgrade: true
`

const testNetv1 = `version: 1
config:
  - type: physical
    name: ens3
    subnets:
      - type: static
        address: 10.0.2.15
        netmask: 255.255.255.0
        gateway: 10.0.2.2
        dns_nameservers: [1.1.1.1]
`

// parse is Parse with testUserData, testNetv1, and no policy.
func parse(edge string) (Config, error) {
	return Parse([]byte(testUserData), []byte(testNetv1), withCA(edge), nil)
}

func TestParseProxmoxSeed(t *testing.T) {
	c, err := parse("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Iface != "ens3" || c.Tunnel != "edge1.example.com" || c.Addr.String() != "10.0.2.15/24" || c.Gateway.String() != "10.0.2.2" {
		t.Fatalf("%+v", c)
	}
	if len(c.DNS) != 1 || c.DNS[0].String() != "1.1.1.1" {
		t.Fatalf("dns: %v", c.DNS)
	}
	// user-data's mounts and ntp are not read; nor is any policy there.
	if c.Disk != "" || !slices.Equal(c.NTP, []string{DefaultNTP}) || c.QUIC || c.ACME != "" {
		t.Fatalf("user-data keys other than fqdn applied: %+v", c)
	}
	if c.Limits != DefaultLimits() || c.Block != nil || c.Exempt != nil {
		t.Fatalf("policy without policy.yml: %+v", c.Policy)
	}
}

func TestParseRequiresEachPart(t *testing.T) {
	for name, files := range map[string][3][]byte{
		"network-config": {[]byte(testUserData), nil, withCA("")},
		"fqdn":           {[]byte("#cloud-config\nhostname: edge1\n"), []byte(testNetv1), withCA("")},
		"user-data":      {nil, []byte(testNetv1), withCA("")},
		"fortress.yml":   {[]byte(testUserData), []byte(testNetv1), nil},
		"client_ca":      {[]byte(testUserData), []byte(testNetv1), []byte("quic: true\n")},
		"gateway":        {[]byte(testUserData), []byte("version: 2\nethernets:\n  eth0:\n    addresses: [10.0.2.15/24]\n"), withCA("")},
	} {
		if _, err := Parse(files[0], files[1], files[2], nil); err == nil {
			t.Errorf("accepted without %s", name)
		}
	}
}

func TestFQDN(t *testing.T) {
	for in, want := range map[string]string{
		"edge1.example.com":   "edge1.example.com",
		"Edge1.Example.COM.":  "edge1.example.com",
		"a-1.b2.example":      "a-1.b2.example",
		" tunnel.example.io ": "tunnel.example.io",
	} {
		c, err := Parse([]byte("#cloud-config\nfqdn: \""+in+"\"\n"), []byte(testNetv1), withCA(""), nil)
		if err != nil || c.Tunnel != want {
			t.Errorf("%q: %q %v", in, c.Tunnel, err)
		}
	}
	// Proxmox writes the VM name alone, or VM<id>, when the VM has no DNS domain.
	for _, bad := range []string{"edge1", "VM100", "10.0.2.15", "2001:db8::1", "-a.example.com", "a_b.example.com",
		"a..example.com", "edge1.123", strings.Repeat("a", 64) + ".example.com"} {
		if _, err := Parse([]byte("#cloud-config\nfqdn: \""+bad+"\"\n"), []byte(testNetv1), withCA(""), nil); err == nil {
			t.Errorf("accepted fqdn %q", bad)
		}
	}
	_, err := Parse([]byte("#cloud-config\nfqdn: edge1\n"), []byte(testNetv1), withCA(""), nil)
	if err == nil || !strings.Contains(err.Error(), "Proxmox") {
		t.Fatalf("a bare hostname should say how to fix it: %v", err)
	}
}

// What Proxmox writes for ipconfig0 ip=10.0.2.15/24,gw=10.0.2.2 with the
// VM's DNS server set: the servers are an item of their own.
func TestParseProxmoxNetwork(t *testing.T) {
	c, err := Parse([]byte(testUserData), []byte(`version: 1
config:
    - type: physical
      name: eth0
      mac_address: 'bc:24:11:2a:5f:10'
      subnets:
      - type: static
        address: '10.0.2.15'
        netmask: '255.255.255.0'
        gateway: '10.0.2.2'
      - type: static6
        address: '2001:db8::15/64'
    - type: nameserver
      address:
      - '10.0.0.53'
      - '10.0.0.54'
      search:
      - 'example.com'
`), withCA(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Iface != "eth0" || c.Addr.String() != "10.0.2.15/24" || c.Gateway.String() != "10.0.2.2" {
		t.Fatalf("%+v", c)
	}
	if len(c.DNS) != 2 || c.DNS[0].String() != "10.0.0.53" || c.DNS[1].String() != "10.0.0.54" {
		t.Fatalf("dns: %v", c.DNS)
	}
	// A subnet's own dns_nameservers win.
	c, err = Parse([]byte(testUserData), []byte(testNetv1+"  - type: nameserver\n    address: ['10.0.0.53']\n"), withCA(""), nil)
	if err != nil || len(c.DNS) != 1 || c.DNS[0].String() != "1.1.1.1" {
		t.Fatalf("dns: %v %v", c.DNS, err)
	}
	if _, err := Parse([]byte(testUserData), []byte(testNetv1+"  - type: nameserver\n    address: [nope]\n"), withCA(""), nil); err == nil {
		t.Fatal("bad nameserver accepted")
	}
}

func TestParseNetv2(t *testing.T) {
	c, err := Parse([]byte(testUserData), []byte(`version: 2
ethernets:
  eth0:
    addresses: [192.0.2.10/24]
    gateway4: 192.0.2.1
    nameservers:
      addresses: [8.8.8.8]
`), withCA(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Iface != "eth0" || c.Addr.String() != "192.0.2.10/24" || c.Gateway.String() != "192.0.2.1" {
		t.Fatalf("%+v", c)
	}
	if len(c.DNS) != 1 || c.DNS[0].String() != "8.8.8.8" {
		t.Fatalf("dns: %v", c.DNS)
	}
}

func TestParseNetworkWrapper(t *testing.T) {
	c, err := Parse([]byte(testUserData), []byte(`network:
  version: 1
  config:
    - type: physical
      name: eth0
      subnets:
        - type: static
          address: 10.0.2.15/24
          gateway: 10.0.2.2
`), withCA(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr.String() != "10.0.2.15/24" || c.Iface != "eth0" {
		t.Fatalf("%+v", c)
	}
}

func TestParseNTP(t *testing.T) {
	c, err := parse("ntp: 10.0.0.1:123\n")
	if err != nil || !slices.Equal(c.NTP, []string{"10.0.0.1:123"}) {
		t.Fatalf("ntp: %q %v", c.NTP, err)
	}
	c, err = parse("ntp: [ntp11.metas.ch, ntp12.metas.ch, '[2001:db8::1]:4123']\n")
	if err != nil || !slices.Equal(c.NTP, []string{"ntp11.metas.ch", "ntp12.metas.ch", "[2001:db8::1]:4123"}) {
		t.Fatalf("ntp list: %q %v", c.NTP, err)
	}
	for _, bad := range []string{
		"ntp: [a.example.com, a.example.com]\n",
		"ntp: time.example.com:ntp\n",
		"ntp: time.example.com:70000\n",
		"ntp: not a name\n",
		"ntp: {server: a.example.com}\n",
		"ntp: [a1.example.com, a2.example.com, a3.example.com, a4.example.com, a5.example.com, a6.example.com, a7.example.com, a8.example.com, a9.example.com]\n",
	} {
		if _, err := parse(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestParseACME(t *testing.T) {
	c, err := parse("acme: https://vault.example.com/v1/pki/acme/directory\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.ACME != "https://vault.example.com/v1/pki/acme/directory" {
		t.Fatalf("acme: %q", c.ACME)
	}
	crt, _, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	withRoot, err := parse("acme_ca: |\n" + indentPEM(string(crt)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(withRoot.ACMECA, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("acme_ca: %q", withRoot.ACMECA)
	}
	if _, err := parse("acme_ca: not-a-cert\n"); err == nil {
		t.Fatal("expected acme_ca error")
	}
	for _, raw := range []string{"not-a-url", "ftp://ca.example", "https://"} {
		if _, err := parse("acme: " + raw + "\n"); err == nil {
			t.Fatalf("accepted acme %q", raw)
		}
	}
}

func TestParseRenewInterval(t *testing.T) {
	if c, err := parse(""); err != nil || c.RenewInterval != DefaultRenewInterval {
		t.Fatalf("default: %v %v", c.RenewInterval, err)
	}
	if c, err := parse("renew_interval: 90m\n"); err != nil || c.RenewInterval != 90*time.Minute {
		t.Fatalf("90m: %v %v", c.RenewInterval, err)
	}
	for _, raw := range []string{"4", "soon", "50ms", "-1h"} {
		if _, err := parse("renew_interval: " + raw + "\n"); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestParseQUIC(t *testing.T) {
	if q, err := parse("quic: true\n"); err != nil || !q.QUIC {
		t.Fatalf("quic: %v", err)
	}
}

func TestParseAccessLog(t *testing.T) {
	p, err := ParsePolicy([]byte("access_log: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := (AccessLog{On: true, MaxSize: DefaultAccessLogMaxSize, MaxFiles: DefaultAccessLogMaxFiles}); p.AccessLog != want {
		t.Fatalf("access_log: %+v", p.AccessLog)
	}
	p, err = ParsePolicy([]byte("access_log: true\naccess_log_max_size: 1GiB\naccess_log_max_files: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.AccessLog.MaxSize != 1<<30 || p.AccessLog.MaxFiles != 10 {
		t.Fatalf("access_log sizes: %+v", p.AccessLog)
	}
	for _, bad := range []string{"access_log_max_size: 8\n", "access_log_max_size: 512KiB\n", "access_log_max_size: 8MB\n",
		"access_log_max_size: -8MiB\n", "access_log_max_files: -1\n", "access_log_max_files: 1001\n"} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
	// It moved from fortress.yml, which says where it went.
	if _, err := parse("access_log: true\n"); err == nil || !strings.Contains(err.Error(), "put it in policy.yml") {
		t.Fatalf("access_log in fortress.yml: %v", err)
	}
}

func TestParseSites(t *testing.T) {
	p, err := ParsePolicy([]byte("access_log: true\nlimits:\n  max_body_size: 1MiB\n  response_header_timeout: 30s\n" +
		"sites:\n  Upload.Example.com.:\n    max_body_size: 4GiB\n    access_log: false\n" +
		"  '*.apps.example.com':\n    response_header_timeout: 10m\n    max_body_size: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	edge := Site{AccessLog: true, MaxBodyBytes: 1 << 20, ResponseHeaderTimeout: 30 * time.Second}
	for _, tc := range []struct {
		host, route string
		want        Site
	}{
		{"other.example.com", "other.example.com", edge},
		{"upload.example.com", "upload.example.com", Site{MaxBodyBytes: 4 << 30, ResponseHeaderTimeout: 30 * time.Second}},
		{"argo.apps.example.com", "*.apps.example.com", Site{AccessLog: true, ResponseHeaderTimeout: 10 * time.Minute}},
		// A name's own entry wins over its wildcard's.
		{"upload.example.com", "*.example.com", Site{MaxBodyBytes: 4 << 30, ResponseHeaderTimeout: 30 * time.Second}},
	} {
		if got := p.Site(tc.host, tc.route); got != tc.want {
			t.Errorf("%s via %s: %+v, want %+v", tc.host, tc.route, got, tc.want)
		}
	}
	if !p.AccessLogAnywhere() {
		t.Fatal("AccessLogAnywhere")
	}
	p, _ = ParsePolicy([]byte("sites:\n  a.example.com:\n    access_log: true\n"))
	if p.AccessLog.On || !p.AccessLogAnywhere() || !p.Site("a.example.com", "a.example.com").AccessLog {
		t.Fatal("one site's access log")
	}
	for _, bad := range []string{
		"sites:\n  localhost:\n    access_log: true\n",
		"sites:\n  '*example.com':\n    access_log: true\n",
		"sites:\n  a.example.com:\n    max_body_size: 12\n",
		"sites:\n  a.example.com:\n    response_header_timeout: 1h\n",
		"sites:\n  a.example.com:\n    ban: 1m\n",
		"sites:\n  a.example.com: {}\n  A.example.com: {}\n",
	} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestParseTunnelGrace(t *testing.T) {
	if p, err := ParsePolicy(nil); err != nil || p.TunnelGrace != DefaultTunnelGrace {
		t.Fatalf("default: %s %v", p.TunnelGrace, err)
	}
	for in, want := range map[string]time.Duration{"0": 0, "1h": time.Hour, "720h": 720 * time.Hour} {
		if p, err := ParsePolicy([]byte("tunnel_grace: " + in + "\n")); err != nil || p.TunnelGrace != want {
			t.Errorf("%s: %s %v", in, p.TunnelGrace, err)
		}
	}
	for _, bad := range []string{"-1m", "721h", "soon"} {
		if _, err := ParsePolicy([]byte("tunnel_grace: " + bad + "\n")); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}

func TestParseTrace(t *testing.T) {
	if p, err := ParsePolicy(nil); err != nil || p.Trace.TrustIncoming {
		t.Fatalf("default: %+v %v", p.Trace, err)
	}
	if p, err := ParsePolicy([]byte("trace:\n  trust_incoming: true\n")); err != nil || !p.Trace.TrustIncoming {
		t.Fatalf("trust_incoming: %+v %v", p.Trace, err)
	}
	if _, err := ParsePolicy([]byte("trace:\n  export: otlp\n")); err == nil {
		t.Fatal("unknown trace key")
	}
}

func TestParseClientCA(t *testing.T) {
	c, err := parse("")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(c.ClientCA, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("client_ca: %q", c.ClientCA)
	}
	if err := CheckEdge([]byte("client_ca: not-a-cert\n")); err == nil {
		t.Fatal("expected client_ca error")
	}
	// One CA only: a second certificate would be trusted too.
	other, _, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	two := "client_ca: |\n" + indentPEM(testCA) + indentPEM(string(other))
	if err := CheckEdge([]byte(two)); err == nil || !strings.Contains(err.Error(), "more than one certificate") {
		t.Fatalf("two CAs: %v", err)
	}
}

// Each key has one file. One in the other file says where it belongs.
func TestKeysInTheWrongFile(t *testing.T) {
	for edge, want := range map[string]string{
		"block: [1.2.3.4]\n":                "fortressctl apply",
		"limits:\n  ban: 0\n":               "fortressctl apply",
		"tls: static\n":                     `unknown key "tls"`,
		"fqdn: edge1.example.com\n":         `unknown key "fqdn"`,
		"quic: [\n":                         EdgeFile,
		"exempt: [192.0.2.0/24]\nquic: 1\n": "fortressctl apply",
	} {
		if err := CheckEdge(withCA(edge)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("fortress.yml %q: %v, want %q", edge, err, want)
		}
	}
	for policy, want := range map[string]string{
		"quic: true\n":             "bake a new one",
		"client_ca: x\n":           "bake a new one",
		"allow: [192.0.2.0/24]\n":  `unknown key "allow"`,
		"block: [1.2.3.4]\nx: 1\n": `unknown key "x"`,
	} {
		if _, err := ParsePolicy([]byte(policy)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("policy.yml %q: %v, want %q", policy, err, want)
		}
	}
}

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte("block: [10.0.0.0/8, 2001:db8::/32, 192.0.2.9]\nexempt: [192.0.2.0/24, 2001:db8::7]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Block) != 3 || p.Block[0].String() != "10.0.0.0/8" || p.Block[1].String() != "2001:db8::/32" || p.Block[2].String() != "192.0.2.9/32" {
		t.Fatalf("block: %v", p.Block)
	}
	if len(p.Exempt) != 2 || p.Exempt[0].String() != "192.0.2.0/24" || p.Exempt[1].String() != "2001:db8::7/128" {
		t.Fatalf("exempt: %v", p.Exempt)
	}
	for _, bad := range []string{"block: [not-an-ip]\n", "exempt: [nope]\n", "block: [\n"} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
	c, err := Parse([]byte(testUserData), []byte(testNetv1), withCA(""), []byte("block: [192.0.2.9]\n"))
	if err != nil || len(c.Block) != 1 {
		t.Fatalf("Parse with a policy: %v %v", c.Block, err)
	}
	if _, err := Parse([]byte(testUserData), []byte(testNetv1), withCA(""), []byte("block: [x]\n")); err == nil {
		t.Fatal("Parse accepted a bad policy")
	}
}

func TestPolicyRebootFrom(t *testing.T) {
	cur := Policy{Limits: DefaultLimits()}
	next := cur
	next.Block = []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}
	next.Exempt = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if next.RebootFrom(cur) {
		t.Fatal("block and exempt apply in place")
	}
	for name, live := range map[string]func(*Limits){
		"requests_per_second":        func(l *Limits) { l.RequestsPerSecond = 7 },
		"request_burst":              func(l *Limits) { l.RequestBurst = 7 },
		"connections_per_source":     func(l *Limits) { l.ConnsPerSource = 7 },
		"new_connections_per_second": func(l *Limits) { l.NewConnsPerSecond = 7 },
		"ban":                        func(l *Limits) { l.Ban = time.Second },
		"ban_after":                  func(l *Limits) { l.BanAfter = 7 },
		"ban_window":                 func(l *Limits) { l.BanWindow = time.Minute },
		"max_uri_size":               func(l *Limits) { l.MaxURIBytes = 7 },
		"max_body_size":              func(l *Limits) { l.MaxBodyBytes = 7 },
		// Each request carries its own to frps.
		"response_header_timeout": func(l *Limits) { l.ResponseHeaderTimeout = time.Hour },
	} {
		next := cur
		live(&next.Limits)
		if next.RebootFrom(cur) {
			t.Fatalf("%s applies in place", name)
		}
	}
	for name, boot := range map[string]func(*Limits){
		"max_connections":   func(l *Limits) { l.MaxConns = 7 },
		"max_header_size":   func(l *Limits) { l.MaxHeaderBytes = 7 },
		"max_http2_streams": func(l *Limits) { l.MaxHTTP2Streams = 7 },
	} {
		next := cur
		boot(&next.Limits)
		if !next.RebootFrom(cur) {
			t.Fatalf("%s reboots", name)
		}
	}
}

func TestParseLimits(t *testing.T) {
	parse := ParsePolicy
	c, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits != DefaultLimits() {
		t.Fatalf("defaults: %+v", c.Limits)
	}
	c, err = parse([]byte("limits:\n  requests_per_second: 0\n  connections_per_source: 1000\n  ban: 0\n  ban_after: 5\n  ban_window: 1m\n" +
		"  new_connections_per_second: 500\n  new_connection_burst: 1000\n  max_connections: 50000\n" +
		"  max_header_size: 128KiB\n  max_uri_size: 32KiB\n  max_body_size: 0\n  max_http2_streams: 250\n" +
		"  response_header_timeout: 5m\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultLimits()
	want.RequestsPerSecond, want.ConnsPerSource, want.Ban = 0, 1000, 0
	want.BanAfter, want.BanWindow = 5, time.Minute
	want.NewConnsPerSecond, want.NewConnBurst, want.MaxConns = 500, 1000, 50000
	want.MaxHeaderBytes, want.MaxURIBytes = 128<<10, 32<<10
	want.MaxBodyBytes, want.MaxHTTP2Streams = 0, 250
	want.ResponseHeaderTimeout = 5 * time.Minute
	if c.Limits != want {
		t.Fatalf("limits: %+v", c.Limits)
	}
	for _, bad := range []string{
		"limits:\n  requests_per_second: -1\n",
		"limits:\n  request_burst: 0\n",
		"limits:\n  new_connection_burst: 0\n",
		"limits:\n  ban: soon\n",
		"limits:\n  ban_after: 0\n",
		"limits:\n  ban_window: 500ms\n",
		"limits:\n  max_header_size: 1KiB\n",
		"limits:\n  max_uri_size: 64\n",
		"limits:\n  max_body_size: 12\n",
		"limits:\n  max_http2_streams: 0\n",
		"limits:\n  response_header_timeout: 0\n",
		"limits:\n  response_header_timeout: 500ms\n",
		"limits:\n  response_header_timeout: 1.5s\n",
		"limits:\n  response_header_timeout: 11m\n",
		"limits:\n  response_header_timeout: 60\n",
	} {
		if _, err := parse([]byte(bad)); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
	// A burst of 0 is fine once its rate is off.
	if _, err := parse([]byte("limits:\n  requests_per_second: 0\n  request_burst: 0\n")); err != nil {
		t.Fatal(err)
	}
	// The bounds of response_header_timeout are in.
	for _, ok := range []string{"1s", "10m"} {
		if _, err := parse([]byte("limits:\n  response_header_timeout: " + ok + "\n")); err != nil {
			t.Fatal(err)
		}
	}
}

// withCA is a fortress.yml body with a client_ca added, which every
// fortress.yml needs.
func withCA(body string) []byte {
	return []byte(body + "client_ca: |\n" + indentPEM(testCA))
}

var testCA = func() string {
	crt, _, err := ca.NewCA()
	if err != nil {
		panic(err)
	}
	return string(crt)
}()

func indentPEM(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
