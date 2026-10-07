// Package config reads the edge's config. It comes in four parts, and
// each has one owner:
//
//	fortress.yml    baked into the ISO by fortressctl bake: what the edge
//	                trusts and how it runs. A new ISO changes it.
//	user-data       the NoCloud drive: fqdn, the edge's DNS name. Nothing
//	                else in it is read.
//	network-config  the NoCloud drive: the static address.
//	policy.yml      the /var disk, from fortressctl apply: who may reach the
//	                edge and how much. It changes while the edge runs.
//
// None of them holds a secret.
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Sebiee/fortressedge/internal/ca"
)

// frps listens on loopback for dark-node control, which the edge reaches
// in-process. QUIC, when enabled, binds FrpsQUICPort on the public address
// instead.
const (
	FrpsBindAddr     = "127.0.0.1"
	FrpsTCPPort      = 7000 // dark-node control (wss)
	FrpsQUICPort     = 443  // dark-node QUIC on the public UDP port; TCP control stays on loopback
	FrpWebsocketPath = "/~!frp"

	// Operator API, served on the tunnel SNI (mTLS already enforced there).
	OpsPathPrefix = "/~!ops/"
	OpsLogsPath   = OpsPathPrefix + "logs"
	OpsAccessPath = OpsPathPrefix + "access"
	OpsStatusPath = OpsPathPrefix + "status"
	// OpsMetricsPath is the Prometheus text format of what status counts.
	OpsMetricsPath = OpsPathPrefix + "metrics"
	// OpsPolicyPath reads the policy (GET) and replaces it (PUT).
	OpsPolicyPath = OpsPathPrefix + "policy"
)

func ControlAddr() string { return fmt.Sprintf("%s:%d", FrpsBindAddr, FrpsTCPPort) }

const (
	DefaultNTP = "pool.ntp.org"
	// DefaultRenewInterval is how often ACME certificates are checked for
	// renewal when fortress.yml sets no renew_interval.
	DefaultRenewInterval = 4 * time.Hour
	// DefaultTunnelGrace covers a reboot of the edge, and a dark node
	// restarting or upgraded; maxTunnelGrace bounds it at a month.
	DefaultTunnelGrace = 10 * time.Minute
	maxTunnelGrace     = 720 * time.Hour
	// DefaultTunnelDeadTimeout matches fortresskube's dead_server_timeout:
	// neither end of a tunnel gives up on the other first.
	DefaultTunnelDeadTimeout = 3 * time.Second
	maxTunnelDeadTimeout     = 10 * time.Minute
	// The access log's defaults keep it at 24 MiB, well inside a 64 MiB
	// data disk.
	DefaultAccessLogMaxSize  = 8 << 20
	DefaultAccessLogMaxFiles = 3

	// EdgeFile is the baked config, at BakedFile in the initramfs.
	EdgeFile  = "fortress.yml"
	BakedFile = "/etc/fortressedge/" + EdgeFile
	// PolicyName is the runtime config, stored at PolicyFile.
	PolicyName = "policy.yml"

	// The persistent disk mounts at /var; state and logs live there.
	DataDir    = "/var/fortressedge"
	PolicyFile = DataDir + "/" + PolicyName
	CertsDir   = DataDir + "/certs"
	// RunClientCA holds the fortress.yml client_ca for this boot, for frps,
	// which reads its trust anchor from a file. The edge holds no CA key.
	RunClientCA = "/run/fortressedge/client_ca.crt"
	LogDir      = "/var/log/fortressedge"
	LogFile     = LogDir + "/current.log"
	// AccessLogDir holds the access log (policy.yml's access_log), one JSON
	// line per site request, apart from the edge's own log.
	AccessLogDir = LogDir + "/access"
)

type Config struct {
	Iface   string
	Addr    netip.Prefix // static address of Iface, with prefix length
	Gateway netip.Addr
	DNS     []netip.Addr
	Tunnel  string // the fqdn: SNI dark nodes and operators connect to
	// Disk is the device boot mounted at /var; not part of the config.
	Disk string
	// NTP are the time servers, host or host:port, which the clock keeps
	// to while the edge runs (internal/clock).
	NTP  []string
	ACME string // ACME directory URL; empty is Let's Encrypt
	// ACMECA is the PEM trust anchor for the directory's TLS certificate.
	// Empty uses the system roots. Set, it is the only pool the ACME client trusts.
	ACMECA []byte
	// RenewInterval is how often every ACME certificate is checked, and
	// renewed once it is due (the last third of its life, or when the CA
	// says so through ARI).
	RenewInterval time.Duration
	QUIC          bool // dark-node QUIC on UDP 443
	// Vault, when set, is where the edges that serve the same names share
	// their certificates, ACME account, and challenges.
	Vault *Vault
	// ClientCA is the PEM trust anchor from fortress.yml (client_ca) for
	// dark-node, operator, and log-reader certificates.
	ClientCA []byte
	// ClientCAPath is the file listeners load this boot. Set after boot
	// resolves client_ca; not part of fortress.yml.
	ClientCAPath string
	Policy
}

// Vault is a KV v2 path several edges share their certificates in, and
// the AppRole that may use it.
type Vault struct {
	URL      string // https://vault.example.com:8200
	CA       []byte // PEM; empty trusts the system roots
	Mount    string // the KV v2 mount
	Path     string // the path in it, for these edges only
	RoleID   string
	SecretID string
}

// Policy is policy.yml: what the edge lets through. It is the part an
// operator changes while the edge runs.
type Policy struct {
	Block []netip.Prefix // XDP drop list; host or CIDR
	// Exempt are sources the per-address limits and bans skip: a load
	// generator, a monitoring probe, an office behind one address.
	Exempt []netip.Prefix
	Limits Limits
	// AccessLog is the access log for every site, unless Sites turns it
	// off or on for one.
	AccessLog AccessLog
	Trace     Trace
	// TunnelGrace is how long a site whose tunnel left, or that a dark
	// node published before a boot, is answered 503 before it goes silent
	// like any name the edge does not serve. 0 never answers it.
	TunnelGrace time.Duration
	// TunnelDeadTimeout is how long a tunnel connection may go without the
	// dark node acknowledging anything before the edge drops it, so a lost
	// frpc leaves its group and the others carry its share. 0 leaves it to
	// frps's heartbeat. A tunnel keeps the timeout it connected with.
	TunnelDeadTimeout time.Duration
	// Sites are settings for one site, by the name its dark node publishes
	// (app.example.com, *.example.com) or a name a wildcard covers.
	Sites map[string]SitePolicy
}

// AccessLog writes one line per site request to AccessLogDir, in files of
// up to MaxSize bytes, keeping MaxFiles.
type AccessLog struct {
	On       bool
	MaxSize  int64
	MaxFiles int
}

// Trace is how the edge joins a request to a W3C trace (traceparent).
type Trace struct {
	// TrustIncoming continues a visitor's valid traceparent. Off, every
	// request starts a new trace, and the visitor's is only logged, as a
	// link: an outsider cannot choose the trace a request lands in.
	TrustIncoming bool
}

// SitePolicy overrides edge-wide settings for one site. A nil or zero
// field keeps the edge-wide one.
type SitePolicy struct {
	AccessLog             *bool
	MaxBodyBytes          *int64 // 0: no limit
	ResponseHeaderTimeout time.Duration
	// For a TCP route: see Limits.
	TCPIdleTimeout    *time.Duration
	TCPConnsPerSource *int
}

// Site is the settings in force for one request.
type Site struct {
	AccessLog             bool
	MaxBodyBytes          int64 // 0: no limit
	ResponseHeaderTimeout time.Duration
	TCPIdleTimeout        time.Duration // 0: never
	TCPConnsPerSource     int           // 0: no limit
}

// Site is what applies to a request for host, which frps routed by route,
// the published name that matched it (host itself, or a wildcard). An
// entry for host wins over one for route.
func (p Policy) Site(host, route string) Site {
	s := Site{
		AccessLog: p.AccessLog.On, MaxBodyBytes: p.Limits.MaxBodyBytes, ResponseHeaderTimeout: p.Limits.ResponseHeaderTimeout,
		TCPIdleTimeout: p.Limits.TCPIdleTimeout, TCPConnsPerSource: p.Limits.TCPConnsPerSource,
	}
	if len(p.Sites) == 0 {
		return s
	}
	sp, ok := p.Sites[host]
	if !ok {
		if sp, ok = p.Sites[route]; !ok {
			return s
		}
	}
	if sp.AccessLog != nil {
		s.AccessLog = *sp.AccessLog
	}
	if sp.MaxBodyBytes != nil {
		s.MaxBodyBytes = *sp.MaxBodyBytes
	}
	if sp.ResponseHeaderTimeout > 0 {
		s.ResponseHeaderTimeout = sp.ResponseHeaderTimeout
	}
	if sp.TCPIdleTimeout != nil {
		s.TCPIdleTimeout = *sp.TCPIdleTimeout
	}
	if sp.TCPConnsPerSource != nil {
		s.TCPConnsPerSource = *sp.TCPConnsPerSource
	}
	return s
}

// AccessLogAnywhere reports whether any site may write the access log.
func (p Policy) AccessLogAnywhere() bool {
	if p.AccessLog.On {
		return true
	}
	for _, sp := range p.Sites {
		if sp.AccessLog != nil && *sp.AccessLog {
			return true
		}
	}
	return false
}

// PolicyETag names a policy.yml body: its SHA-256, quoted as an HTTP
// entity tag. The ops API sends it with the policy; fortressctl diff
// compares it with the file in git.
func PolicyETag(policy []byte) string {
	return fmt.Sprintf("\"%x\"", sha256.Sum256(policy))
}

// RebootFrom reports whether moving from cur to p needs a reboot: only
// the limits the servers fix when they start do.
func (p Policy) RebootFrom(cur Policy) bool {
	return p.Limits.BootLimits() != cur.Limits.BootLimits()
}

// Limits protect the edge from one source (an IPv4 address or an IPv6
// /64). A rate or count of 0 turns that limit off.
type Limits struct {
	ConnsPerSource    int           // open connections
	RequestsPerSecond int           // sustained
	RequestBurst      int           // at once
	NewConnsPerSecond int           // TCP SYNs, dropped in XDP
	NewConnBurst      int           // SYNs at once
	Ban               time.Duration // XDP ban for a source that keeps being refused; 0 never bans
	BanAfter          int           // refusals within BanWindow that earn a ban
	BanWindow         time.Duration
	MaxConns          int   // all sources, per port; 0 sizes it from memory
	MaxHeaderBytes    int   // request line and headers
	MaxURIBytes       int   // request target
	MaxBodyBytes      int64 // request body; 0: no limit
	MaxHTTP2Streams   int   // concurrent streams per HTTP/2 connection
	// ResponseHeaderTimeout is how long a request waits for the origin's
	// response headers; a stream that sends them with its first event
	// (server-sent events, long polling) is cut after it. Whole seconds.
	ResponseHeaderTimeout time.Duration
	// TCPIdleTimeout closes a TCP route's connection after this long
	// with no byte either way; 0 never does. Database tools hold
	// sessions open for hours.
	TCPIdleTimeout time.Duration
	// TCPConnsPerSource is how many connections one source may hold open
	// to one TCP route; connections_per_source counts them too.
	TCPConnsPerSource int
}

// BootLimits are the limits the HTTP servers and listeners fix when they
// start; a change to any of them reboots. The rest apply at once.
func (l Limits) BootLimits() Limits {
	return Limits{MaxConns: l.MaxConns, MaxHeaderBytes: l.MaxHeaderBytes, MaxHTTP2Streams: l.MaxHTTP2Streams}
}

// DefaultLimits are generous: many people can share one IPv4 address.
func DefaultLimits() Limits {
	return Limits{
		ConnsPerSource:    256,
		RequestsPerSecond: 150,
		RequestBurst:      600, // several heavy pages at once from one address
		NewConnsPerSecond: 64,
		NewConnBurst:      128,
		Ban:               15 * time.Minute,
		// Twenty refusals a second for ten seconds: a client that honors
		// Retry-After, or goes slightly over, is never banned.
		BanAfter:        200,
		BanWindow:       10 * time.Second,
		MaxHeaderBytes:  64 << 10,
		MaxURIBytes:     16 << 10,
		MaxBodyBytes:    512 << 20,
		MaxHTTP2Streams: 100, // net/http's default is 250
		// frp's default.
		ResponseHeaderTimeout: time.Minute,
		TCPIdleTimeout:        8 * time.Hour,
		TCPConnsPerSource:     20,
	}
}

// limitsYAML is policy.yml's limits block. A key left out keeps its default.
type limitsYAML struct {
	ConnsPerSource        *int   `yaml:"connections_per_source"`
	RequestsPerSecond     *int   `yaml:"requests_per_second"`
	RequestBurst          *int   `yaml:"request_burst"`
	NewConnsPerSecond     *int   `yaml:"new_connections_per_second"`
	NewConnBurst          *int   `yaml:"new_connection_burst"`
	Ban                   string `yaml:"ban"`
	BanAfter              *int   `yaml:"ban_after"`
	BanWindow             string `yaml:"ban_window"`
	MaxConns              *int   `yaml:"max_connections"`
	MaxHeaderSize         string `yaml:"max_header_size"`
	MaxURISize            string `yaml:"max_uri_size"`
	MaxBodySize           string `yaml:"max_body_size"`
	MaxHTTP2Streams       *int   `yaml:"max_http2_streams"`
	ResponseHeaderTimeout string `yaml:"response_header_timeout"`
	TCPIdleTimeout        string `yaml:"tcp_idle_timeout"`
	TCPConnsPerSource     *int   `yaml:"tcp_connections_per_source"`
}

// edgeConfig is fortress.yml.
type edgeConfig struct {
	ACME     string  `yaml:"acme"`
	ACMECA   string  `yaml:"acme_ca"`
	ClientCA string  `yaml:"client_ca"`
	NTP      servers `yaml:"ntp"`
	Renew    string  `yaml:"renew_interval"`
	QUIC     bool    `yaml:"quic"`
	Vault    string  `yaml:"vault"`
	VaultCA  string  `yaml:"vault_ca"`
	VMount   string  `yaml:"vault_mount"`
	VPath    string  `yaml:"vault_path"`
	VRole    string  `yaml:"vault_role_id"`
	VSecret  string  `yaml:"vault_secret_id"`
}

// policyConfig is policy.yml.
type policyConfig struct {
	Block     []string    `yaml:"block"`
	Exempt    []string    `yaml:"exempt"`
	Limits    *limitsYAML `yaml:"limits"`
	AccessLog bool        `yaml:"access_log"`
	// A size such as 8MiB; KiB, MiB, and GiB are the units.
	AccessLogMaxSize  string              `yaml:"access_log_max_size"`
	AccessLogMaxFiles int                 `yaml:"access_log_max_files"`
	Trace             *traceYAML          `yaml:"trace"`
	TunnelGrace       string              `yaml:"tunnel_grace"`
	TunnelDeadTimeout string              `yaml:"tunnel_dead_timeout"`
	Sites             map[string]siteYAML `yaml:"sites"`
}

type traceYAML struct {
	TrustIncoming bool `yaml:"trust_incoming"`
}

// siteYAML is one entry of policy.yml's sites. A key left out keeps the
// edge-wide setting.
type siteYAML struct {
	AccessLog             *bool  `yaml:"access_log"`
	MaxBodySize           string `yaml:"max_body_size"`
	ResponseHeaderTimeout string `yaml:"response_header_timeout"`
	TCPIdleTimeout        string `yaml:"tcp_idle_timeout"`
	TCPConnsPerSource     *int   `yaml:"tcp_connections_per_source"`
}

// The keys each file takes. A key in the other file's list is refused
// with a pointer to where it belongs.
var (
	edgeKeys = []string{"acme", "acme_ca", "client_ca", "ntp", "renew_interval", "quic",
		"vault", "vault_ca", "vault_mount", "vault_path", "vault_role_id", "vault_secret_id"}
	policyKeys = []string{"block", "exempt", "limits", "access_log", "access_log_max_size", "access_log_max_files",
		"trace", "sites", "tunnel_grace", "tunnel_dead_timeout"}
)

// EdgeKeys lists the keys fortress.yml takes.
func EdgeKeys() []string { return slices.Clone(edgeKeys) }

// InvalidError is a config that parsed but is not acceptable. Callers map
// it to HTTP 400; other errors are failures to store or apply.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string { return "config invalid: " + e.Err.Error() }
func (e *InvalidError) Unwrap() error { return e.Err }

type netDoc struct {
	Network   *netDoc            `yaml:"network"`
	Version   int                `yaml:"version"`
	Config    []netv1            `yaml:"config"`
	Ethernets map[string]netv2if `yaml:"ethernets"`
}

type netv1 struct {
	Type    string     `yaml:"type"`
	Name    string     `yaml:"name"`
	Subnets []netv1sub `yaml:"subnets"`
	// Address is a nameserver item's list of servers.
	Address []string `yaml:"address"`
}

type netv1sub struct {
	Type    string   `yaml:"type"`
	Address string   `yaml:"address"`
	Netmask string   `yaml:"netmask"`
	Gateway string   `yaml:"gateway"`
	DNS     []string `yaml:"dns_nameservers"`
}

type netv2if struct {
	Addresses   []string  `yaml:"addresses"`
	Gateway4    string    `yaml:"gateway4"`
	Nameservers netv2dns  `yaml:"nameservers"`
	Routes      []netv2rt `yaml:"routes"`
}

type netv2dns struct {
	Addresses []string `yaml:"addresses"`
}

type netv2rt struct {
	To  string `yaml:"to"`
	Via string `yaml:"via"`
}

// Parse reads the four parts. policy may be nil: an edge nobody has
// applied a policy to yet runs the defaults (no block list, DefaultLimits).
func Parse(userData, networkConfig, edge, policy []byte) (Config, error) {
	c := Config{Iface: "eth0", NTP: []string{DefaultNTP}, RenewInterval: DefaultRenewInterval}
	if err := applyEdge(&c, edge); err != nil {
		return Config{}, err
	}
	if err := applyUserData(&c, userData); err != nil {
		return Config{}, err
	}
	if err := applyNetwork(&c, networkConfig); err != nil {
		return Config{}, err
	}
	if !c.Addr.IsValid() {
		return Config{}, fmt.Errorf("network-config: static address is required")
	}
	if !c.Gateway.IsValid() {
		return Config{}, fmt.Errorf("network-config: gateway is required")
	}
	if len(c.DNS) == 0 {
		c.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	p, err := ParsePolicy(policy)
	if err != nil {
		return Config{}, err
	}
	c.Policy = p
	return c, nil
}

// CheckEdge validates fortress.yml on its own, as fortressctl bake does
// before it puts the file into an ISO.
func CheckEdge(edge []byte) error {
	var c Config
	return applyEdge(&c, edge)
}

// ParsePolicy reads policy.yml. Empty is the defaults.
func ParsePolicy(b []byte) (Policy, error) {
	p := Policy{
		Limits:            DefaultLimits(),
		AccessLog:         AccessLog{MaxSize: DefaultAccessLogMaxSize, MaxFiles: DefaultAccessLogMaxFiles},
		TunnelGrace:       DefaultTunnelGrace,
		TunnelDeadTimeout: DefaultTunnelDeadTimeout,
	}
	if err := checkKeys(b, PolicyName, policyKeys, edgeKeys,
		"belongs in "+EdgeFile+", which is baked into the ISO: bake a new one to change it"); err != nil {
		return Policy{}, err
	}
	var y policyConfig
	if err := yaml.Unmarshal(b, &y); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", PolicyName, err)
	}
	if err := checkNested(b, "trace", "sites"); err != nil {
		return Policy{}, err
	}
	var err error
	if p.Block, err = parsePrefixes(y.Block, PolicyName+": block"); err != nil {
		return Policy{}, err
	}
	if p.Exempt, err = parsePrefixes(y.Exempt, PolicyName+": exempt"); err != nil {
		return Policy{}, err
	}
	if err := applyLimits(&p.Limits, y.Limits); err != nil {
		return Policy{}, err
	}
	if err := applyAccessLog(&p.AccessLog, y); err != nil {
		return Policy{}, err
	}
	if y.Trace != nil {
		p.Trace.TrustIncoming = y.Trace.TrustIncoming
	}
	if s := strings.TrimSpace(y.TunnelGrace); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 || d > maxTunnelGrace {
			return Policy{}, fmt.Errorf("%s: tunnel_grace: want a duration from 0 (never) to 720h, such as 10m", PolicyName)
		}
		p.TunnelGrace = d
	}
	if s := strings.TrimSpace(y.TunnelDeadTimeout); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 || d > maxTunnelDeadTimeout || d%time.Second != 0 {
			return Policy{}, fmt.Errorf("%s: tunnel_dead_timeout: want whole seconds from 0 (off) to 10m, such as 3s", PolicyName)
		}
		p.TunnelDeadTimeout = d
	}
	if p.Sites, err = parseSites(y.Sites); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// parseSites reads policy.yml's sites. A key is a DNS name or a wildcard
// (*.example.com, or * for every name), as a dark node publishes them.
func parseSites(y map[string]siteYAML) (map[string]SitePolicy, error) {
	if len(y) == 0 {
		return nil, nil
	}
	out := make(map[string]SitePolicy, len(y))
	for _, key := range slices.Sorted(maps.Keys(y)) {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(key)), ".")
		if rest, ok := strings.CutPrefix(name, "*."); name != "*" && (ok && checkName(rest) != nil || !ok && checkName(name) != nil) {
			return nil, fmt.Errorf("%s: sites: %q: want a DNS name such as app.example.com, or a wildcard such as *.example.com", PolicyName, key)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s: sites: %q twice", PolicyName, name)
		}
		sy := y[key]
		sp := SitePolicy{AccessLog: sy.AccessLog}
		if s := strings.TrimSpace(sy.MaxBodySize); s != "" {
			n, err := parseBodySize(s)
			if err != nil {
				return nil, fmt.Errorf("%s: sites: %s: %w", PolicyName, name, err)
			}
			sp.MaxBodyBytes = &n
		}
		if s := strings.TrimSpace(sy.ResponseHeaderTimeout); s != "" {
			d, err := parseHeaderTimeout(s)
			if err != nil {
				return nil, fmt.Errorf("%s: sites: %s: %w", PolicyName, name, err)
			}
			sp.ResponseHeaderTimeout = d
		}
		if s := strings.TrimSpace(sy.TCPIdleTimeout); s != "" {
			d, err := parseIdleTimeout(s)
			if err != nil {
				return nil, fmt.Errorf("%s: sites: %s: %w", PolicyName, name, err)
			}
			sp.TCPIdleTimeout = &d
		}
		if v := sy.TCPConnsPerSource; v != nil {
			if *v < 0 {
				return nil, fmt.Errorf("%s: sites: %s: tcp_connections_per_source: want 0 (off) or more", PolicyName, name)
			}
			sp.TCPConnsPerSource = v
		}
		out[name] = sp
	}
	return out, nil
}

// checkKeys refuses a top-level key of doc that is not in known, and says
// where a key in other belongs instead.
func checkKeys(doc []byte, file string, known, other []string, elsewhere string) error {
	var m map[string]yaml.Node
	if err := yaml.Unmarshal(doc, &m); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		switch {
		case slices.Contains(known, k):
		case slices.Contains(other, k):
			return fmt.Errorf("%s: %s %s", file, k, elsewhere)
		default:
			return fmt.Errorf("%s: unknown key %q", file, k)
		}
	}
	return nil
}

// checkNested refuses a key the blocks named keys do not take, where a
// typo would otherwise be ignored. limits stays lenient: a stored policy
// with a key a newer edge dropped must still boot.
func checkNested(doc []byte, keys ...string) error {
	var m map[string]yaml.Node
	if err := yaml.Unmarshal(doc, &m); err != nil {
		return fmt.Errorf("%s: %w", PolicyName, err)
	}
	for _, k := range keys {
		n, ok := m[k]
		if !ok {
			continue
		}
		b, err := yaml.Marshal(&n)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", PolicyName, k, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		var out any = &traceYAML{}
		if k == "sites" {
			out = &map[string]siteYAML{}
		}
		if err := dec.Decode(out); err != nil {
			return fmt.Errorf("%s: %s: %w", PolicyName, k, err)
		}
	}
	return nil
}

// applyUserData takes fqdn from a cloud-config and nothing else: the
// platform writes the rest (hostname, users, keys) for guests that have
// a shell, and this one has none.
func applyUserData(c *Config, userData []byte) error {
	var ud struct {
		FQDN string `yaml:"fqdn"`
	}
	if err := yaml.Unmarshal(userData, &ud); err != nil {
		return fmt.Errorf("user-data: %w", err)
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ud.FQDN)), ".")
	if name == "" {
		return fmt.Errorf("user-data: fqdn is required: the edge's DNS name, such as edge1.example.com")
	}
	if err := checkName(name); err != nil {
		return fmt.Errorf("user-data: fqdn %q: %w; on Proxmox, name the VM edge1.example.com or give it a DNS domain", name, err)
	}
	c.Tunnel = name
	return nil
}

// checkName accepts a DNS name with a domain: two labels at least, and a
// last label that is not all digits. A bare hostname, which Proxmox
// writes as fqdn for a VM without a DNS domain, and an IP address are
// refused: the name is what dark nodes and operators ask for by SNI,
// which carries no address, and what the certificates are issued for.
func checkName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("longer than 253 characters")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("not a DNS name with a domain")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("label %q is not a DNS label", l)
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("label %q is not a DNS label", l)
			}
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return fmt.Errorf("an IP address, not a DNS name")
	}
	return nil
}

func applyEdge(c *Config, edge []byte) error {
	if len(edge) == 0 {
		return fmt.Errorf("%s: missing; bake one into the ISO with fortressctl bake", EdgeFile)
	}
	if err := checkKeys(edge, EdgeFile, edgeKeys, policyKeys,
		"is policy, which changes while the edge runs: put it in "+PolicyName+" and run fortressctl apply"); err != nil {
		return err
	}
	var e edgeConfig
	if err := yaml.Unmarshal(edge, &e); err != nil {
		return fmt.Errorf("%s: %w", EdgeFile, err)
	}
	if err := applyACME(c, e); err != nil {
		return err
	}
	c.QUIC = e.QUIC
	if err := applyNTP(c, e.NTP); err != nil {
		return err
	}
	if err := applyVault(c, e); err != nil {
		return err
	}
	pemText := strings.TrimSpace(e.ClientCA)
	if pemText == "" {
		return fmt.Errorf("%s: client_ca is required (fortressctl bake adds one)", EdgeFile)
	}
	if _, err := ca.ParseCAPEM([]byte(pemText)); err != nil {
		return fmt.Errorf("%s: client_ca: %w", EdgeFile, err)
	}
	c.ClientCA = []byte(pemText)
	return nil
}

var vaultPathRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)

// applyVault reads the vault keys: all of them but vault_ca, or none.
func applyVault(c *Config, e edgeConfig) error {
	v := Vault{
		URL: strings.TrimSpace(e.Vault), Mount: strings.Trim(strings.TrimSpace(e.VMount), "/"),
		Path: strings.Trim(strings.TrimSpace(e.VPath), "/"), RoleID: strings.TrimSpace(e.VRole), SecretID: strings.TrimSpace(e.VSecret),
	}
	ca := strings.TrimSpace(e.VaultCA)
	if v.URL == "" && v.Mount == "" && v.Path == "" && v.RoleID == "" && v.SecretID == "" && ca == "" {
		return nil
	}
	u, err := url.Parse(v.URL)
	if v.URL == "" || err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil {
		return fmt.Errorf("%s: vault: want the https URL of the Vault server, such as https://vault.example.com:8200", EdgeFile)
	}
	v.URL = u.Scheme + "://" + u.Host
	for _, k := range []struct{ key, val string }{{"vault_mount", v.Mount}, {"vault_path", v.Path}} {
		if !vaultPathRegex.MatchString(k.val) || slices.Contains(strings.Split(k.val, "/"), "..") {
			return fmt.Errorf("%s: %s: want a KV v2 path such as edge-certs or prod/public", EdgeFile, k.key)
		}
	}
	if v.RoleID == "" || v.SecretID == "" {
		return fmt.Errorf("%s: vault_role_id and vault_secret_id: the AppRole the edge logs in with is required", EdgeFile)
	}
	if ca != "" {
		if _, err := pemCerts([]byte(ca)); err != nil {
			return fmt.Errorf("%s: vault_ca: %w", EdgeFile, err)
		}
		v.CA = []byte(ca)
	}
	c.Vault = &v
	return nil
}

// pemCerts parses one or more PEM certificates.
func pemCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("want PEM certificates, got %s", blk.Type)
		}
		crt, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, crt)
	}
	if len(out) == 0 || len(strings.TrimSpace(string(b))) > 0 {
		return nil, errors.New("want PEM certificates")
	}
	return out, nil
}

// servers is fortress.yml's ntp: one server, or a list of them.
type servers []string

func (s *servers) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = servers{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return fmt.Errorf("ntp: want a server or a list of servers")
	}
	*s = list
	return nil
}

// maxNTP bounds the ntp list: every poll asks each server.
const maxNTP = 8

func applyNTP(c *Config, list servers) error {
	var out []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host := s
		if h, port, err := net.SplitHostPort(s); err == nil {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("%s: ntp: %q: want host or host:port", EdgeFile, s)
			}
			host = h
		}
		if net.ParseIP(host) == nil && checkName(strings.ToLower(strings.TrimSuffix(host, "."))) != nil {
			return fmt.Errorf("%s: ntp: %q: want a DNS name or an address, with :port if not 123", EdgeFile, s)
		}
		if slices.Contains(out, s) {
			return fmt.Errorf("%s: ntp: %q twice", EdgeFile, s)
		}
		out = append(out, s)
	}
	if len(out) > maxNTP {
		return fmt.Errorf("%s: ntp: at most %d servers", EdgeFile, maxNTP)
	}
	if len(out) > 0 {
		c.NTP = out
	}
	return nil
}

func applyACME(c *Config, e edgeConfig) error {
	if s := strings.TrimSpace(e.ACME); s != "" {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s: acme: want http(s) directory URL", EdgeFile)
		}
		c.ACME = u.String()
	}
	if pemText := strings.TrimSpace(e.ACMECA); pemText != "" {
		if _, err := ca.ParseCertPEM([]byte(pemText)); err != nil {
			return fmt.Errorf("%s: acme_ca: %w", EdgeFile, err)
		}
		c.ACMECA = []byte(pemText)
	}
	if s := strings.TrimSpace(e.Renew); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 100*time.Millisecond {
			return fmt.Errorf("%s: renew_interval: want a duration of at least 100ms, such as 4h", EdgeFile)
		}
		c.RenewInterval = d
	}
	return nil
}

func applyAccessLog(a *AccessLog, y policyConfig) error {
	a.On = y.AccessLog
	if s := strings.TrimSpace(y.AccessLogMaxSize); s != "" {
		n, err := parseSize(s)
		if err != nil || n < 1<<20 {
			return fmt.Errorf("%s: access_log_max_size: want a size of at least 1MiB, such as 8MiB", PolicyName)
		}
		a.MaxSize = n
	}
	if n := y.AccessLogMaxFiles; n != 0 {
		if n < 1 || n > 1000 {
			return fmt.Errorf("%s: access_log_max_files: want 1 to 1000", PolicyName)
		}
		a.MaxFiles = n
	}
	return nil
}

func applyLimits(l *Limits, y *limitsYAML) error {
	if y == nil {
		return nil
	}
	count := func(dst *int, v *int, key string) error {
		if v == nil {
			return nil
		}
		if *v < 0 {
			return fmt.Errorf("%s: limits: %s: want 0 (off) or more", PolicyName, key)
		}
		*dst = *v
		return nil
	}
	for _, f := range []struct {
		dst *int
		v   *int
		key string
	}{
		{&l.ConnsPerSource, y.ConnsPerSource, "connections_per_source"},
		{&l.RequestsPerSecond, y.RequestsPerSecond, "requests_per_second"},
		{&l.RequestBurst, y.RequestBurst, "request_burst"},
		{&l.NewConnsPerSecond, y.NewConnsPerSecond, "new_connections_per_second"},
		{&l.NewConnBurst, y.NewConnBurst, "new_connection_burst"},
		{&l.MaxConns, y.MaxConns, "max_connections"},
		{&l.TCPConnsPerSource, y.TCPConnsPerSource, "tcp_connections_per_source"},
	} {
		if err := count(f.dst, f.v, f.key); err != nil {
			return err
		}
	}
	if l.RequestsPerSecond > 0 && l.RequestBurst < 1 {
		return fmt.Errorf("%s: limits: request_burst: want at least 1 while requests_per_second is on", PolicyName)
	}
	if l.NewConnsPerSecond > 0 && l.NewConnBurst < 1 {
		return fmt.Errorf("%s: limits: new_connection_burst: want at least 1 while new_connections_per_second is on", PolicyName)
	}
	if s := strings.TrimSpace(y.Ban); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return fmt.Errorf("%s: limits: ban: want a duration such as 15m, or 0 to never ban", PolicyName)
		}
		l.Ban = d
	}
	if v := y.BanAfter; v != nil {
		if *v < 1 {
			return fmt.Errorf("%s: limits: ban_after: want at least 1 (ban: 0 turns bans off)", PolicyName)
		}
		l.BanAfter = *v
	}
	if s := strings.TrimSpace(y.BanWindow); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < time.Second {
			return fmt.Errorf("%s: limits: ban_window: want a duration of at least 1s, such as 10s", PolicyName)
		}
		l.BanWindow = d
	}
	for _, f := range []struct {
		dst      *int
		raw, key string
		min      int64
	}{
		{&l.MaxHeaderBytes, y.MaxHeaderSize, "max_header_size", 4 << 10},
		{&l.MaxURIBytes, y.MaxURISize, "max_uri_size", 1 << 10},
	} {
		if s := strings.TrimSpace(f.raw); s != "" {
			n, err := parseSize(s)
			if err != nil || n < f.min || n > 1<<30 {
				return fmt.Errorf("%s: limits: %s: want a size of %dKiB to 1GiB, such as 64KiB", PolicyName, f.key, f.min>>10)
			}
			*f.dst = int(n)
		}
	}
	if s := strings.TrimSpace(y.MaxBodySize); s != "" {
		n, err := parseBodySize(s)
		if err != nil {
			return fmt.Errorf("%s: limits: %w", PolicyName, err)
		}
		l.MaxBodyBytes = n
	}
	if v := y.MaxHTTP2Streams; v != nil {
		if *v < 1 || *v > 10000 {
			return fmt.Errorf("%s: limits: max_http2_streams: want 1 to 10000", PolicyName)
		}
		l.MaxHTTP2Streams = *v
	}
	if s := strings.TrimSpace(y.ResponseHeaderTimeout); s != "" {
		d, err := parseHeaderTimeout(s)
		if err != nil {
			return fmt.Errorf("%s: limits: %w", PolicyName, err)
		}
		l.ResponseHeaderTimeout = d
	}
	if s := strings.TrimSpace(y.TCPIdleTimeout); s != "" {
		d, err := parseIdleTimeout(s)
		if err != nil {
			return fmt.Errorf("%s: limits: %w", PolicyName, err)
		}
		l.TCPIdleTimeout = d
	}
	return nil
}

// parseIdleTimeout reads tcp_idle_timeout.
func parseIdleTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d > 7*24*time.Hour || d > 0 && d < time.Second {
		return 0, fmt.Errorf("tcp_idle_timeout: want a duration from 1s to 168h, such as 8h, or 0 for never")
	}
	return d, nil
}

// parseBodySize reads max_body_size: a size, or 0 for no limit.
func parseBodySize(s string) (int64, error) {
	if s == "0" {
		return 0, nil
	}
	n, err := parseSize(s)
	if err != nil || n < 1<<10 {
		return 0, fmt.Errorf("max_body_size: want a size of at least 1KiB, such as 512MiB, or 0 for no limit")
	}
	return n, nil
}

// parseHeaderTimeout reads response_header_timeout.
func parseHeaderTimeout(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Second || d > 10*time.Minute || d%time.Second != 0 {
		return 0, fmt.Errorf("response_header_timeout: want whole seconds from 1s to 10m, such as 60s")
	}
	return d, nil
}

// parseSize reads a whole number with a KiB, MiB, or GiB suffix.
func parseSize(s string) (int64, error) {
	for suffix, shift := range map[string]uint{"KiB": 10, "MiB": 20, "GiB": 30} {
		if num, ok := strings.CutSuffix(s, suffix); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
			if err != nil || n < 0 || n > 1<<(62-shift) {
				return 0, fmt.Errorf("size %q", s)
			}
			return n << shift, nil
		}
	}
	return 0, fmt.Errorf("size %q: want KiB, MiB, or GiB", s)
}

func applyNetwork(c *Config, raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("network-config: missing")
	}
	var doc netDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("network-config: %w", err)
	}
	if doc.Network != nil {
		doc = *doc.Network
	}
	switch doc.Version {
	case 1:
		return applyNetv1(c, doc.Config)
	case 2:
		return applyNetv2(c, doc.Ethernets)
	default:
		return fmt.Errorf("network-config: version %d not supported", doc.Version)
	}
}

// applyNetv1 takes the first static address of a physical item. DNS
// servers are that subnet's dns_nameservers, or else a nameserver item's:
// Proxmox writes them there, from the VM's DNS settings or the host's.
func applyNetv1(c *Config, items []netv1) error {
	for _, it := range items {
		if it.Type != "nameserver" || len(c.DNS) > 0 {
			continue
		}
		dns, err := parseAddrs(it.Address, "network-config: nameserver")
		if err != nil {
			return err
		}
		c.DNS = dns
	}
	for _, it := range items {
		if it.Type != "physical" {
			continue
		}
		for _, s := range it.Subnets {
			if s.Type != "" && s.Type != "static" {
				continue
			}
			p, err := prefixFrom(s.Address, s.Netmask)
			if err != nil {
				return fmt.Errorf("network-config: %w", err)
			}
			if it.Name != "" {
				c.Iface = it.Name
			}
			c.Addr = p
			if s.Gateway != "" {
				gw, err := netip.ParseAddr(s.Gateway)
				if err != nil {
					return fmt.Errorf("network-config: gateway: %w", err)
				}
				c.Gateway = gw
			}
			dns, err := parseAddrs(s.DNS, "network-config: dns")
			if err != nil {
				return err
			}
			if len(dns) > 0 {
				c.DNS = dns
			}
			return nil
		}
	}
	return fmt.Errorf("network-config: no static physical address")
}

func applyNetv2(c *Config, ifaces map[string]netv2if) error {
	// Sorted so a multi-ethernet config picks the same iface every boot.
	for _, name := range slices.Sorted(maps.Keys(ifaces)) {
		it := ifaces[name]
		if len(it.Addresses) == 0 {
			continue
		}
		p, err := prefixFrom(it.Addresses[0], "")
		if err != nil {
			return fmt.Errorf("network-config: %w", err)
		}
		c.Iface = name
		c.Addr = p
		gw := it.Gateway4
		if gw == "" {
			for _, r := range it.Routes {
				if r.To == "default" || r.To == "0.0.0.0/0" {
					gw = r.Via
					break
				}
			}
		}
		if gw != "" {
			a, err := netip.ParseAddr(gw)
			if err != nil {
				return fmt.Errorf("network-config: gateway: %w", err)
			}
			c.Gateway = a
		}
		dns, err := parseAddrs(it.Nameservers.Addresses, "network-config: dns")
		if err != nil {
			return err
		}
		c.DNS = dns
		return nil
	}
	return fmt.Errorf("network-config: no static ethernet address")
}

func prefixFrom(addr, netmask string) (netip.Prefix, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return netip.Prefix{}, fmt.Errorf("empty address")
	}
	if strings.Contains(addr, "/") {
		return netip.ParsePrefix(addr)
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, err
	}
	if netmask == "" {
		return netip.PrefixFrom(a, 24), nil
	}
	ip := net.ParseIP(netmask).To4()
	if ip == nil {
		return netip.Prefix{}, fmt.Errorf("netmask %s", netmask)
	}
	ones, _ := net.IPMask(ip).Size()
	return netip.PrefixFrom(a, ones), nil
}

func parseAddrs(vals []string, key string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range vals {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func parsePrefixes(vals []string, key string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range vals {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
