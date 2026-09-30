module github.com/Sebiee/fortressedge/test/e2e

go 1.27.0

require (
	github.com/Sebiee/fortressedge v0.0.0
	github.com/digitalocean/go-qemu v0.0.0-20250212194115-ee9b0668d242
	github.com/fatedier/frp v0.71.0
	github.com/fatedier/golib v0.8.2
	github.com/letsencrypt/challtestsrv v1.4.2
	github.com/letsencrypt/pebble/v2 v2.10.1
	github.com/quic-go/quic-go v0.63.0
	github.com/stretchr/testify v1.12.1
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	golang.org/x/time v0.16.0
)

require (
	github.com/Azure/go-ntlmssp v0.1.0 // indirect
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5 // indirect
	github.com/bitfield/gotestdox v0.2.2 // indirect
	github.com/coreos/go-oidc/v3 v3.18.0 // indirect
	github.com/digitalocean/go-libvirt v0.0.0-20220804181439-8648fbde413e // indirect
	github.com/diskfs/go-diskfs v1.9.4 // indirect
	github.com/djherbis/times v1.6.0 // indirect
	github.com/dnephin/pflag v1.0.7 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pelletier/go-toml/v2 v2.2.0 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/samber/lo v1.47.0 // indirect
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/templexxx/cpu v0.1.1 // indirect
	github.com/templexxx/xorsimd v0.4.3 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.13 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/gotestsum v1.13.0 // indirect
	k8s.io/apimachinery v0.37.0 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/utils v0.0.0-20260626114624-be93311217bd // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

// The system tests drive the edge from this repository.
replace github.com/Sebiee/fortressedge => ../..

// Keep these two replaces identical in every module of this repository;
// `make tidy` checks. frp v0.71.0 ships this yamux fork, and a replace
// is not inherited from a dependency.
replace github.com/hashicorp/yamux => github.com/fatedier/yamux v0.0.0-20250825093530-d0154be01cd6

// The frp fork: a separate QUIC bind address, handshake certificate
// reload, plaintext control beside a client CA, preserved X-Forwarded-*
// headers, the OnDomain callback, 502 for a down origin, a
// client-certificate VerifyConnection hook, and a site proxy the edge
// calls in-process that uses work connections on the request's goroutine.
replace github.com/fatedier/frp => github.com/Sebiee/frp v0.71.1-0.20260930163047-d05d30dbd0f2

tool gotest.tools/gotestsum
