#!/bin/sh
# Configure the three-VM lab from a workstation that can ssh to the dark
# node and the loadgen. The edge is fortressedge: it has no shell, so this
# writes what it boots from instead of logging in.
#
#   EDGE=192.0.2.10 DARK=root@192.0.2.20 LOAD=root@192.0.2.30 TLS=out/tls \
#   ACME=https://ca.lab:9000/acme/acme/directory ROOTS=root.crt \
#   ISO=out/fortressedge.iso test/perf/vms.sh
#
# EDGE is the edge's IPv4 address. DARK and LOAD are ssh destinations.
# TLS is a fortressctl ca directory (ca.crt, clients/node/node1.crt,
# clients/node/node1.key). ACME is a directory the edge reaches, which
# can validate tunnel.example.com and a, b, c.example.com at EDGE (lab
# DNS); ROOTS is the root its certificates chain to, which frpc and the
# loadgen trust. Optional: ACME_CA (the directory's own TLS root, when the
# system roots do not cover it), ISO (the release ISO to bake), GATEWAY
# (default .1 of EDGE), PREFIX (default 24), IFACE (eth0), QUIC=1,
# LOAD_IP (default: LOAD's host), which the policy exempts from the
# per-source limits: all load comes from that one address.
set -eu
cd "$(dirname "$0")/../.."

edge=${EDGE:?set EDGE to the fortressedge IPv4 address}
dark=${DARK:?set DARK to the dark-node ssh destination (user@host)}
load=${LOAD:?set LOAD to the loadgen ssh destination (user@host)}
tls=${TLS:?set TLS to the fortressctl ca directory}
acme=${ACME:?set ACME to an ACME directory URL the edge reaches}
roots=${ROOTS:?set ROOTS to the root the ACME server issues under}
prefix=${PREFIX:-24}
iface=${IFACE:-eth0}
quic=false
[ "${QUIC:-}" = 1 ] && quic=true
load_ip=${LOAD_IP:-${load#*@}}

case $edge in
*.*.*.*) ;;
*) echo "EDGE must be an IPv4 address" >&2; exit 1 ;;
esac
gateway=${GATEWAY:-$(printf '%s\n' "$edge" | awk -F. '{print $1"."$2"."$3".1"}')}

for f in ca.crt clients/node/node1.crt clients/node/node1.key; do
	if ! [ -f "$tls/$f" ]; then
		echo "missing $tls/$f" >&2
		echo "  fortressctl ca init $tls" >&2
		echo "  fortressctl ca client $tls spiffe://tunnel.example.com/node/node1" >&2
		exit 1
	fi
done

lab=test/perf/lab
mkdir -p "$lab"
# The edge's NoCloud drive: what Proxmox writes for a VM named
# tunnel.example.com (or tunnel with DNS domain example.com) and this
# ipconfig0.
cat >"$lab/user-data" <<EOF
#cloud-config
fqdn: tunnel.example.com
EOF
cat >"$lab/network-config" <<EOF
version: 1
config:
  - type: physical
    name: $iface
    subnets:
      - type: static
        address: $edge/$prefix
        gateway: $gateway
        dns_nameservers: [1.1.1.1]
EOF
{
	printf 'quic: %s\nacme: %s\n' "$quic" "$acme"
	if [ -n "${ACME_CA:-}" ]; then
		printf 'acme_ca: |\n'
		sed 's/^/  /' "$ACME_CA"
	fi
	printf 'client_ca: |\n'
	sed 's/^/  /' "$tls/ca.crt"
} >"$lab/fortress.yml"
printf 'exempt: [%s]\n' "$load_ip" >"$lab/policy.yml"
if [ -n "${ISO:-}" ]; then
	go run ./cmd/fortressctl bake -o "$lab/edge.iso" -c "$lab/fortress.yml" "$ISO"
fi

# shellcheck disable=SC2086
remote() { ssh ${SSH_OPTS:-} "$@"; }
# shellcheck disable=SC2086
send() { scp ${SSH_OPTS:-} "$@"; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/tls"
cp "$roots" "$stage/tls/ca.crt"
cp "$tls/clients/node/node1.crt" "$stage/tls/node1.crt"
cp "$tls/clients/node/node1.key" "$stage/tls/node1.key"
chmod 600 "$stage/tls/node1.key"

cat >"$stage/origin.py" <<'EOF'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

body = sys.argv[1].encode()
port = int(sys.argv[2])

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
EOF

cat >"$stage/frpc.toml" <<EOF
serverAddr = "$edge"
serverPort = 443
transport.protocol = "wss"
transport.wireProtocol = "v2"
transport.tls.certFile = "tls/node1.crt"
transport.tls.keyFile = "tls/node1.key"
transport.tls.trustedCaFile = "tls/ca.crt"
transport.tls.serverName = "tunnel.example.com"
loginFailExit = false

[[proxies]]
name = "a"
type = "http"
localIP = "127.0.0.1"
localPort = 18081
customDomains = ["a.example.com"]

[[proxies]]
name = "b"
type = "http"
localIP = "127.0.0.1"
localPort = 18082
customDomains = ["b.example.com"]

[[proxies]]
name = "c"
type = "http"
localIP = "127.0.0.1"
localPort = 18083
customDomains = ["c.example.com"]
EOF

cat >"$stage/start.sh" <<'EOF'
#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 || { echo "need python3" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
mkdir -p bin run
if ! [ -x bin/frpc ]; then
	arch=$(uname -m)
	case "$arch" in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "unsupported arch $arch" >&2; exit 1 ;;
	esac
	ver=0.71.0
	url=https://github.com/fatedier/frp/releases/download/v${ver}
	asset=frp_${ver}_linux_${arch}.tar.gz
	curl -fsSL "$url/$asset" | tar -xz --strip-components=1 -C bin "frp_${ver}_linux_${arch}/frpc"
	chmod +x bin/frpc
fi
if [ -f run/pids ]; then
	while read -r p; do
		kill "$p" 2>/dev/null || true
	done < run/pids
	rm -f run/pids
fi
start() {
	name=$1
	shift
	nohup "$@" </dev/null >>"run/$name.log" 2>&1 &
	echo $! >> run/pids
	echo "$name pid $!"
}
start origin-a python3 origin.py origin-a 18081
start origin-b python3 origin.py origin-b 18082
start origin-c python3 origin.py origin-c 18083
start frpc bin/frpc -c frpc.toml
EOF
chmod +x "$stage/start.sh"

echo "== dark node $dark"
tar -C "$stage" -cf - . | remote "$dark" 'mkdir -p ~/fortress-e2e && tar -C ~/fortress-e2e -xf - && sh ~/fortress-e2e/start.sh'

echo "== loadgen $load"
remote "$load" 'mkdir -p ~/fortress-e2e'
cp "$roots" "$stage/roots.crt"
send test/perf/loadgen.sh "$stage/roots.crt" "$load:fortress-e2e/"

echo
echo "Edge has no ssh. Boot $lab/edge.iso (fortressctl bake -c $lab/fortress.yml,"
echo "when ISO was not set) with a blank data disk and a NoCloud drive holding"
echo "$lab/user-data and $lab/network-config. Once it is up, as an operator:"
echo "  fortressctl ca client $tls spiffe://tunnel.example.com/ops/admin"
echo "  fortressctl apply tunnel.example.com -f $lab/policy.yml --connect $edge:443 \\"
echo "    --cert $tls/clients/ops/admin.crt --key $tls/clients/ops/admin.key --cacert $roots"
echo
echo "Loadgen, once the edge is up:"
echo "  ssh $load 'EDGE=$edge CA=\$HOME/fortress-e2e/roots.crt \$HOME/fortress-e2e/loadgen.sh'"
