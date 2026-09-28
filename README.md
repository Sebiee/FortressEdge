# FortressEdge

FortressEdge is a small, locked-down edge for a public VM. It serves your
websites from nodes that stay unreachable from the internet ("dark"
nodes): they dial out to the edge, and the edge terminates HTTPS for them.

It boots from an ISO: an Alpine kernel with `fortressedge` as PID 1. There
is no shell and no sshd. It is built on [frp](https://github.com/fatedier/frp)
for the tunnel and [CertMagic](https://github.com/caddyserver/certmagic)
for ACME certificates.

```
Internet  --TCP 80-->   308 redirect to HTTPS
Internet  --TCP 443-->  TLS, then the dark node that publishes that hostname
Dark node --TCP 443-->  frp over WebSocket, with a client certificate
```

- **Certificates.** The edge gets one certificate per hostname, as soon as
  a dark node publishes it, from Let's Encrypt or any ACME directory, such
  as step-ca or Vault. A timer renews them every `renew_interval`
  (default 4h). The edge holds no other private key.
- **Mutual TLS, with roles.** Dark nodes, operators, and log shippers
  authenticate with client certificates from your CA. A certificate's
  SPIFFE ID says what it may do: join the tunnel (`node`), manage the edge
  (`ops`), or read its logs (`logs`). The edge holds the CA's certificate,
  never its key, and signs nothing.
- **Invisible to strangers.** Only published hostnames and the tunnel name
  are answered. A scan of the address, or a request for any other name,
  gets no bytes back: no certificate, no error page, no version.
- **XDP filter.** Inbound traffic other than HTTP and HTTPS, and replies to
  the edge's own connections, is dropped in the kernel's fast path, with
  SYN rate limits and an address block list.
- **Visitor limits.** Each source address (IPv6: its /64) gets a fair
  share: capped connections and request rate, and a 15-minute XDP ban
  when it keeps pushing past them. Malformed and ambiguous requests are
  refused before they reach a site. Details in
  [docs/operations.md](docs/operations.md#limits).

## How an edge is configured

| Part | Holds | Comes from |
| --- | --- | --- |
| `fortress.yml` | whom the edge trusts: your client CA, the ACME server and its CA | baked into the release ISO (`fortressctl bake`, or the Terraform provider) |
| `fqdn` and address | the edge's DNS name and static address | the machine's cloud-init (NoCloud) drive: `user-data` and `network-config` |
| `policy.yml` | who may reach the edge and how much: block list, limits | `fortressctl apply`, while the edge runs |

None of them holds a secret, and one ISO serves every edge that shares a
`fortress.yml`. There is no other way in: no shell, no config upload. An
edge whose config is missing or wrong says why on its console. Details in
[docs/provisioning.md](docs/provisioning.md).

## Quick start: local

One edge in QEMU, with [Pebble](https://github.com/letsencrypt/pebble), a
test ACME server, for its certificates, and a site on this machine
published through it. You need `qemu-system-x86_64`, Docker, `openssl`,
and `cloud-localds` (Debian and Ubuntu: `cloud-image-utils`).

```sh
v=v0.1.0
base=https://github.com/Sebiee/fortressedge/releases/download/$v
wget -O fortressedge.iso "$base/fortressedge-$v.iso"
wget -O fortressctl "$base/fortressctl-$v-linux-amd64" && chmod +x fortressctl

# The client CA, an operator certificate, and a dark node's.
./fortressctl ca init tls
./fortressctl ca client tls spiffe://edge1.example.com/ops/admin
./fortressctl ca client tls spiffe://edge1.example.com/node/node1

# Pebble, at 10.0.2.2:14000 as the VM sees it, issuing without validation.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=pebble -addext subjectAltName=IP:10.0.2.2,IP:127.0.0.1 \
  -keyout pebble.key -out pebble.crt
cat > pebble.json <<'EOF'
{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/work/pebble.crt", "privateKey": "/work/pebble.key",
  "httpPort": 80, "tlsPort": 443}}
EOF
docker run -d --name pebble -p 14000:14000 -p 15000:15000 -v "$PWD:/work:ro" \
  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 \
  ghcr.io/letsencrypt/pebble -config /work/pebble.json

# fortress.yml, baked into a copy of the ISO.
{
  echo 'acme: https://10.0.2.2:14000/dir'
  echo 'acme_ca: |'; sed 's/^/  /' pebble.crt
  echo 'client_ca: |'; sed 's/^/  /' tls/ca.crt
} > fortress.yml
./fortressctl bake -o edge.iso -c fortress.yml fortressedge.iso

# The cloud-init drive: the edge's name and address.
printf '#cloud-config\nfqdn: edge1.example.com\n' > user-data
cat > network-config <<'EOF'
version: 2
ethernets:
  eth0:
    addresses: [10.0.2.15/24]
    gateway4: 10.0.2.2
    nameservers:
      addresses: [10.0.2.3]
EOF
cloud-localds --network-config=network-config seed.iso user-data
truncate -s 64M data.img

qemu-system-x86_64 -nographic -m 512 -boot order=d \
  -drive file=data.img,format=raw,if=virtio \
  -drive file=edge.iso,media=cdrom,readonly=on,if=ide,index=0 \
  -drive file=seed.iso,media=cdrom,readonly=on,if=ide,index=1 \
  $([ -w /dev/kvm ] && echo -accel kvm -cpu host) \
  -netdev user,id=n0,hostfwd=tcp::8080-:80,hostfwd=tcp::8443-:443 \
  -device virtio-net-pci,netdev=n0
```

From another terminal, the ops API, with Pebble's root to check the
edge's certificate:

```sh
curl -sk https://localhost:15000/roots/0 > acme-root.pem
curl --cacert acme-root.pem --cert tls/clients/ops/admin.crt --key tls/clients/ops/admin.key \
  --resolve edge1.example.com:8443:127.0.0.1 'https://edge1.example.com:8443/~!ops/status'
```

A site: frpc 0.71 ([releases](https://github.com/fatedier/frp/releases))
publishes `app.example.com` from a server on port 8000.

```sh
cat > frpc.toml <<'EOF'
serverAddr = "127.0.0.1"
serverPort = 8443
transport.protocol = "wss"
transport.wireProtocol = "v2"
transport.tls.certFile = "tls/clients/node/node1.crt"
transport.tls.keyFile = "tls/clients/node/node1.key"
transport.tls.trustedCaFile = "acme-root.pem"
transport.tls.serverName = "edge1.example.com"

[[proxies]]
name = "app"
type = "http"
localPort = 8000
customDomains = ["app.example.com"]
EOF
python3 -m http.server 8000 &
frpc -c frpc.toml &
curl --cacert acme-root.pem --resolve app.example.com:8443:127.0.0.1 https://app.example.com:8443/
```

## Quick start: Terraform

An edge on Proxmox, with the
[FortressEdge provider](https://registry.terraform.io/providers/sebiee/fortressedge)
baking the ISO where Terraform runs and
[bpg/proxmox](https://registry.terraform.io/providers/bpg/proxmox)
creating the VM. The edge gets its certificates from Let's Encrypt here:
give it a public address, open TCP 80 and 443, and point
`edge1.example.com` at the address before the first boot.

```sh
fortressctl ca init tls                    # tls/ca.key stays with you
{ echo 'client_ca: |'; sed 's/^/  /' tls/ca.crt; } > fortress.yml
```

```terraform
terraform {
  required_providers {
    fortressedge = { source = "sebiee/fortressedge" }
    proxmox      = { source = "bpg/proxmox" }
  }
}

data "fortressedge_iso" "edge" {
  release_url    = "https://github.com/Sebiee/fortressedge/releases/download/v0.1.0/fortressedge-v0.1.0.iso"
  release_sha256 = "…" # from the release's SHA256SUMS
  config         = file("${path.module}/fortress.yml")
}

resource "proxmox_virtual_environment_file" "edge_iso" {
  node_name    = "pve"
  datastore_id = "local"
  content_type = "iso"
  source_file {
    path      = data.fortressedge_iso.edge.path
    file_name = data.fortressedge_iso.edge.file_name
    checksum  = data.fortressedge_iso.edge.sha256
  }
}

resource "proxmox_virtual_environment_vm" "edge1" {
  node_name  = "pve"
  name       = "edge1"
  boot_order = ["ide0"]
  memory { dedicated = 1024 }
  cdrom {
    file_id   = proxmox_virtual_environment_file.edge_iso.id
    interface = "ide0"
  }
  disk {
    datastore_id = "local-lvm"
    interface    = "virtio0"
    size         = 1
  }
  network_device { bridge = "vmbr0" }
  initialization { # the cloud-init drive: fqdn edge1.example.com, and the address
    datastore_id = "local-lvm"
    interface    = "ide2"
    dns {
      domain  = "example.com"
      servers = ["1.1.1.1"]
    }
    ip_config {
      ipv4 {
        address = "203.0.113.10/24"
        gateway = "203.0.113.1"
      }
    }
  }
}
```

Then `terraform init` and `terraform apply`. For an internal ACME server, add `acme` and
`acme_ca` to `fortress.yml`; see [docs/provisioning.md](docs/provisioning.md).
A policy, once the edge is up:

```sh
fortressctl ca client tls spiffe://edge1.example.com/ops/admin
fortressctl apply edge1.example.com -f policy.yml \
  --cert tls/clients/ops/admin.crt --key tls/clients/ops/admin.key
```

## Configuration

`fortress.yml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `client_ca` | required | PEM CA that signs the dark-node, operator, and log-reader certificates |
| `acme` | Let's Encrypt | ACME directory URL |
| `acme_ca` | system roots | PEM CA that signed that directory's HTTPS certificate |
| `renew_interval` | `4h` | How often ACME certificates are checked and renewed once due |
| `ntp` | `pool.ntp.org` | Time source for the boot clock sync, `host` or `host:port` |
| `quic` | `false` | Dark nodes may also connect over QUIC on UDP 443 |
| `access_log` | `false` | One JSON line per site request, served at `/~!ops/access` |
| `access_log_max_size` | `8MiB` | Size at which the access log starts a new file (`KiB`, `MiB`, `GiB`) |
| `access_log_max_files` | `3` | Access log files kept, the current one included; the oldest is deleted |

The cloud-init drive: `fqdn` in `user-data`, a DNS name with a domain,
which is the tunnel name dark nodes and operators connect to; and a
static address and gateway in `network-config` (v1 or v2). Nothing else
in `user-data` is read.

`policy.yml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `block` | none | Addresses or CIDRs dropped in XDP |
| `exempt` | none | Addresses or CIDRs the visitor limits and bans skip, such as a monitoring probe |
| `limits` | see [operations](docs/operations.md#limits) | Per-source connection, request, and SYN rates, the ban length, header and URI sizes, and how long an origin may take to answer; `0` turns one off |

`block`, `exempt`, and most `limits` apply at once; four limits reboot
the edge. Certificates and trust are in [docs/certificates.md](docs/certificates.md).

## Dark nodes

A dark node runs frpc 0.71 with a client certificate from the client CA:

```toml
serverAddr = "edge1.example.com"
serverPort = 443
transport.protocol = "wss"
transport.wireProtocol = "v2"
transport.tls.certFile = "node1.crt"
transport.tls.keyFile = "node1.key"
transport.tls.trustedCaFile = "/etc/ssl/certs/ca-certificates.crt"
transport.tls.serverName = "edge1.example.com"

[[proxies]]
name = "app"
type = "http"
localPort = 8080
customDomains = ["app.example.com"]
```

The frp token is empty on both sides; the client certificate is the
credential. `trustedCaFile` is what the edge's certificates chain to: the
system roots for Let's Encrypt, or an internal ACME server's root. Set it
for stock frpc, which does not check the edge's certificate without it.
`fortresskube` checks against the system roots when it is not set, and
skips the check only with `transport.tls.insecureSkipVerify = true`. For Kubernetes, `fortresskube`
publishes every HTTPRoute a Gateway accepts: see
[docs/kubernetes.md](docs/kubernetes.md).

## Operations

Operators use a small HTTPS API on the tunnel name: status, logs (live,
or with resumable cursors for shippers), and the policy. An operator
certificate (`ops/<name>`) may do all of it; a log-reader certificate
(`logs/<name>`) may only read, so a log host never holds a key that can
change the edge. The VGA and serial consoles show a status grid and the
log. See [docs/operations.md](docs/operations.md).

## Development

`make build`, `make test`, `make e2e` (edges booted in QEMU), `make ci`.
See [docs/development.md](docs/development.md) for the layout, the test
suites, and releases. Changes are in [CHANGELOG.md](CHANGELOG.md), and
planned work in [docs/roadmap.md](docs/roadmap.md).

## License

MIT. `bpf/` is dual MIT/GPL.
