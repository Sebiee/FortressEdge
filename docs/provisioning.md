# Provisioning

An edge's config has three parts, and each has one owner:

| Part | Holds | Comes from | Changes by |
| --- | --- | --- | --- |
| `fortress.yml` | whom the edge trusts and how it runs: the ACME server and its CA, the client CA, NTP, QUIC | the ISO, baked with `fortressctl bake` | a new ISO and a restart |
| `fqdn` and address | the edge's DNS name and static address, and with Vault its own secret ID | the machine's NoCloud (cloud-init) drive: `user-data` and `network-config` | the platform's settings and a restart |
| `policy.yml` | who may reach the edge and how much, and what it records: `block`, `exempt`, `limits`, `access_log`, `trace`, `sites` | `fortressctl apply`, kept on the data disk | `fortressctl apply`, while the edge runs |

The ISO holds no secret, so it can be a build artifact, and the drive can
be what any platform writes. The one exception is the Vault secret ID of
edges that share certificates: it is each edge's own, in its `user-data`,
or in an ISO baked for that edge alone
([below](#with-vault-the-secret-id)). There is no other way to configure
an edge: no maintenance mode, no config upload, no shell.

The machine needs:

- the baked ISO as its boot CD (BIOS boot; the ISO is not a UEFI image),
  on a SCSI or SATA controller rather than IDE: the boot loader reads
  the kernel and initramfs through the BIOS, which takes about 3s from an
  emulated IDE CD and about 1s from virtio-scsi. The edge reads nothing
  from the CD once the kernel starts;
- one blank data disk, `/dev/vda` (VirtIO) or else `/dev/sda` (SCSI),
  which the edge formats ext4 on the first boot. Certificates, the policy,
  and logs live there;
- a NoCloud drive that stays attached, as Proxmox's cloud-init drive
  does: every boot reads it;
- TCP 80 and 443 open, and UDP 443 for QUIC;
- its `fqdn` resolving to its address, where the ACME server looks it
  up, before the first boot: the tunnel certificate is issued then, over
  TLS-ALPN-01 on port 443.

## fortress.yml: bake once per environment

The client CA is yours; create it once and keep `ca.key` off every edge:

```sh
fortressctl ca init tls        # tls/ca.crt, tls/ca.key
```

`fortress.yml` for edges that get certificates from an internal ACME
server, such as step-ca or Vault:

```yaml
acme: https://acme.internal.example/acme/acme/directory
acme_ca: |
  -----BEGIN CERTIFICATE-----
  ...the CA that signed the ACME server's own HTTPS certificate...
  -----END CERTIFICATE-----
ntp: [ntp1.internal.example, ntp2.internal.example, ntp3.internal.example]
quic: true
client_ca: |
  -----BEGIN CERTIFICATE-----
  ...tls/ca.crt...
  -----END CERTIFICATE-----
```

Leave out `acme` and `acme_ca` for Let's Encrypt. Every key is listed in
the [README](../README.md#configuration). Then bake:

```sh
fortressctl bake -o edge-prod.iso -c fortress.yml fortressedge-v0.9.4.iso
```

`bake` checks the file first: a missing `client_ca`, a `client_ca` with
more than one certificate, an unknown key, or a policy key (which belongs
in `policy.yml`) is refused. A bake is reproducible: the same release and
`fortress.yml` give the same bytes, wherever they are baked. The release's
kernel and edge binary are copied unchanged, and `fortress.yml` becomes
one more archive in the initramfs. One ISO serves every edge that shares
these settings. Bake it with Terraform ([below](#terraform)), or in CI
from the file in git, publishing it where the platform can download it,
with its checksum:

```yaml
# .github/workflows/edge-iso.yml, on a change to envs/prod/fortress.yml
- run: |
    v=v0.9.4
    base=https://github.com/sebiee/fortressedge/releases/download/$v
    curl -fsSLo release.iso "$base/fortressedge-$v.iso"
    curl -fsSLo fortressctl "$base/fortressctl-$v-linux-amd64" && chmod +x fortressctl
    ./fortressctl bake -o "edge-prod-$v.iso" -c envs/prod/fortress.yml release.iso
    sha256sum "edge-prod-$v.iso" > "edge-prod-$v.iso.sha256"
```

To upgrade, bake the new release with the same file and point the
machines at the new ISO; the data disk, with its certificates and
policy, carries over.

## The NoCloud drive: fqdn and address

The edge reads `fqdn` from `user-data` (with Vault, `vault_secret_id`
too) and nothing else there, and the first static address, gateway, and
DNS servers from `network-config` (v1 or v2). That is what platforms
write from their own settings. On Proxmox, the `fqdn` is the VM's name
with its DNS domain: a VM named `edge1` with the domain `example.com`,
or one named `edge1.example.com`. Proxmox writes the bare name `edge1`
as `fqdn` when the VM has no DNS domain; the edge refuses that, because
the name is what dark nodes ask for by SNI and what the certificates are
issued for.

Proxmox writes, for instance:

```yaml
# user-data (hostname, users, keys, and the rest are ignored)
fqdn: edge1.example.com
# network-config
version: 1
config:
    - type: physical
      name: eth0
      subnets:
      - type: static
        address: '10.0.10.21'
        netmask: '255.255.255.0'
        gateway: '10.0.10.1'
    - type: nameserver
      address:
      - '10.0.0.53'
```

A static address may be a /32 whose gateway lies outside it; the edge
adds the route to the gateway. Without DNS servers, the edge uses
1.1.1.1. Elsewhere, write the same two files onto a drive labelled
`cidata` with `meta-data` (such as `cloud-localds`), or let libvirt or the
cloud do it.

### With Vault: the secret ID

Edges that share their certificates through Vault
([certificates.md](certificates.md#several-edges-for-the-same-names))
log in with one AppRole, whose `vault_role_id` is in `fortress.yml`, and
each with a secret ID of its own, bound to its address, in `user-data`:

```yaml
#cloud-config
fqdn: edge1.example.com
vault_secret_id: 2f1b...
```

A shared ISO holds no secret: `fortress.yml` refuses `vault_secret_id`,
since an ISO is shared and copied, and whoever holds a secret ID reads
every private key on the path. Keep the drive, and wherever its
`user-data` comes from, as you keep the keys. Proxmox writes no such key
from the VM's settings, so give the VM a `user-data` of your own, with
`fqdn` in it, as a snippet:
`qm set <vmid> --cicustom user=local:snippets/edge1-user-data.yaml`.
Proxmox still writes `network-config` from the VM's settings.

**A per-edge ISO.** Where a platform bakes one ISO for each edge anyway,
that ISO may carry the edge's own secret ID instead, said so in its
`fortress.yml`:

```yaml
vault_secret_id: 2f1b...     # this edge's own
vault_secret_in_iso: true    # this ISO is this one edge's
```

Without `vault_secret_in_iso`, the key is refused, and with it in the
ISO, `user-data` must not have one too. `fortressctl bake` writes such
an ISO `0600`, with `fortress.yml` `0600` inside, and says so: the ISO is
a credential. Keep it as you keep the keys, never publish it or put it
in a CI artifact or a shared image store, and bake one per edge. Either
way, bind each secret ID to its edge's address (`cidr_list`, see
[certificates.md](certificates.md#several-edges-for-the-same-names)), so
a copy is useless anywhere else. On Proxmox this needs no snippet and no
SSH: the ISO goes to the image datastore like any other, readable by
whoever reads that datastore.

## Terraform

The `fortressedge` provider bakes on the machine that runs Terraform,
from a release pinned by its checksum, with no CI job. Bakes are
reproducible, so the ISO's checksum is known at plan time: the same
release and settings plan no change, on any machine, and nothing is
uploaded again. With the [bpg/proxmox](https://registry.terraform.io/providers/bpg/proxmox)
provider, an edge is then stock resources:

```hcl
terraform {
  required_providers {
    fortressedge = { source = "sebiee/fortressedge" }
    proxmox      = { source = "bpg/proxmox" }
  }
}

data "fortressedge_iso" "prod" {
  release_url    = "https://github.com/sebiee/fortressedge/releases/download/v0.9.4/fortressedge-v0.9.4.iso"
  release_sha256 = "…"                         # from the release's SHA256SUMS
  client_ca      = file("${path.module}/tls/ca.crt")
  acme           = "https://vault.example.com:8200/v1/pki/acme/directory"
  acme_ca        = file("${path.module}/vault-ca.pem")
}

resource "proxmox_virtual_environment_file" "edge_iso" {
  node_name    = "pve"
  datastore_id = "local"
  content_type = "iso"
  source_file {
    path      = data.fortressedge_iso.prod.path
    file_name = data.fortressedge_iso.prod.file_name   # changes with the content
    checksum  = data.fortressedge_iso.prod.sha256
  }
}

resource "proxmox_virtual_environment_vm" "edge1" {
  node_name = "pve"
  name      = "edge1"
  cpu { cores = 2 }
  memory { dedicated = 1024 }
  cdrom {
    file_id   = proxmox_virtual_environment_file.edge_iso.id
    interface = "scsi0" # virtio-scsi; IDE boots about 2s slower
  }
  disk {
    datastore_id = "local-lvm"
    interface    = "virtio0"
    size         = 1
  }
  boot_order = ["scsi0"]
  network_device { bridge = "vmbr0" }
  initialization {
    datastore_id = "local-lvm"
    interface    = "ide2"
    dns {
      domain  = "example.com"
      servers = ["10.0.0.53"]
    }
    ip_config {
      ipv4 {
        address = "10.0.10.21/24"
        gateway = "10.0.10.1"
      }
    }
  }
}
```

With Vault, each edge's `user-data` is a snippet, given to the VM in
place of the one Proxmox would write:

```hcl
resource "proxmox_virtual_environment_file" "edge1_user_data" {
  node_name    = "pve"
  datastore_id = "local" # a datastore that holds snippets
  content_type = "snippets"
  source_raw {
    file_name = "edge1-user-data.yaml"
    data      = <<-EOT
      #cloud-config
      fqdn: edge1.example.com
      vault_secret_id: ${var.edge1_vault_secret_id}
    EOT
  }
}
```

and, in the VM's `initialization`, `user_data_file_id =
proxmox_virtual_environment_file.edge1_user_data.id`.

The Proxmox API cannot upload snippets, so the `bpg/proxmox` provider
writes this file over SSH to the node, which a platform that so far uses
only an API token does not have:

- The provider needs an `ssh` block and a PAM user on the node, and the
  datastore must have the `snippets` content type turned on.
- By default it streams the file with `sudo tee` into the snippets
  directory, so that user needs sudo for it. With `upload_mode = "sftp"`
  on the file resource it needs no sudo, but must be allowed to write
  the snippets directory itself.

Either way the platform gets standing SSH access to its hypervisors:
scope that user to this one directory where you can. Without Terraform,
copy the snippet to the node as you deploy (`qm set ... --cicustom`
above).

`fortressedge_iso` takes the `fortress.yml` settings as attributes of the
same names (`client_ca`, `acme`, `acme_ca`, `ntp`, and the rest), checked
at plan time as the edge checks them, and `release_url` with
`release_sha256` or, for a build of your own, `release_path`. It returns `path`, `sha256`,
and `file_name`. Downloads and baked ISOs are kept in the user's cache
directory, or the provider's `cache_dir`. The DNS record for
`edge1.example.com` and the edge's operator certificate belong in the
same configuration or the same pipeline. An ISO baked in CI (above) can
take the provider's place: `proxmox_virtual_environment_download_file`
with its URL and checksum.

The provider is [Sebiee/terraform-provider-fortressedge](https://github.com/Sebiee/terraform-provider-fortressedge),
in the Terraform Registry as `sebiee/fortressedge`; `terraform init`
installs it. It bakes with this repository's `bake` package, so use the
provider release that matches the edge release.

## Certificates per edge

The client CA is shared, but a client certificate names one edge: its
SPIFFE ID's trust domain is the `fqdn`. Sign each edge's operator,
log-reader, and dark-node certificates where `ca.key` lives:

```sh
fortressctl ca client tls spiffe://edge1.example.com/ops/ci
fortressctl ca client tls spiffe://edge1.example.com/node/app1
```

See [certificates.md](certificates.md).

## policy.yml: apply while the edge runs

```yaml
block: [203.0.113.0/24]
exempt: [198.51.100.7]        # a monitoring probe
limits:
  requests_per_second: 300
```

An edge nobody applied a policy to runs the defaults: no block list, and
the limits in [operations.md](operations.md#limits). Keep the policy in
git and apply it on every merge; the same file again changes nothing:

```sh
fortressctl apply edge1.example.com -f policy.yml \
  --cert ops-ci.crt --key ops-ci.key --cacert acme-root.crt
fortressctl diff edge1.example.com -f policy.yml ...   # exit 1: the edge differs
```

`--cacert` is the root the edge's certificates chain to (for Let's
Encrypt, leave it out), and `--connect host:port` dials an address DNS
does not point at yet. `apply` checks the file before it sends it, the
edge checks it again, and a refused policy changes nothing. Everything
applies at once except `max_connections`, `max_header_size`, and
`max_http2_streams`, which reboot the edge into the new policy. The edge
puts a policy in force before it stores it, a policy that reboots the
edge included: one it cannot load, such as a block list XDP has no room
for or an access log it cannot open, is refused with a `500`, and the
previous one stays in force, on the disk, and in the status. The policy replaces the previous
one whole, is kept on the data disk, and survives reboots and new ISOs.
`GET /~!ops/policy` returns it as applied, with its SHA-256 as the ETag;
a new data disk starts from the defaults until the next apply.

### When the stored policy does not load

Nothing in the stored policy stops a boot: it would still be on the disk
at the next one, and the edge could never come up to take a fix. A boot
reads it leniently, as an edge rolled back past a new key or upgraded
past a stricter check needs: a key it does not know is skipped, a part
that does not parse keeps its default and the rest stays, and a block
list longer than a `PUT` may send loads if XDP has room for it (XDP then
may not hold it and a new list at once: if an apply is refused for that,
apply a shorter block list first). A block list XDP cannot hold, or an
access log the edge cannot open, is left out.
Each is logged, listed under `policy_degraded` in `/~!ops/status`, and
counted in `fortressedge_policy_degraded`. `GET /~!ops/policy` still
returns the stored file. The next apply that succeeds, the same file
included, clears it; a `PUT` is checked strictly, so a file the edge only
partly read is refused with the reason.

## When an edge cannot start

A missing or invalid part stops the boot. The console says what is wrong
and how to fix it, and the edge waits for the power button:

```
fortressedge: cannot start: user-data: fqdn "edge1": not a DNS name with a domain;
  on Proxmox, name the VM edge1.example.com or give it a DNS domain
```

The same happens for the release ISO booted unbaked, a machine without
its NoCloud drive, and a `network-config` without a static address or
gateway. Fix the ISO or the VM's settings, and start it again. Proxmox
Shutdown and Reboot work in every state: both press the ACPI power
button, and the edge powers off cleanly.
