# Changelog

## Unreleased

`response_header_timeout` in the policy's `limits`: how long a request
waits for the origin's response headers before the edge answers `504`,
whole seconds from 1s to 10m, and a boot-time limit like
`max_connections`. The default is 60s, frp's own; it was a fixed 10s,
which cut server-sent events and long polls (such as Argo CD's
application stream) whose headers come with their first event. A visitor
who leaves before the origin answers is logged at debug, no longer as
frp's `context canceled` warning. `/~!ops/status` shows the limit.

## 0.1.0

First release.

**The edge.** An ISO that boots an Alpine kernel with `fortressedge` as
PID 1: no shell, no sshd. It serves websites from dark nodes, which dial
out to it with frp over WebSocket (or QUIC on UDP 443 with `quic: true`),
and terminates HTTPS for them.

- **Certificates** come from Let's Encrypt or any ACME directory, such as
  step-ca or Vault (`acme`, `acme_ca`): one per hostname, as soon as a dark
  node publishes it, renewed on a timer and through ACME Renewal Info.
- **Mutual TLS with roles.** Dark nodes, operators, and log shippers
  authenticate with client certificates from your CA (`client_ca`, one CA
  certificate). A certificate's SPIFFE ID gives its role: `node`, `ops`, or
  `logs`. The edge holds no CA key and signs nothing.
- **Invisible to strangers.** Only the tunnel name and published hostnames
  are answered; anything else gets no bytes back.
- **XDP filter** in front of the kernel: only HTTP, HTTPS, and replies to
  the edge's own connections pass, with SYN rate limits and a block list.
- **Visitor limits** per source address (IPv6: its /64): open connections,
  request rate, and bans in XDP for sources that keep pushing past them.
  Malformed, ambiguous, and smuggling requests are refused before they
  reach a site, and forwarding headers are the edge's own.
- **Operations API** on the tunnel name: status, logs with resumable
  cursors, an optional access log, and the policy.

**Provisioning**, one way:

- `fortress.yml`, baked into the release ISO with `fortressctl bake` or the
  Terraform provider: the ACME server and its CA, the client CA, NTP, QUIC,
  and the access log. A bake is reproducible: the same release and
  `fortress.yml` give the same bytes.
- The machine's cloud-init (NoCloud) drive: `fqdn` in `user-data`, which
  must be a DNS name with a domain, and the static address in
  `network-config` (v1 or v2, as Proxmox writes them).
- `policy.yml` (block list, exempt sources, limits), applied to a running
  edge with `fortressctl apply` and checked with `fortressctl diff`.

An edge whose config is missing or wrong says why on its console.

**Tools.**

- `fortressctl`: `bake`, `apply`, `diff`, and `ca` to create the client CA
  and sign certificates.
- `fortresskube`: frpc for Kubernetes, publishing the HTTPRoutes a Gateway
  accepts.
- `github.com/Sebiee/fortressedge/bake`: checking and baking `fortress.yml`
  from Go, which the
  [Terraform provider](https://github.com/Sebiee/terraform-provider-fortressedge)
  uses.

frp is a fork (`Sebiee/frp`): frps runs inside the edge's process, a down
origin answers 502, and frpc checks the server's certificate against the
system roots when `transport.tls.trustedCaFile` is not set
(`transport.tls.insecureSkipVerify = true` skips the check).

Releases carry build provenance attestations for the ISO, `fortressctl`,
`fortresskube`, and the `fortresskube` image.
