# Changelog

## Unreleased

- Boot's clock sync logs one line, `clock: boot sync`, with what it took
  and each name lookup and NTP query it made: when, how long, and how it
  ended. "clock synced" is logged after the step, so the time between it
  and "network up" includes the step itself; this line has the sync's
  own time.

## 0.5.2

- Boot's clock step no longer waits out a lost NTP answer before the
  edge listens. It asked each server once and waited for every answer or
  its 2-second timeout, then, without a majority, a second before asking
  all again: a reply lost just as the network came up cost a second or
  two of ingress after a reboot. It now steps as soon as the answers in
  hand agree, a majority of the servers, re-asks only the servers that
  have not answered, every 250 ms, and looks the names up together.

## 0.5.1

- `fortresskube` finds a restarting edge up to a second sooner. A
  connection attempt sent while the edge's machine is down is lost, and
  TCP sends it again only after a second; before each login it now
  starts another attempt every 250 ms until one connects (the frp fork,
  over tcp, websocket, and wss without a proxy).
- `fortressedge_clock_boot_step_seconds`, and `boot_step` in the status's
  `clock`: what boot's step moved the clock by. Until the first poll,
  64 seconds after boot, the offset gauge shows the same step, which read
  as an uncorrected clock. It was corrected: boot steps the clock before
  anything that reads it starts, and the edge's ready time matched when
  its port opened, as a host on its network saw it, within 11 ms after
  boot steps of 0.2 to 1.3 s.
- e2e: on a tap device, `TestTunnelComesBack` checks
  `fortressedge_ready_time_seconds` against the port opening.

## 0.5.0

**Restarts cost less ingress.** When the edge restarts, dark nodes come
back within a fraction of a second of it listening, and visitors get an
answer meanwhile, not a closed connection.

- A site whose dark node is away answers `503 Service Unavailable`
  with `Retry-After: 1` and an empty body, for `tunnel_grace`, a new
  policy key (default `10m`, `0` turns it off), then goes silent like any
  name the edge does not serve. It covers names whose dark node left, and
  after a boot the names whose certificates are on the data disk, until
  their dark node is back. Only names a dark node published, with a valid
  certificate, are answered. The access log says `error: no_tunnel`.
- The proxy error reason `no_route` is now `no_tunnel`, answered 503 and
  logged at debug; `dial` is answered 503 with `Retry-After` too, not 502.
- The ACPI power button powers the edge off in about 1.25 seconds: a
  shutdown waits a second for requests in flight, not 30. The edge found
  the button's device only when its node was the first to appear, so a
  press was sometimes ignored and Proxmox fell back to stop after 60
  seconds; it now waits for the button by name.
- `fortresskube` reconnects fast: every 250 to 375 ms for a minute after
  it loses the edge, then backing off to 20 s as before; a refused login
  backs off at once. New defaults for keys its config leaves out:
  `transport.deadServerTimeout = 3`, `transport.dialServerTimeout = 2`,
  `loginFailExit = false` (see [kubernetes.md](docs/kubernetes.md)).
- The frp fork: `transport.deadServerTimeout` (frpc, default 0, off) drops
  a TCP tunnel whose server stopped acknowledging, with TCP_USER_TIMEOUT
  and one-second keepalives. frpc no longer drops a work connection that
  arrives just before its proxy has started, which answered the first
  request after a reconnect 502. Its per-client logger is safe for
  concurrent use; a reconnect raced the control's goroutines on it.
- `fortressedge_boot_time_seconds` is by the clock as boot set it; it
  moved by the boot step. New: `fortressedge_kernel_boot_time_seconds`
  and `fortressedge_ready_time_seconds`, when the edge first accepts
  connections.

## 0.4.0

**The clock stays in step.** Boot still steps the clock once; the edge
then polls its NTP servers every 64 seconds, up to 1024 while the offset
stays under half a millisecond. It measures the clock's frequency error
over the first ten minutes and sets it, as ntpd does, then hands each offset
to the kernel's NTP discipline, which slews it away and follows the
frequency: time never jumps, and a clock ahead is never stepped back unless more
than a second ahead. It was set once at boot and drifted from there,
some 25 ms in an hour on one VM, which put the edge's spans out of line
with the cluster's.

- `ntp` in `fortress.yml` takes a list, and `bake.Config.NTP` is a
  `[]string`: the Terraform provider needs its 0.4 release. Each poll
  keeps each server's fastest of four samples, and follows the servers
  only when a majority of them agree; one that disagrees is ignored and
  logged. `pool.ntp.org`, still the default, counts as four servers.
- `/~!ops/status` has `clock`, and `/~!ops/metrics` the offset, the last
  sync, steps, the poll interval, the learned frequency, the followed
  server's stratum, and per server queries by result, round trips, and
  falsetickers.
- A warning when no majority answers for 30 minutes, or an offset is
  still over 10 ms after a correction.
- `make clock-soak` keeps an edge VM on real NTP servers and prints its
  offset each minute.

## 0.3.0

**Observability.** `GET /~!ops/metrics` serves Prometheus's text format
to operator and log-reader certificates, never rate limited: per site
(the published name, so a wildcard is one site) requests by status
class, a histogram of the time to the response headers, bytes, requests
in flight, proxy errors by reason, and limit hits; tunnel sessions by
dark node, logins, and work connections; each certificate's expiry and
its obtains and renewals; XDP's packets by action and reason; bans; and
the kernel's TCP counters. `fortressedge_boot_time_seconds` and
`fortressedge_build_info` date and name the build.

- A request frps could not proxy is one warning that names the site,
  method, path (no query), visitor, request and trace ids, the time since
  the request arrived, the bytes already sent, and a reason: `no_route`,
  `dial`, `send`, `header_timeout`, `eof_headers`, or `eof_body`. frp's
  own lines for it, which named only the host, are gone.
- Each site request is a hop of a W3C trace: the origin gets a
  `traceparent` under the edge's own span, the visitor gets
  `Fortress-Trace-Id`, and the access log line gets `trace_id`, `span_id`,
  `start`, `us`, and `headers_us`, from which a collector rebuilds the
  edge's span. A visitor's `traceparent` is continued only with
  `trace: {trust_incoming: true}`; otherwise it is logged as a link.
- XDP's `drop_other` is split into `drop_truncated`, `drop_fragment`,
  `drop_ethertype` (with the dropped EtherTypes counted), and, from
  `drop_port`, `drop_proto` and `drop_icmp`. `/~!ops/status` keys change
  with them.
- Go's `http2: received GOAWAY` line is a debug line.
- `/~!ops/status` counts `sites` by the published name, as metrics do.

**The policy.** `access_log`, `access_log_max_size`, and
`access_log_max_files` move from `fortress.yml` to `policy.yml`: the
access log turns on and off with `fortressctl apply`, without a new ISO
or a reboot. `bake` refuses them in `fortress.yml` and says where they
went; `bake.Config` loses its three fields, so the Terraform provider
needs its 0.3 release. A new `sites` block sets `access_log`,
`max_body_size`, and `response_header_timeout` for one published name or
wildcard. `response_header_timeout` applies at once and no longer
reboots. A body over `max_body_size` is answered `413`, before the
origin when its length says so.

**The tunnel.** A work connection frpc sends beyond its pool is closed
without an error message, which frpc logged as
`StartWorkConn contains error`, and counted. The frp fork has the hooks
all of this needs: the proxy's failures by stage, a response header
timeout per request, the work connection counts, and QUIC connections.

**Booting.** The documentation and `os/qemu.sh` put the boot CD on
virtio-scsi instead of IDE: SeaBIOS reads the kernel and initramfs about
2 seconds faster (about 1s from power-on to the edge's first line under
KVM, from 3s). On Proxmox, attach the ISO as `scsi0`.

## 0.2.0

`response_header_timeout` in the policy's `limits`: how long a request
waits for the origin's response headers before the edge answers `504`,
whole seconds from 1s to 10m, and a boot-time limit like
`max_connections`. The default is 60s, frp's own; it was a fixed 10s,
which cut server-sent events and long polls (such as Argo CD's
application stream) whose headers come with their first event. A visitor
who leaves before the origin answers is logged at debug, no longer as
frp's `context canceled` warning. `/~!ops/status` shows the limit.

The `bake` package has `Config`, `fortress.yml` as fields, one per key
the edge reads: `YAML` writes it, leaving defaults out, and `Check`
checks it. The Terraform provider v0.2.0 builds its `fortressedge_iso`
attributes on it, one per key, in place of `config`.

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
