# Changelog

## Unreleased

Releases carry build provenance attestations, signed by GitHub, for the ISO, `fortressctl`, `fortresskube`, and the `fortresskube` image: `gh attestation verify <file> --repo Sebiee/fortressedge` shows the workflow run and commit that built it.

Breaking: an edge is provisioned one way. `fortress.yml` is baked into the release ISO (`fortressctl bake -c fortress.yml`), and names whom the edge trusts: the ACME server (`acme`, `acme_ca`), the client CA, and now NTP (`ntp`). The machine's NoCloud drive gives its name, as `fqdn` in `user-data`, and its address, in `network-config`; nothing else in `user-data` is read, and the drive stays attached. The policy (`block`, `exempt`, `limits`) is a file of its own, `policy.yml`, which `fortressctl apply` puts on a running edge (`PUT /~!ops/policy`, operator certificate) and which the edge keeps on its data disk; `fortressctl diff` shows how an edge differs from the file, so a pipeline can apply on merge and check on pull requests. A key in the wrong file is refused with a pointer to the right one. One ISO serves a whole environment, and none of the three holds a secret. See [docs/provisioning.md](docs/provisioning.md), with a CI job and a Terraform example.

Removed, with nothing in their place: maintenance mode (the console token, SSH-signed bundles, its Let's Encrypt IP certificate and DHCP client), `POST /~!ops/config`, the config copy on the data disk, `fortress.yml` on the drive, `user-data`'s `mounts`, `ntp`, and `ssh_authorized_keys`, `tls: static` and `tls: off` (certificates come from ACME only), and `fortressctl provision`, `cidata`, and `disk`. `fortressctl ca init` no longer writes a server certificate, and `bake` no longer creates a CA or signs an operator certificate: create the CA once with `fortressctl ca init`. An edge that cannot start (the release ISO unbaked, no drive, an `fqdn` without a domain as Proxmox writes for a VM with no DNS domain, no static address) says why on the console and waits for the power button.

`network-config` v1's nameserver item, where Proxmox writes the DNS servers, is read; the edge used 1.1.1.1 instead.

Security: without `transport.tls.trustedCaFile`, frpc did not check the server's certificate at all, so anyone between a dark node and the edge could stand in for the edge. In the frp fork, which `fortresskube` and the system tests run, frpc now checks it against the system roots, and skips the check only with `transport.tls.insecureSkipVerify = true`. Stock frpc still skips it without a `trustedCaFile`, so the examples always set one.

Builds are reproducible. `make iso` dates every file, directory, and volume date in the ISO at the last commit's time (`SOURCE_DATE_EPOCH`, which `fortressctl iso` reads), and records no owner or link count of the build machine, so the same commit builds the same bytes. `fortressctl bake` dates its copy as its source, and stores `fortress.yml` uncompressed, so the same release and `fortress.yml` bake the same bytes anywhere. The boot catalog is no longer listed in the ISO's directories; the boot record still points at it. `client_ca` takes exactly one CA certificate: a second one in the same field would have been trusted too.

The Go module is `github.com/Sebiee/fortressedge`, and `bake` is its one public package: checking `fortress.yml` as the edge does, and baking it into a release ISO. The Terraform provider, [Sebiee/terraform-provider-fortressedge](https://github.com/Sebiee/terraform-provider-fortressedge) (`sebiee/fortressedge` in the Terraform Registry), builds on it: `fortressedge_iso` bakes a release, pinned by its checksum, with `fortress.yml`, on the machine that runs Terraform, and returns the ISO's path and checksum for the platform's upload. The checksum is known at plan time, so an unchanged configuration uploads nothing. See [docs/provisioning.md](docs/provisioning.md#terraform).

Sites are served about four times as fast. On a 2-vCPU edge in `make waf-bench`, open-appsec's legitimate requests went from about 1,650 to about 7,200 a second, and the median latency from 15 ms to 7 ms. frps runs in the edge's process, and the edge no longer reaches it over loopback: a site request goes straight to frps's proxy, already parsed, and a dark node's WebSocket goes straight to frps once upgraded, where both used to be written to a local port, copied, and parsed again. frps's proxy (the frp fork) uses work connections on the request's own goroutine instead of `http.Transport`'s reader and writer goroutines, keeps 64 idle per site instead of 5, and no longer asks origins for gzip on a visitor's behalf. The edge gathers what it writes into the tunnel into as few writes as it can. The edge no longer flushes a response on every write, which cost a fifth of its CPU, and garbage-collects at five times the live heap, within half the machine's memory (`GOGC` and `GOMEMLIMIT` still win). frps now sees a dark node's own address instead of `127.0.0.1`.

`/~!ops/status` counted no bad gateways once frps answered 502 and 504 itself; it does again, and a visitor who leaves before the answer is logged as `499`, not as the origin's fault. With frps in the process, an absolute-form request target would have reached the site as it came, and a visitor could have named `X-Real-IP` or `X-Request-Id` in `Connection` to have frps drop them: the edge now sends origin-form, and keeps the headers it sets. The log line `xdp filter up` says whether XDP attached in driver or generic mode.

CI's `perf-guard` job keeps the edge from getting slower: on every pull request it boots the base commit's build and the pull request's in turn, replays part of open-appsec's dataset at a fixed rate, and fails when a request costs the edge more than 20% more CPU, or 10% more allocations, or the edge's peak memory (RSS) grows more than 15%, than before. The WAF bench now runs weekly and on demand; its throughput on a 2-core runner is information only. The edge's unused loopback listener for sites (`127.0.0.1:8080`) and its copier are gone, and so is the console's `VHOST` line.

Known issue: through a QUIC tunnel, a large upload (a file upload in open-appsec's dataset) stalls until the visitor's timeout; WebSocket tunnels are not affected.

`OPTIONS *` got a `200` from Go's HTTP server for any `Host`, so a scan of port 80 for the bare address was answered. It now goes through routing: a name the edge does not serve gets no response, and a name it serves gets an empty `200` from the edge. It used to be answered the same way, and proxying it would have turned it into `OPTIONS /*`.

`TestHostileRequests` sends request smuggling (CL.TE, TE.CL, H2.CL, H2.TE), malformed framing and headers, ambiguous paths, and fields HTTP/2 forbids. It checks that what reaches a site is one clean HTTP/1.1 request, or nothing, and that the next visitor's request arrives intact. See [docs/development.md](docs/development.md#hostile-requests).

`make waf-bench`, and a `waf-bench` workflow on `main`, weekly and on demand, replays open-appsec's WAF comparison datasets (1,040,242 legitimate requests from 185 real websites, 73,924 attacks) and runs GoTestWAF through an edge VM with 2 vCPUs and 2 GiB. What becomes of each class of request, and GoTestWAF's summary, are pinned as the baseline a WAF will move, and the run records throughput, latency, and the edge's status as the artifact `waf-bench-<sha>`. The VM sits on a tap device with vhost-net, in a network namespace `os/netns.sh` makes without root; QEMU's user-mode network capped the bench near 1,500 requests a second. See [docs/development.md](docs/development.md#waf-bench). `os/qemu.sh` takes `QEMU_SMP`, `QEMU_MEM`, and `TAP`.

Visitor limits. Each source address, or IPv6 /64, may hold 256 open connections and make 150 requests per second (burst 600); past that a connection is closed at accept and a request gets `429` with `Retry-After`. A source that keeps being refused is banned in XDP for 15 minutes. Connections from all sources are capped by the machine's memory, and PID 1 may now open 65536 files instead of 4096. XDP's SYN rate limit and its bans count IPv6 per /64, so rotating addresses inside one /64 buys nothing. A request with a verified client certificate on the tunnel name is never rate limited, and `exempt` in the policy lists sources that skip the limits (a load generator, a monitoring probe); `test/perf/vms.sh` exempts its load generator. Every limit is a key under `limits:` in the policy, including the XDP SYN rate, the body size (`max_body_size`, 512 MiB as before, `0` for none), and HTTP/2 streams per connection (`max_http2_streams`); `0` turns a rate or count off, and `ban: 0` refuses without banning. A source is banned after more than `ban_after` refusals (default 200) within `ban_window` (default 10s), so a client that honors `Retry-After` or goes slightly over the rate is never banned. A change applies at once without a reboot, like `block`, except `max_connections`, `max_header_size`, and `max_http2_streams`, which Go's HTTP server fixes at start; `exempt` also applies at once now. A refused source is logged with the limit that refused it (once a minute per source, about ten lines a minute in all), and `/~!ops/status` shows the limits in force. A rejected request for a name the edge does not serve still gets no response. Per-route and per-user limits stay with the gateway behind the dark node. See [docs/operations.md](docs/operations.md#limits).

Requests no site should get are refused at the edge with an empty body: `TRACE`, `TRACK`, and `CONNECT` (`405`), and paths with dot segments, NUL, or a backslash (`400`). The request line may be 16 KiB (`414`) and headers 64 KiB (`431`, was 1 MiB); an HTTP/2 connection may carry 100 concurrent streams (was 250). The `Forwarded` header is removed before a request reaches a site, like `X-Forwarded-*` already was: a gateway trusting it could be handed a forged client address.

Every site request gets an id, sent to the visitor as `Fortress-Request-Id` and to the dark node as `X-Request-Id`, replacing one the visitor sent. With `access_log: true` in `fortress.yml`, each site request is one JSON line (id, address, site, method, path without the query string, status, bytes, duration, user agent) in `/var/log/fortressedge/access/`, served by `GET /~!ops/access` with the logs endpoint's cursors. It starts a new file at `access_log_max_size` (default `8MiB`) and keeps `access_log_max_files` files (default 3), so it stays within 24 MiB by default and fits the default 64 MiB data disk; the edge warns at boot when it could take more than half of the disk. `/~!ops/status` counts requests, requests in flight, bytes, and responses by class for each published site, and the limit counters. A visitor who leaves before the response is logged as `499` and no longer counts as a bad gateway.

`/~!ops/status` has the kernel's TCP counters under `kernel_tcp` (accept and SYN queue overflows, resets sent), to tell a refusal by the edge's kernel from one outside it. `make load` measures what one edge VM serves through each tunnel; see [docs/development.md](docs/development.md#load-tests).

`/~!ops/logs?follow` sent everything in its first response a second time.

QUIC dark nodes were capped at about 40 Mbit/s: XDP counted every UDP packet to port 443 against a 4096-per-second limit per source, the data inside an open tunnel included. It now counts only long-header packets, which QUIC sends while it sets a connection up (512 per second per source), so an open tunnel runs at full speed, as a WebSocket one always did. QUIC also no longer shares its counter with the TCP SYN limit.

`fortresskube` is a new frpc for Kubernetes. It runs frpc in-process and publishes every hostname of the HTTPRoutes that one Gateway has accepted, one proxy per name, forwarded to that Gateway. A new app needs only its HTTPRoute, and the edge gets a certificate for each exact name. Releases attach the binary and push it as `ghcr.io/<owner>/<repo>/fortresskube:<tag>`. It is its own Go module, so `k8s.io/client-go` does not change the edge's dependency versions.

`tls: acme` issues a certificate when a dark node registers a hostname, and renews it only while that name is still registered. A reconnect reuses the certificate already on disk. Renewal is a timer, no longer a side effect of handshakes: every `renew_interval` (new in `fortress.yml`, default `4h`) each certificate is checked, and renewed in the last third of its life or when the CA asks through ACME Renewal Info. The tunnel certificate is renewed the same way. An expired certificate, after a long power-off, is renewed before it is served. The tunnel name is still issued at boot. Wildcards are skipped. The old check that the name's DNS must contain this machine's address is gone, so a 1:1 NAT no longer blocks issuance. Let's Encrypt's own TLS-ALPN-01 connection is the reachability check.

`acme_ca` in `fortress.yml` is the CA certificate that signed a private ACME directory's TLS certificate. The ACME client trusts only that CA when calling the directory. Leave it out and the client uses the system roots, which is Let's Encrypt.

Security: a client without a certificate could reach frps's login, which has an empty token, by naming a site in TLS and the tunnel in the `Host` header, and then register any hostname. A request whose `Host` is the tunnel name now needs the tunnel as its TLS server name too, or it gets `421 Misdirected Request`.

The edge answers only the names it serves: the tunnel name and each hostname a dark node publishes. A handshake for any other name, or with no name, is closed before the edge sends a certificate or an alert. Plain HTTP for such a name, or plain HTTP on the TLS port, is closed without a response. Unpublished names used to get frp's 404 page, and plain HTTP redirected every name. A name whose dark node left goes silent too, where it used to be served from the certificate on disk. QUIC presents the server certificate only to the tunnel name.

A site whose origin does not answer gets `502 Bad Gateway` with an empty body, or `504` after 10 seconds without response headers. frp used to answer `404` with its own page and a `server: frp/<version>` header. The frp fork (`Sebiee/frp` `49510b4b`) returns 502 for a matched route whose connection fails, and no longer sends that header. The edge sets frp's 404 page to an empty file.

TCP 443 and QUIC share one certmagic config and cache. A failed TLS handshake is logged at debug level, not on the console. certmagic and its ACME client log through slog, like the rest of the edge, so their lines reach the log file and the ops logs API in the same format. The ACME client used to write to stderr, which reached only the console.

The console status header sends only the characters that changed on each refresh. On KVM an idle edge now costs its host no more with the header refreshing every second than it used to with no refresh at all; the old 5-second refresh added about half again. The header shows open connections on TCP 80 and 443 in place of the process count, which was always 1, and `/~!ops/status` reports them as `connections`.

`fortressctl bake` writes a copy of the release ISO with any of the three config files in its initramfs (`--authorized-key` bakes a `user-data` of SSH public keys only). All three make a machine that boots provisioned, with no drive. Fewer make one that waits in maintenance mode, on the baked address or DHCP, for the rest. A maintenance bundle now carries only the files it replaces, so `fortressctl provision --identity <private key> --config fortress.yml` completes a machine whose keys and network were baked: no second drive, no DHCP, and no console, which suits servers that only take a custom ISO. Once the disk has a config, it wins over the ISO's, and the edge logs which baked files it ignores. `bake` adds `client_ca` and signs the first operator certificate as `provision` does. A maintenance bundle is refused with `409` while a cloud-init drive is attached, as on a running edge. The system tests boot baked ISOs: fully baked for proxying, keys and network for the signed bundle.

The maintenance signature covers the `sha256sum` of the files sent, not the files joined together: bytes can no longer move from one file into the next, and a file cannot be dropped or added, without breaking it. Signatures made the old way are refused.

A static address may be a /32 whose gateway lies outside it: the edge adds a link route to the gateway before the default route. It used to fail with "network is unreachable".

Fix: a hijacked connection (a WebSocket, or a dark node's frp control) stayed in the edge's connection list after it closed, so the list grew with every one. The edge now tracks connections at the listener.

`tls: acme` works on a running edge. XDP dropped the replies to the edge's own connections, so ACME, DNS, and OCSP never got an answer. XDP now passes TCP segments with ACK set to the kernel's ephemeral ports (32768–60999) and rate-limited DNS replies. The check is stateless, and a bare SYN still never passes. An ACME boot also no longer waits on the console for an email address.

The boot clock sync retries short NTP queries for its whole 15 seconds, so one lost UDP packet no longer fails the boot. Maintenance mode's DHCP client resends after one second instead of five, so a DISCOVER lost while the link comes up costs a second, not ten. A boot with no config looks for one for 5 seconds, as intended; it looked for about 13, because every look mounts each disk and CD.

The system suite covers ACME against an in-process Pebble (issuance, early renewal through ACME Renewal Info, renewal at the end of 12-second lifetimes, reboot from disk) and proxying (routing, forwarded headers, HTTP/2, WebSockets, streaming, large bodies, timeouts, silence for unknown names). The lab serves NTP to the guests, so the suite no longer needs pool.ntp.org.

The repository has three Go modules: the edge and `fortressctl`, `test/e2e`, and `cmd/fortresskube`. Test tools and Kubernetes libraries are no longer in the edge's `go.mod`. `make tidy` and CI keep all three tidy and on the same frp fork; Dependabot covers each. `make e2e RUN=<name>` runs chosen system tests. Test output is one line per package plus failures; `V=1` shows all of it. Binaries are built with `-trimpath -ldflags='-s -w'`, and the initramfs with the default gzip level (0.4s instead of 2.6s, 3% larger).

The README is a short front page; the details moved to `docs/` (provisioning, certificates, operations, Kubernetes, development).

A Go system test suite in `test/e2e/` replaces `os/ci.sh`. It boots the
ISO in QEMU and checks only what users rely on: status codes, certificate
chains, a dark node's site answering, and a closed control port. Three
parallel scenarios cover bootstrap with a console token, bootstrap with
an operator key, and boot from a cloud-init volume, in five VM boots, within 3 minutes on KVM. `make ci` runs `make test` (now with
`-race`) and `make e2e` on the host toolchain; `./dev` is optional.
`make test`, `make build`, and `make iso` no longer run `go generate`,
because the BPF output is committed. CI runs unit and system tests as two
parallel jobs and caches Go, the Alpine kernel, and the apt package files.
The package files are installed with apt on each run, which is what puts
the ISO boot loader on disk. The
load lab moved from `e2e/` to `test/perf/`.

The project is FortressEdge. It was fortressOS. The binary, the ISO, the
log prefix, disk paths (`/var/fortressedge`, `/var/log/fortressedge`),
and the bootstrap signature namespace (`fortressedge-bootstrap`) all use
the new name. A boot renames a leftover `fortressos` directory on the
data disk. Signatures made with the old namespace do not verify.

The console status grid stays pinned at the top of the VGA and serial
screens. A rule separates it from the log. The header shows uptime, CPU
use, and memory used out of the machine total, and refreshes every few
seconds by rewriting only the lines that changed. Only READY and
CONNECTIVITY are colored. Log timestamps include milliseconds.
Kernel printk no longer writes the consoles; kernel errors and frp logs
are slog lines, so they cannot split another log line.

Proxmox Shutdown and Reboot work. Both send an ACPI power button and wait
for the VM to power off (Reboot starts it again afterwards). PID 1 now
reads that button and powers the machine off. The old halt stopped the
CPUs and left QEMU running, so both buttons timed out.

`fortressctl` replaces `fortressca` and the operator shell scripts
(`cidata`, `provision`, `ca`, `disk`, plus the initramfs and BIOS ISO).
Maintenance on a public address is HTTPS: the edge obtains a short-lived
Let's Encrypt certificate for that IP before accepting a bundle. Any
other address stays plain HTTP and warns not to send a `tls: static`
server key; the recommended bootstrap is a cidata volume, with
`fortressctl disk` writing `server.crt` and `server.key` onto an ext4
`/var` image when TLS is static.

The client trust anchor is `client_ca` in `fortress.yml`, and it is required unless `tls: off`. The edge keeps only this certificate, never a CA key, and signs nothing: no generated CA, no `ca.key` on `/var`, no minting endpoint. `fortressctl provision` creates the CA on the operator's machine when `fortress.yml` has none, writes it into `fortress.yml`, and signs the first operator certificate there. `fortressctl mint` and `fortressctl disk --ca` are gone. A loose `ca.crt` on the NoCloud volume or the data disk is not read.

Edge settings moved out of cloud-init into `fortress.yml` (`tls`, `acme`,
`quic`, `block`, `client_ca`). `user-data` keeps the stock fields (`fqdn`,
`mounts`, `ntp`, `ssh_authorized_keys`). An attached NoCloud volume is
the config; it is copied to `fortressedge/seed` on `/var` so a reboot still
works if the volume is gone. `POST /~!ops/config` on the tunnel (ops
client certificate) updates that disk copy while the edge is up: `block`
applies in place, and `tls`, `acme`, `quic`, or any cloud-init or CA
change reboots. The POST returns 409 while a NoCloud volume is
attached. The plain-HTTP maintenance listener still runs only when boot
cannot proceed.

The public HTTP hop now forwards client identity (`X-Forwarded-For` /
`X-Real-IP` / `Proto` / `Host`, inbound spoofed values stripped), sets
HSTS and `nosniff` on HTTPS, caps bodies at 512 MiB, and idles keepalives
at 65s. Per-route and per-user rate limits stay behind the tunnel
(Gateway API or whatever the dark cluster runs). `GET /~!ops/status` gains request / 502
counters plus XDP pass/drop reasons. Port 80 redirects with 308.

XDP `block:` accepts CIDRs and IPv6, and a runtime ban (with a deadline)
so a future WAF can pin a source after it has seen the request. SYN (and
QUIC-pps) token buckets sit in front of TLS — a packet fuse, not HTTP
policy. NTP is allowed as
replies (UDP source 123, rate-capped), not as a server hole on dest 123.
IPv4 ICMP dest-unreachable passes for path MTU.

Config moved onto stock cloud-init fields where they exist: `fqdn`
replaces `tunnel` (the edge's public name — tunnel SNI, cert name,
SPIFFE trust domain) and the standard `mounts: [[/dev/vdb, /var]]` form
replaces `disk`. `ntp` and `ssh_authorized_keys` were already standard.
`tls`, `acme`, `quic`, `block`, and `client_ca` are `fortress.yml` —
cloud-init has no vocabulary for them.

Maintenance mode: when boot needs operator material — no config anywhere,
an invalid config, or no client CA — the machine waits for one config
bundle at `POST /~!ops/config` (multipart `user-data`, `network-config`,
`ca.crt`). Two authorization modes: if the seed's user-data defines
operator keys (standard cloud-config `ssh_authorized_keys`, top-level or
per `users[]` entry; ed25519, ecdsa, or RSA), the bundle must carry an
`ssh-keygen -Y sign -n fortressedge-bootstrap` signature from one of them —
`os/provision.sh <addr> <key> user-data network-config ca.crt` does it in
one command; the network comes from the seed's network-config (static,
pipeline-known) in that case. With no keys defined, a one-time
rate-limited token is printed on the consoles and the network comes from
DHCP. A valid bundle is persisted to the disk the config names and the
machine reboots into it; a broken one gets a 400 with the exact parse
error.

Client-certificate identity is a SPIFFE ID in the only URI SAN, never the
CN: `spiffe://<tunnel>/<role>/<name>`, with the tunnel name as trust
domain. `node/<name>` may only join the tunnel: frp control on TCP 443
and QUIC (through a new verify hook in the frp fork) refuse any other
role, so an operator or log-reader certificate cannot register
hostnames. `ops/<name>` may use the whole ops API. `logs/<name>` may read
logs and status only, so a log shipper holds no key that can reconfigure
the edge. Refusals and config changes are logged with the caller's ID.
`ops_id` is gone; `fortressctl ca client <dir> <id>` writes
`<dir>/clients/<role>/<name>.crt`.

Applied config is copied to `fortressedge/seed` on the `/var` disk. An
attached NoCloud volume wins at the next boot and refreshes that copy;
the copy is what boots when the volume is gone.

Operator ops API on the tunnel SNI (mutual TLS as for dark nodes, plus an
identity check — the client cert's URI SAN must be the ops SPIFFE ID):
`GET /~!ops/logs` serves this boot's log as text or NDJSON
(`?format=ndjson`), streams with `?follow`, and resumes with an
`X-Log-Cursor` header (`<boot-id>:<offset>`) that survives a reboot by
draining `previous.log` first; unrecoverable gaps are signalled with
`X-Log-Gap: true`. `GET /~!ops/status` returns boot id, uptime, network,
tunnel/TLS/QUIC state, and the current log cursor. Disabled when
`tls: off`. Filebeat's httpjson input can ship logs with it natively;
CI boots QEMU and checks the identity gate, cursors, gap header, and NDJSON.

The persistent disk now mounts at `/var` instead of `/data`. The on-disk
layout is unchanged (`fortressedge/tls`, `fortressedge/certs`), so existing
disks keep working; logs join them at `/var/log/fortressedge/`.

Structured logs (slog) go to the VGA console, the serial console, and
`current.log` on the persistent disk (previous boot kept as `previous.log`).
The kernel boots `quiet` and PID 1 clamps `kernel.printk`, so the consoles
show fortressedge state and events instead of kernel spam: a state panel when
the edge is up, then boot milestones, clock offset, XDP state, ACME
decisions, and frps dark-node logins. frp and certmagic log through the
same fan-out.

ACME is TLS-ALPN-01 only. TCP 80 is an HTTP→HTTPS 308; it is not used for
ACME.

Optional dark-node QUIC: `quic: true` in `fortress.yml`. XDP then passes UDP
443 and frps listens there directly (the TCP control port stays on
loopback). That listener requires a fortress client cert. The QUIC server
cert is the ACME tunnel cert (re-read on each handshake) or `server.crt`
when `tls: static`. wss on TCP 443 stays available.

`test/perf/` is a three-VM load harness: vegeta against the ISO, frpc plus three
http-echo origins on the dark node.

Boot logs go to VGA and serial. PID 1 prints the error and waits 30s
before reboot. virtio-scsi (`/dev/sda`) is loaded for Proxmox. A blank
data disk is formatted ext4 in-process (go-diskfs) on first boot; `ca.crt`
may come from the NoCloud volume.

## 0.1.0

First release.

ISO is built and smoked in GitHub Actions. Don't upload a local build.

- Go 1.27 (`golang:1.27-bookworm`)
- frp v0.71.0 (in-process frps + the CI frpc smoke), wire protocol v2
