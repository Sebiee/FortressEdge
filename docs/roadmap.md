# Roadmap

Work planned after v0.1.0, with the design already agreed, so it can be
picked up without redoing the thinking.

## Certificate revocation (CRL)

Today a leaked client key stays valid until it expires (two years),
unless you move to a new CA and re-issue every certificate. The plan
is to check a certificate revocation list (CRL) on every client-certificate
handshake.

**Why a CRL and not OCSP.** OCSP asks the CA about each certificate at
handshake time. The edge usually cannot reach the CA: Vault, say, runs
in the dark cluster, and dark nodes dial out, never in. OCSP would also
tie the edge's availability to the CA's, which is the reason the ops
API uses mutual TLS and not SSO. A CRL is one file, signed by the CA,
that the edge can keep on disk and check with a lookup.

**Checks.** Every mTLS handshake: frp control on TCP 443 (WebSocket) and
on QUIC (through the fork's `VerifyConnection` hook), and the ops API. A
revoked certificate is refused like one from a foreign CA.

**Trust.** The edge accepts a CRL only when a certificate in `client_ca`
signed it; `client_ca` may be a bundle, for example a Vault root and the
intermediate that issues the client certificates. It accepts only a CRL
newer than the one it holds (CRL number), so an old or forged list cannot
un-revoke anything. The last good CRL is kept on the data disk and
survives a reboot.

**Delivery.**

- Push: `POST /~!ops/crl`. The CRL's signature is the authorization, so
  any valid client certificate may push it, including a dark node's.
  `fortresskube` runs in the cluster with a node certificate. It would
  take `-crl-url http://vault.vault:8200/v1/pki/crl/pem`, fetch the CRL
  every few minutes, and push it through the tunnel. A CronJob with
  `curl` works too.
- Pull: an optional `crl_url` in `fortress.yml`, for a CA the edge can
  reach, fetched on a timer like `renew_interval`.
- `fortressctl ca revoke <dir> <cert>` writes a CRL signed by
  `<dir>/ca.key`, so the `fortressctl` CA uses the same mechanism. This
  replaces the idea of a serial-number denylist.

**Stale CRL.** A CRL expires (Vault's default is 72 hours) and is
re-signed regularly. When no fresh one arrives, the edge keeps enforcing
the last one and logs a warning. It does not refuse every certificate,
which would lock out dark nodes and operators exactly when something is
already broken.

**Vault side.** `vault write pki/config/crl auto_rebuild=true` keeps the
CRL fresh; `vault write pki/revoke serial_number=<serial>` revokes; the
CRL path (`/v1/pki/crl/pem`) needs no token. Delta CRLs
(`/v1/pki/crl/delta`) can come later.

**Tests.** e2e: revoke a node, an operator, and a log-reader certificate
through a pushed CRL, and check each is refused on its path. Also check
that an older CRL and a CRL from another CA are rejected, and that the
CRL survives a reboot.

## Hostnames per dark node

Any `node/<name>` certificate may publish any hostname. The next step
is to limit each node to the names it owns, for example a map in
`fortress.yml` from node name to hostnames or wildcard suffixes,
enforced when frps registers a route.

## Log push

`logx` is already a fan-out writer, so shipping logs to a collector is
one more writer, configured with a `logs:` key (syslog or HTTPS). The
pull API stays as the fallback. Vector's `http_client` source cannot
carry the pull API's cursor, so Vector users need this.

## XDP

- Replies to the edge's own connections pass statelessly: any TCP
  segment with ACK set to an ephemeral port gets through, and the kernel
  answers a stray one with a reset. A connection table filled from a TC
  egress hook would pass real replies only.
- ICMPv6 passes whole, for neighbour discovery, so the address answers
  IPv6 ping. Echo requests (type 128) could be dropped.

## Edge WAF

The edge sees every request in the clear, for every site, so it can run a
managed WAF the way Cloudflare and Airlock do. It adds to the gateway's
rules; it does not replace them.

**Engine.** [Coraza](https://github.com/corazawaf/coraza) v3 with the
OWASP Core Rule Set v4 (`coraza-coreruleset`, embedded): pure Go, no cgo,
the same engine Caddy, Traefik, and Envoy's Wasm filter use. Measured
(Coraza 3.7, CRS 4.25): +10 MB binary (+3.4 MB gzipped), about 19 MiB of
heap per compiled rule set, 90 ms to load, about 0.6 ms of CPU per
request at paranoia level 1. The cheap limits in
[operations.md](operations.md#limits) must keep running first, so a
flood never reaches it.

**Inspection.** Request headers and the first 128 KiB of `form`, `json`,
and `xml` bodies, handed back to the stream so uploads and streaming keep
working. No response inspection (it would break streaming), no body for
WebSocket upgrades. A thin adapter of our own, not Coraza's
`http.WrapHandler`, so the edge keeps control of streaming and silence.

**Policy per site.** `fortress.yml` sets the default:
`waf: {mode: detect, paranoia: 1}`, with `mode` one of `off`, `detect`,
`block`. A dark node overrides it for its own hostnames through frp's
proxy `metadatas` (`waf`, `waf.exclude` with CRS rule ids); its client
certificate already authenticates it. This needs the fork's `OnDomain`
hook to pass the proxy's metadata; when two proxies share a name, the
stricter setting wins. `fortresskube` maps a Gateway or HTTPRoute
annotation onto these. One compiled rule set per distinct policy,
cached.

**Rollout.** Every site starts in `detect` and moves to `block` once its
counters and logs are clean, as with Cloudflare's log mode.

**Tracing.** A block is `403` with an empty body and the
`Fortress-Request-Id`. The access log line gains `waf_action`,
`waf_rules`, and `waf_score`; from it, an exclusion is one rule id.
Blocks and detections are logged even with `access_log` off: they are
few and are what a false-positive report needs. Repeated high scores are
strikes toward the XDP ban.

**Measuring it.** `make waf-bench` ([development.md](development.md#waf-bench))
is the yardstick: open-appsec's 1,040,242 legitimate requests (false
positives) and 73,924 attacks (detection, per category), and GoTestWAF's
score, all pinned today at "no WAF". The WAF lands when those baselines
move the right way, and the bench's latency shows its cost. Open questions
the first runs raised:

- *Query cleaning.* `net/http/httputil` re-encodes a query with a `;` or a
  broken `%` escape (sorted, unparsable parameters dropped) before the
  request reaches a site. That breaks 1,342 of the legitimate requests
  (Google Fonts' `wght@400;700`, `&amp;` in ad beacons), and it also cuts
  4,662 attacks down to `GET /`. Copying the inbound `RawQuery` keeps
  sites working, but then Coraza's parse and the backend's can differ, a
  known WAF bypass. Decide with the WAF: raw query to the site, and the WAF
  inspects that raw query with a parser at least as lenient as common
  backends.
- *Refusals as blocks.* The edge refuses dot segments, backslashes and NUL
  in paths with `400`, which GoTestWAF counts as unresolved, not blocked
  (5 cases). A WAF block is `403`; decide whether these stay `400`.
- *Limits on real traffic.* 27 legitimate requests (analytics beacons)
  exceed `max_uri_size` (16 KiB) and 2 exceed `max_header_size` (64 KiB).

## Fair sharing between sites

The limits count per source. A flood from many addresses against one site
uses the edge's shared capacity and can slow the others. A fixed cap per
site would punish busy sites (a portal next to a small API), so the plan
is fairness only under load, as in Kubernetes API Priority and Fairness:
a global budget of requests in flight, no per-site limit while it has
room, and past about 80% of it a request is refused with `503` only when
its site holds more than an equal share. WebSockets and other long
streams stay out of the budget; the per-source connection cap bounds
them. The per-site counters in status show whether this is needed.

## Edge signals and feeds

- **TLS fingerprint.** Only the edge sees the ClientHello. It can compute
  JA4 and forward it as a header, so gateway rules can use it.
- **IP reputation.** Lists such as Spamhaus DROP loaded into the XDP
  block list on a timer. Needs `max_entries` above 1024 in `bpf/flod.c`.

## Silence gaps

The edge answers unknown names with nothing, except in these cases:

- Go's HTTP server answers a malformed request on port 80 (HTTP/1.1
  with no `Host`) with its own 400.
- QUIC closes a handshake for a name other than the tunnel with a QUIC
  error, not silence.

## Booting from the data disk

Today the ISO stays attached: it is the read-only OS, and the data disk
holds only state (policy, certificates, logs). Some providers detach an
ISO after install, charge for keeping one, or offer virtual media only
for an IPMI session. For them, a bootable disk image (`fortressctl
image`: a boot partition and a data partition) to import as a custom
image. What that needs:

- **Immutability.** Booting from read-only media means a compromised
  edge cannot persist a modified binary. On a writable disk, the boot
  files need signatures the boot checks, or a read-only partition
  verified at boot (dm-verity).
- **Upgrades and rollback.** Swapping the ISO is the upgrade today, and
  the old ISO is the rollback. A disk needs A/B boot slots and a way to
  write the new one, such as a signed image posted to the ops API.
- **Layout.** The data disk is whole-disk ext4 with no partition table,
  and the ISO boots BIOS only. A disk image needs a partition table, a
  boot loader written from Go, and likely UEFI.

## Baking without a pipeline

`fortressedge_iso`, the data source of the Terraform provider
([Sebiee/terraform-provider-fortressedge](https://github.com/Sebiee/terraform-provider-fortressedge)),
bakes on the machine that runs Terraform, and bakes are reproducible.
Still to come:

- **A public bake endpoint**: a URL whose parameters are the settings
  (`acme`, and `acme_ca` and `client_ca` base64-encoded, a couple of KiB),
  answering with the baked ISO, for any tool that can download a file.
  Reproducible bakes let anyone check what it serves: bake the same
  release and `fortress.yml` and compare checksums. `client_ca` takes one
  certificate only, so a second CA cannot hide in it.
