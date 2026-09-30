# Operations

There is no shell and no sshd. Operators and log shippers use a small
HTTPS API on the tunnel name, the same TCP 443 handshake dark nodes use.
The client certificate's role decides what it may call (see
[certificates.md](certificates.md)).

| Endpoint | Who | What it does |
| --- | --- | --- |
| `GET /~!ops/status` | `ops`, `logs` | JSON: boot id, uptime, network, tunnel, QUIC, open connections, limit and XDP counters, per-site counters, log cursor |
| `GET /~!ops/metrics` | `ops`, `logs` | the same counters and more in Prometheus's text format, for a scraper; see [Metrics](#metrics) |
| `GET /~!ops/logs` | `ops`, `logs` | this boot's log as text; `?follow` streams new lines |
| `GET /~!ops/logs?format=ndjson` | `ops`, `logs` | one `{"line": ...}` object per line, for shippers |
| `GET /~!ops/access` | `ops`, `logs` | the access log (the policy's `access_log`), one JSON object per line; `?follow` and `?cursor=` as for logs |
| `GET /~!ops/policy` | `ops`, `logs` | `policy.yml` as last applied (empty: the defaults), its SHA-256 as the ETag |
| `PUT /~!ops/policy` | `ops` | replaces the policy whole; `fortressctl apply` sends it, see [provisioning.md](provisioning.md#policyyml-apply-while-the-edge-runs) |

A dark-node certificate gets 403 everywhere, and so does a log-reader
certificate on `PUT`. Refusals and policy changes are logged with the
caller's SPIFFE ID. The edge has no endpoint that signs certificates.

```sh
# --cacert is the root the edge's ACME certificates chain to; nothing for Let's Encrypt.
curl --cacert acme-root.crt --cert tls/clients/ops/alice.crt --key tls/clients/ops/alice.key \
  --resolve tunnel.example.com:443:203.0.113.10 'https://tunnel.example.com/~!ops/logs?follow'
```

## Logs

The consoles and `/var/log/fortressedge/current.log` on the data disk get
the same lines: the edge's own, kernel errors, frp, and certificate
events. The previous boot is kept as `previous.log`. Logs are about the
edge; requests go to the [access log](#access-log).

### Shipping without gaps

Every logs response carries `X-Log-Cursor: <file-id>:<offset>`. Send it
back as `?cursor=` to get exactly the lines written since. Offsets make a
refetch idempotent, and the file id (the kernel's boot id, also the first
line of each log file) makes reboots visible: a cursor from the previous
boot drains `previous.log` first, then continues into the current one.
When the cursor's file is older than what is kept, the edge answers from
the start of the current log with `X-Log-Gap: true`. That is the only way
lines are lost, and it is signalled. `?cursor=now` starts at the end;
`/~!ops/status` returns the current cursor as `log_cursor`.

Delivery is at least once: a shipper that polls at least once per boot
loses nothing, and may see duplicates after a crash. Give a shipper its
own log-reader certificate, never an operator's: a log host is rarely
the best-guarded machine, and a `logs/<name>` key can only read.

```sh
fortressctl ca client tls spiffe://tunnel.example.com/logs/filebeat
```

Filebeat's `httpjson` input handles the cursor:

```yaml
filebeat.inputs:
  - type: httpjson
    id: fortressedge
    interval: 30s
    request:
      method: GET
      url: https://tunnel.example.com/~!ops/logs?format=ndjson
      ssl:
        certificate: /etc/filebeat/filebeat.crt   # tls/clients/logs/filebeat.crt
        key: /etc/filebeat/filebeat.key
      transforms:
        - set:
            target: url.params.cursor
            value: '[[.cursor.pos]]'
            default: now
    response:
      decode_as: application/x-ndjson
    cursor:
      pos:
        value: '[[.last_response.header.Get "X-Log-Cursor"]]'
        ignore_empty_value: true
```

Vector's `http_client` source cannot carry a cursor. Until the edge can
push logs, scrape the whole log with it and deduplicate downstream.

### Proxy errors

When frps cannot proxy a site request, the edge logs one warning that
says where and for whom, and counts it for the site
(`fortressedge_proxy_errors_total`):

```
level=WARN msg="proxy error" site=vault.example.com method=GET path=/v1/sys/health ip=203.0.113.7 id=01925f3a-… trace_id=4bf92f35… span_id=00f067aa… reason=eof_body elapsed_ms=812 sent=16384 err="unexpected EOF"
```

`elapsed_ms` is the time since the request arrived and `sent` the
response bytes the visitor already had. `reason` is where it failed:

| `reason` | The visitor gets | Usually |
| --- | --- | --- |
| `no_route` | `404` | the dark node unpublished the name while the request came in |
| `dial` | `502` | no work connection to the dark node: it is gone, or its tunnel is broken |
| `send` | `502` | the request could not be written to the dark node |
| `header_timeout` | `504` | the origin sent no response headers within `response_header_timeout` |
| `eof_headers` | `502` | the origin closed the connection before its headers: down, or restarting |
| `eof_body` | a response cut short | the origin's connection broke mid-response: a pod restarting, say |

A visitor who leaves before the origin answers is not an error; it is a
debug line, and `499` in the access log. A body over `max_body_size` is
the visitor's, answered `413`, and counted as a limit hit instead.

## Access log

With `access_log: true` in the policy (`policy.yml`), every request for
a published site is one JSON line in `/var/log/fortressedge/access/`,
apart from the edge's own log. It is off by default: it is large, and
visitor addresses are personal data. `fortressctl apply` turns it on and
off while the edge runs, for every site or, under `sites`, for one:

```yaml
access_log: true            # every site...
access_log_max_size: 8MiB
access_log_max_files: 3
sites:
  vault.example.com:
    access_log: false       # ...but this one
```

With `access_log: false` (or left out) and one site set to `true`, only
that site is logged.

```json
{"time":"2026-09-24T10:02:17.114Z","id":"01925f3a-…","ip":"203.0.113.7","site":"app.example.com","method":"GET","path":"/api/items","proto":"HTTP/2.0","status":200,"in":0,"out":5120,"ms":41,"start":"2026-09-24T10:02:17.073Z","us":41237,"headers_us":40112,"ua":"Mozilla/5.0 …","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7"}
```

`path` has no query string, which often carries tokens. `status` 499
means the visitor left before the response; 101 is a WebSocket, whose
`ms` is how long it stayed open and whose traffic is not in `in`/`out`.
`start` is when the request arrived, `us` its whole time in
microseconds, and `headers_us` the time until the response headers went
to the visitor, which is the origin's answering time plus the tunnel.
`route` is the published name when a wildcard routed the request, and
`error` the proxy error's `reason` when there was one. The trace fields
are under [Tracing](#tracing).

`id` is also sent to the visitor as `Fortress-Request-Id` and to the dark
node as `X-Request-Id`, replacing any the visitor sent. A visitor who
quotes it finds the line here and, when the gateway logs `X-Request-Id`,
in the gateway's log too. Envoy keeps an incoming `x-request-id` only
from a trusted source; see its `preserve_external_request_id`.

The log starts a new file at `access_log_max_size` (default `8MiB`) and
keeps `access_log_max_files` files (default 3, the current one included),
deleting the oldest, so it never takes more than their product: 24 MiB
by default. That fits a 64 MiB data disk,
which also holds certificates and the edge's log; the edge warns when
the access log could take more than half of its disk. Turning the log
off keeps its files; a new size or count applies from the next write. Each new file
gets a new id (`<boot-id>`, then `<boot-id>.1`, `.2`, …), and a rotated
file is kept as `<id>.log`.

`GET /~!ops/access` serves it with the same cursor, `follow`, and gap
rules as the edge's log, always as NDJSON (the lines are JSON already).
A cursor into any kept file continues through every newer one, so a
shipper that polls before the oldest file is deleted loses nothing. For
Filebeat, copy the input above with `url: …/~!ops/access`; each event is
then the request record itself.

## Clock

Boot steps the clock to NTP time before anything that checks a
certificate starts. After that the edge keeps it there: it polls its
servers every 64 seconds, lengthening to 1024 seconds while the offset
stays under half a millisecond. For the first ten minutes it leaves the
clock alone and measures how fast it drifts, then tells the kernel that
frequency error, as ntpd does without a drift file, and slews away the
few milliseconds that built up meanwhile; from then on it hands
each offset to the kernel's NTP discipline (the same PLL ntpd drives),
which slews it away and follows the frequency as it wanders. Time never
jumps. An offset over 128 ms
behind is stepped forward, and logged; a clock ahead is slewed back, and
stepped only when more than a second ahead, which normal running never
is. Traces need the edge's clock to agree with the cluster's: the access
log's `start` is only as good as it.

Name several servers in `fortress.yml`, so one that is wrong is outvoted:

```yaml
ntp: [ntp11.metas.ch, ntp12.metas.ch, ntp13.metas.ch]
```

Each poll takes four samples from each server, two seconds apart, and
keeps each server's fastest, whose offset the network distorts least.
The servers' offsets, each within its root distance, must then overlap
for a majority of all the servers named: the edge follows their weighted
mean, and ignores a server that disagrees (a falseticker, logged and
counted). With fewer agreeing than a majority, whether the others are
silent or wrong, nothing moves, and the clock runs on the frequency the
kernel learned. `pool.ntp.org` (the default) and its subdomains are
pools: their first four addresses are servers of their own. The servers
stay in `fortress.yml` rather than the policy: the clock decides whether
a certificate is valid, so moving it is a matter of trust, like the CAs.

Warnings: no majority for 30 minutes, an offset still over 10 ms after a
correction, a step, and a falseticker. `/~!ops/status` has `clock`
(`offset` in seconds, `synced_at`, `server`, `stratum`, `poll`, `steps`,
`frequency_ppm`, and `frequency_measured`, false for those first ten
minutes), and `/~!ops/metrics` the `fortressedge_clock_*` and
`fortressedge_ntp_*` metrics below.

## Tracing

Every site request is one hop of a [W3C trace](https://www.w3.org/TR/trace-context/).
The edge gives it a span id of its own and sends the origin a
`traceparent` whose parent is that span, so an app's OpenTelemetry spans
hang under the edge's, and Envoy passes the header on untouched. The
visitor gets the trace id as `Fortress-Trace-Id`, next to
`Fortress-Request-Id`.

By default the edge trusts no visitor's `traceparent`: every request
starts a trace of its own, sampled, so an outsider cannot choose the
trace id a request lands in, nor send a `tracestate` on. A valid
`traceparent` the visitor sent is kept in the access log as
`link_trace_id` and `link_span_id`, to become a span link. When the
visitors are your own services, continue their traces instead:

```yaml
trace:
  trust_incoming: true
```

Then a valid `traceparent` keeps its trace id and flags, its span id
becomes the access log's `parent_id`, and its `tracestate` goes on
unchanged; a missing or malformed one starts a new trace.

The edge exports no spans: the cluster behind it is dark, so there is no
collector to reach. The access log line has what a span needs
(`trace_id`, `span_id`, `parent_id`, `start`, `us`, `status`, `site`,
`method`, `path`), and a shipper that pulls `/~!ops/access` turns each
line into the edge's span.

## Metrics

`GET /~!ops/metrics` serves the Prometheus text format to an operator or
a log-reader certificate. Like the rest of the ops API it is never rate
limited. Counters start at zero at boot, which
`fortressedge_boot_time_seconds` dates. A label set that never happened
is left out, so an edge with a few dozen sites has a few hundred series.

```yaml
scrape_configs:
  - job_name: fortressedge
    scheme: https
    metrics_path: /~!ops/metrics
    tls_config:
      ca_file: /etc/prometheus/acme-root.crt   # leave out for Let's Encrypt
      cert_file: /etc/prometheus/metrics.crt   # tls/clients/logs/metrics.crt
      key_file: /etc/prometheus/metrics.key
    static_configs:
      - targets: [tunnel.example.com:443]
```

`site` is the name a dark node published: `*.example.com` for every
request a wildcard route carried, so the label cannot grow with the
names visitors make up.

| Metric | Labels | What |
| --- | --- | --- |
| `fortressedge_build_info` | `version`, `go_version` | 1 |
| `fortressedge_boot_time_seconds` | | when the edge started |
| `fortressedge_http_requests_total` | `site`, `code_class` | site requests by status class |
| `fortressedge_http_request_duration_seconds` | `site` | histogram of the time to the response headers; buckets 5ms to 60s |
| `fortressedge_http_request_seconds_total` | `site` | requests' whole time, bodies and WebSockets included |
| `fortressedge_http_bytes_total` | `site`, `direction` | body bytes `in` and `out` |
| `fortressedge_http_requests_in_flight` | `site` | requests being served |
| `fortressedge_proxy_errors_total` | `site`, `reason` | see [Proxy errors](#proxy-errors) |
| `fortressedge_limit_hits_total` | `site`, `limit` | refusals: `rate`, `uri`, `body`, `malformed`, and `connections` (no site: refused at accept) |
| `fortressedge_connections`, `fortressedge_visitors` | | open connections; sources tracked |
| `fortressedge_bans_total`, `fortressedge_banned_sources` | | bans since boot; banned now |
| `fortressedge_tunnel_clients` | `node` | open tunnel connections by dark node (`node/<name>`) |
| `fortressedge_tunnel_logins_total`, `fortressedge_tunnel_proxies` | | frpc logins; proxies registered |
| `fortressedge_published_names` | | names published, wildcards included |
| `fortressedge_work_connections` | `state` | work connections: `pooled` by frpc ahead of a request, `idle` after one, `active` |
| `fortressedge_work_connections_discarded_total` | | work connections frpc sent beyond its pool, closed unused |
| `fortressedge_certificate_not_after_seconds` | `name` | when the served certificate expires: the tunnel name and each site |
| `fortressedge_certificate_obtains_total`, `fortressedge_certificate_renewals_total` | `name`, `result` | orders, `ok` or `failed` |
| `fortressedge_xdp_packets_total` | `action`, `reason` | every packet XDP saw; see below |
| `fortressedge_xdp_ethertype_drops_total` | `ethertype` | non-IP frames by EtherType: `0x88cc` LLDP, `llc` 802.3 (STP) |
| `fortressedge_kernel_tcp_total` | `counter` | the kernel's TCP counters, as `kernel_tcp` in status |
| `fortressedge_clock_offset_seconds` | | the clock's offset from NTP time at the last poll, before its correction; positive: behind |
| `fortressedge_clock_sync_timestamp_seconds` | | when the servers last agreed |
| `fortressedge_clock_steps_total` | | steps after boot's |
| `fortressedge_clock_poll_seconds`, `fortressedge_clock_frequency_ppm` | | the poll interval; the frequency correction the kernel learned |
| `fortressedge_clock_stratum` | `server` | the stratum of the server the clock follows most closely |
| `fortressedge_ntp_queries_total` | `server`, `result` | queries: `ok`, `error` (no answer), `invalid` (unsynchronized, a kiss of death), `dns` |
| `fortressedge_ntp_round_trip_seconds` | `server` | each server's least round trip in its last poll |
| `fortressedge_ntp_falsetickers_total` | `server` | polls that found a server's time off from the others' |

XDP's reasons: `pass` for `service` (HTTP, HTTPS, QUIC), `reply` (to the
edge's own connections), `arp`, `icmp6`, `icmp3`, `ntp`, `dns`; `drop` for
`block` (block list and bans), `port`, `synrate`, `ntprate`, `dnsrate`,
`ethertype` (not IPv4, IPv6, or ARP), `proto` (an IP protocol other than
TCP, UDP, ICMP: VRRP, IGMP, GRE…), `icmp` (ICMPv4 other than unreachable),
`fragment` (an IPv4 fragment after the first), and `truncated` (a header
cut short). The header size limit (`431`) is enforced by Go's server
before the edge sees the request, so no counter has it.

## Limits

The edge protects itself and shares itself fairly between sources. It
does not know sites' routes or users: per-route and per-user limits,
authentication, and a full WAF belong to the gateway behind the dark
node.

A source is one IPv4 address or one IPv6 /64, since one user usually
holds a whole /64.

Each limit is a key under `limits:` in the policy (`policy.yml`). A key
left out keeps its default, and `0` turns a rate or count off. A change
through `fortressctl apply` applies at once, without dropping
connections, except for the three keys marked *reboot*: Go's HTTP server
and the connection cap fix those when they start, so the edge reboots
into the new policy.

```yaml
limits:
  connections_per_source: 256       # open connections
  requests_per_second: 150          # sustained, per source
  request_burst: 600                # at once: several heavy pages from one address
  new_connections_per_second: 64    # TCP SYNs, dropped in XDP
  new_connection_burst: 128
  ban: 15m                          # how long; 0: refuse, never ban
  ban_after: 200                    # refusals that earn a ban...
  ban_window: 10s                   # ...within this time
  max_uri_size: 16KiB
  max_body_size: 512MiB             # 0: no limit (leave it to the gateway). Per site too
  response_header_timeout: 60s      # wait for the origin's response headers; whole seconds, 1s–10m. Per site too
  max_connections: 0                # reboot. All sources, per port; 0: RAM ÷ 64 KiB, 1024–32768
  max_header_size: 64KiB            # reboot. Request line and headers
  max_http2_streams: 100            # reboot. Concurrent streams per HTTP/2 connection
```

`max_body_size` and `response_header_timeout` are the edge's defaults. A
site that needs large uploads or long polls gets its own under `sites`,
by the name its dark node publishes (a wildcard such as `*.example.com`
too; a name's own entry wins over its wildcard's):

```yaml
sites:
  upload.example.com:
    max_body_size: 4GiB
  argocd.example.com:
    response_header_timeout: 10m
```

A visitor keeps what it has used when a rate changes: its allowance
refills at the new rate, up to the new burst. A lower
`connections_per_source` closes nothing already open; the source's new
connections are refused until its count drops below it. `exempt` applies at once too.

`response_header_timeout` limits the origin, not a source: how long a
request waits for its response headers. A site that sends them only with
a stream's first event (server-sent events, long polling, Argo CD's
`/api/v1/stream/applications`) has the stream cut with a `504` when no
event comes within it, so raise it for such sites. It no longer applies
once the headers arrive. A visitor who leaves before then (a reload, a
closed tab) is not a warning: it is logged at debug, below what the edge
logs.

| Over the limit | What the source sees |
| --- | --- |
| `new_connections_per_second` | its SYN is dropped; the client retries after a second or more |
| `connections_per_source` | the connection is closed at accept, before any byte |
| `max_connections` | accept waits until a connection closes |
| `requests_per_second` / `request_burst` | `429` with `Retry-After: 1` |
| `max_header_size` | `431` |
| `max_uri_size` | `414` |
| `max_body_size` | `413`; a body announced as larger never reaches the origin, a streamed one is cut off there |
| `max_http2_streams` | the client queues further requests; the server announces the limit when the connection opens |
| `response_header_timeout` | `504` with an empty body |

Each refused request (`429`) or connection is a strike. A source with
more than `ban_after` strikes within `ban_window`, counted from its first
strike, is banned in XDP for `ban`: every packet from it is dropped, with
no answer. Dropped SYNs (`new_connections_per_second`) happen in XDP and
are never strikes. With the defaults, that is more than twenty refusals
a second for ten seconds:

| Source | With the defaults |
| --- | --- |
| a browser loading a page of 500 requests | within the burst; nothing refused |
| three people behind one address loading 200-request pages at once | within the burst; nothing refused |
| a client that honors `Retry-After: 1` | a few `429`s; never banned |
| a script at 151 requests a second | about one `429` a second once its burst is spent; never banned |
| a script at 300 requests a second | about 150 `429`s a second once its burst is spent (after 4 s); banned about 1.3 s later |
| a flood at 1000 requests a second | burst spent in under a second; banned a quarter of a second later |
| a burst of new connections | SYNs over the rate dropped; never banned |

For scale: one vCPU serves about 1,500 site requests a second end to
end (TLS, frp, a small origin response), and the limit check costs
about 140 ns of that. One source at the default rate can take about a
tenth of such an edge; the limits cannot stop many sources at once
(see below).

A rejected request for a name the edge does not serve gets no response,
like every request for it.

**When a limit bites.** The edge logs `edge: source refused src=<source>
by=<limit>` the first time a source is refused, then at most once a
minute per source (and about ten such lines a minute in all, so a flood
cannot fill the log), and `edge: source banned` for each ban.
`/~!ops/status` has the limits in force under `limits`, and counters:
`http_rate_limited`, `conn_limited`, `bans`, and `xdp_drop_synrate` for
the XDP SYN limit. A ban lasts `ban` and ends by itself; to lift it
sooner, reboot the edge. Then raise the limit, or add the source to
`exempt`.

Addresses in `exempt` skip the per-source limits and bans: a load
generator, a monitoring probe, an office behind one address. The XDP SYN
rate still applies.

The limits do not cap a site's traffic through its dark node. A request
counts against the visitor who sent it; the dark node carries all of its
sites' requests inside one long-lived tunnel connection (frp multiplexes
them over the WebSocket, or as QUIC streams). That connection counts
toward its address's connection cap like any other, and the request that
opens it, which carries a verified client certificate, is never rate
limited.

Requests no site should get are refused with an empty body, and appear
in site counters and the access log like any other: `TRACE`,
`TRACK`, and `CONNECT` with `405`, and a path with `.` or `..` segments
(also percent-encoded), a NUL byte, or a backslash with `400`. Browsers
resolve dot segments before sending, so only probes send them, and
refusing is safer than cleaning up a path the gateway might read
differently.

The limits are per source, not per site: a flood from many addresses
against one site can slow the others. Fair sharing between sites under
load is on the [roadmap](roadmap.md#fair-sharing-between-sites).

Under `kernel_tcp`, status also has the kernel's own TCP counters since
boot: `listen_overflows` and `listen_drops` (the accept queue was full),
`syncookies_sent` (the SYN queue was full), `backlog_drops`, and the
resets it sent (`out_rsts`). If these stay at zero while clients see
refused or reset connections, the cause is outside the edge.

`/~!ops/status` counts all of this: `http_rate_limited`, `conn_limited`,
`bans`, `visitors` (sources tracked now), `http_rejected` (malformed),
and for each published name under `sites` its `requests`, `in_flight`,
`bytes_in`, `bytes_out`, and responses by class (`2xx` … `5xx`). A
wildcard route's requests count under the wildcard. `/~!ops/metrics` has
the same per site, and more.

## Console

The VGA and serial consoles keep a status grid at the top: stage, tunnel,
ACME server, QUIC, listeners, disk, NTP, address, gateway, and DNS, under a
header with uptime, open connections on TCP 80 and 443, CPU, and memory,
refreshed every second. READY and CONNECTIVITY are green
when up and red when not. The log scrolls below. A config that cannot
boot (see [provisioning.md](provisioning.md#when-an-edge-cannot-start))
stays on the console with how to fix it until the power button; any
other failed boot prints the error and reboots after 30 seconds.

## Why mutual TLS and not SSO

The edge is the machine that must stay debuggable when everything else is
down, so log access should not depend on an identity provider being
reachable. The CA works offline, and `curl` is the only client needed.
OIDC could be added later as another credential on the same endpoints.
