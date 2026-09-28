# Operations

There is no shell and no sshd. Operators and log shippers use a small
HTTPS API on the tunnel name, the same TCP 443 handshake dark nodes use.
The client certificate's role decides what it may call (see
[certificates.md](certificates.md)).

| Endpoint | Who | What it does |
| --- | --- | --- |
| `GET /~!ops/status` | `ops`, `logs` | JSON: boot id, uptime, network, tunnel, QUIC, open connections, limit and XDP counters, per-site counters, log cursor |
| `GET /~!ops/logs` | `ops`, `logs` | this boot's log as text; `?follow` streams new lines |
| `GET /~!ops/logs?format=ndjson` | `ops`, `logs` | one `{"line": ...}` object per line, for shippers |
| `GET /~!ops/access` | `ops`, `logs` | the access log (`access_log: true`), one JSON object per line; `?follow` and `?cursor=` as for logs |
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

## Access log

With `access_log: true` in `fortress.yml`, every request for a published
site is one JSON line in `/var/log/fortressedge/access/`, apart from the
edge's own log. It is off by default: it is large, and visitor addresses
are personal data.

```json
{"time":"2026-09-24T10:02:17.114Z","id":"01925f3a-…","ip":"203.0.113.7","site":"app.example.com","method":"GET","path":"/api/items","proto":"HTTP/2.0","status":200,"in":0,"out":5120,"ms":41,"ua":"Mozilla/5.0 …"}
```

`path` has no query string, which often carries tokens. `status` 499
means the visitor left before the response; 101 is a WebSocket, whose
`ms` is how long it stayed open and whose traffic is not in `in`/`out`.

`id` is also sent to the visitor as `Fortress-Request-Id` and to the dark
node as `X-Request-Id`, replacing any the visitor sent. A visitor who
quotes it finds the line here and, when the gateway logs `X-Request-Id`,
in the gateway's log too. Envoy keeps an incoming `x-request-id` only
from a trusted source; see its `preserve_external_request_id`.

The log starts a new file at `access_log_max_size` (default `8MiB`) and
keeps `access_log_max_files` files (default 3, the current one included),
deleting the oldest, so it never takes more than their product: 24 MiB
by default. That fits a 64 MiB data disk,
which also holds certificates and the edge's log; the edge warns at boot
when the access log could take more than half of its disk. Each new file
gets a new id (`<boot-id>`, then `<boot-id>.1`, `.2`, …), and a rotated
file is kept as `<id>.log`.

`GET /~!ops/access` serves it with the same cursor, `follow`, and gap
rules as the edge's log, always as NDJSON (the lines are JSON already).
A cursor into any kept file continues through every newer one, so a
shipper that polls before the oldest file is deleted loses nothing. For
Filebeat, copy the input above with `url: …/~!ops/access`; each event is
then the request record itself.

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
  max_body_size: 512MiB             # 0: no limit (leave it to the gateway)
  max_connections: 0                # reboot. All sources, per port; 0: RAM ÷ 64 KiB, 1024–32768
  max_header_size: 64KiB            # reboot. Request line and headers
  max_http2_streams: 100            # reboot. Concurrent streams per HTTP/2 connection
```

A visitor keeps what it has used when a rate changes: its allowance
refills at the new rate, up to the new burst. A lower
`connections_per_source` closes nothing already open; the source's new
connections are refused until its count drops below it. `exempt` applies at once too.

| Over the limit | What the source sees |
| --- | --- |
| `new_connections_per_second` | its SYN is dropped; the client retries after a second or more |
| `connections_per_source` | the connection is closed at accept, before any byte |
| `max_connections` | accept waits until a connection closes |
| `requests_per_second` / `request_burst` | `429` with `Retry-After: 1` |
| `max_header_size` | `431` |
| `max_uri_size` | `414` |
| `max_body_size` | the upload is cut off; the origin sees a short body |
| `max_http2_streams` | the client queues further requests; the server announces the limit when the connection opens |

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
and for each published site under `sites` its `requests`, `in_flight`,
`bytes_in`, `bytes_out`, and responses by class (`2xx` … `5xx`).

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
