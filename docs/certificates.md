# Certificates and trust

## Client certificates

Dark nodes, operators, and log shippers authenticate with client
certificates from one client CA, set as `client_ca` in `fortress.yml`.
The edge holds that CA's certificate, never its key, and signs nothing.
A certificate's only URI SAN is a SPIFFE ID (the CN is never read). Its
trust domain is the edge's `fqdn` (the tunnel name), and its path is a
role and a name, so a certificate works on one edge only:

| Identity | May |
| --- | --- |
| `spiffe://tunnel.example.com/node/<name>` | join the tunnel (frp over WebSocket or QUIC), nothing else |
| `spiffe://tunnel.example.com/ops/<name>` | use the whole ops API: status, logs, the policy |
| `spiffe://tunnel.example.com/logs/<name>` | read logs, status, and the policy |

Anything else is refused: another trust domain, another role, a path
without a name, or more than one URI. The name (lower-case letters,
digits, `.`, `_`, `-`) identifies the node, operator, or shipper in the
edge's log. Certificates are valid for two years, and there is no
revocation list: a leaked key stays valid until it expires, unless you
move to a new CA (a new `client_ca`) and re-issue every certificate.
Revocation lists are planned; see [roadmap.md](roadmap.md#certificate-revocation-crl).

Create the CA once, on your machine, and bake its certificate into
`fortress.yml` as `client_ca` (see [provisioning.md](provisioning.md)).
Sign certificates with it, or with your own PKI:

```sh
fortressctl ca init tls                                           # tls/ca.crt, tls/ca.key
fortressctl ca client tls spiffe://tunnel.example.com/node/node1  # tls/clients/node/node1.crt
fortressctl ca client tls spiffe://tunnel.example.com/ops/alice
fortressctl ca client tls spiffe://tunnel.example.com/logs/filebeat
```

Keep `tls/ca.key` off the edge and off log hosts: whoever holds it can
enroll dark nodes, which can publish any hostname.

## Server certificates

HTTPS certificates come from an ACME directory, one per name, over
TLS-ALPN-01 on TCP 443: Let's Encrypt by default, or the directory
`fortress.yml` names in `acme`. They are stored under
`/var/fortressedge/certs` (and, for several edges, in Vault: see
[below](#several-edges-for-the-same-names)), and no other private key is
ever given to the edge. TCP 443 and QUIC present the same tunnel
certificate; QUIC shows it only to the tunnel name.

- **The tunnel name** is issued at boot, before anything listens.
- **A stored certificate the edge cannot use**, such as a damaged file
  or a key that is not the certificate's, is removed and ordered again,
  for the tunnel name as for a site, rather than stopping the boot.
- **A site** is issued as soon as a dark node publishes the hostname, not
  on the first visit. A name that comes back later reuses the certificate
  on disk.
- **Renewal** is a timer: every `renew_interval` (default 4h) the edge
  checks each certificate and renews the ones that are due. A certificate
  is due in the last third of its life, or earlier when the CA says so
  through ACME Renewal Info (ARI), as Let's Encrypt does before a mass
  revocation. After a long power-off, an expired certificate is renewed
  before the edge serves it; one that is merely due waits for the timer.
- **A name no dark node publishes** is no longer checked or renewed. Its
  certificate stays on disk until the name returns.
- **New orders are capped**, every name together: 30 at once, then one
  every two minutes; renewals are not held back. A name whose order
  failed is not ordered again for a minute, doubling with each failure
  up to six hours, even when its dark node publishes it again; its
  failures are forgotten a day after the last. A dark node may publish
  any hostname, and each new one costs an order: the cap keeps one that
  publishes many from spending the CA's limits for every other name
  (Let's Encrypt allows an account 300 new orders in 3 hours), but it can
  still delay other new names on the edge, and with wildcard DNS it can
  use up a registered domain's 50 certificates a week.
- **Wildcard** routes get no certificate: TLS-ALPN-01 cannot issue one.

For a CA with short-lived certificates, keep `renew_interval` well under
a tenth of their life, such as `1h` for 24-hour certificates. certmagic
treats a certificate with less than five intervals left as urgent.

A private ACME directory, such as Vault or step-ca, whose HTTPS
certificate comes from your own CA:

```yaml
# fortress.yml
acme: https://acme.internal.example/v1/pki/acme/directory
acme_ca: |
  -----BEGIN CERTIFICATE-----
  ...the CA that signed the directory's HTTPS certificate...
  -----END CERTIFICATE-----
renew_interval: 1h
```

`acme_ca` replaces the system roots for the directory connection only.
Dark nodes then need that directory's issuing CA in `trustedCaFile`.

The ACME account and every certificate are stored per directory URL
(`/var/fortressedge/certs/acme/<directory>/` and
`certs/certificates/<directory>/`). An ISO baked with another `acme`
therefore registers a new account at boot and obtains a new certificate
for the tunnel name and each published site, as their dark nodes
reconnect: mind the directory's rate limits when an edge serves many
names. The old directory's files stay on the data disk, unused.

## Several edges for the same names

Edges that serve the same names (two addresses for one site, or one that
takes over from another) can share their certificates, ACME account,
and challenges through a path in Vault's KV v2 engine:

```yaml
# fortress.yml, the same on each edge
vault: https://vault.internal.example:8200
vault_ca: |
  -----BEGIN CERTIFICATE-----
  ...the CA, or chain, that signed Vault's HTTPS certificate...
  -----END CERTIFICATE-----
vault_mount: edge-certs   # a KV v2 mount
vault_path: prod/public   # these edges' path in it, and nothing else's
vault_role_id: ...        # the edges' AppRole
```

```yaml
# user-data, on each edge's NoCloud drive (see provisioning.md)
vault_secret_id: ...      # this edge's own
```

- **A certificate is ordered once.** The edge that orders a name holds a
  lock in Vault meanwhile (a check-and-set write, so two cannot both take
  it); the others wait, then use what it stored. An edge that boots with
  an empty disk starts with the certificates already there.
- **A lock does not hold forever.** Its holder writes it again every 20
  seconds. An edge that sees no new write for a minute, by its own clock
  (no other clock, and nothing written in the lock, counts), takes it
  over: its holder died. One that has waited two minutes on a lock still
  being written gives up and orders by itself, so a stuck holder or a
  forged lock costs a boot two minutes at most. An order that keeps
  failing holds its lock while it is retried, and one that waits for the
  order cap holds it meanwhile, so another edge then orders the same
  name too. Edges of earlier releases on the same path still take a lock
  over by the expiry its holder wrote, by their clocks: the rule holds
  once every edge on the path runs this one.
- **A validation can reach any of them.** With two addresses in DNS, the
  CA's TLS-ALPN-01 connection may reach the edge that did not order. It
  answers from the challenge the other stored in Vault, as long as it
  serves the name too: a dark node publishes it there.
- **Renewals** are shared the same way: whichever edge finds a
  certificate due renews it, and the others load the new one when their
  own check comes.
- **Vault is not in the path of a request.** Each edge keeps every
  certificate on its data disk too and serves from memory. When Vault
  cannot be reached, it boots, serves, and renews from its disk alone (an
  unreachable Vault costs a boot at most two seconds, once), and it
  writes what Vault missed once Vault answers again. Vault, as the truth,
  wins on the next read: a certificate another edge renewed or removed
  meanwhile is not brought back.
- **An edge that had certificates on disk before** writes them to Vault
  at its first boot with it, rather than order them again.
- **What Vault returns is checked before an edge uses it** or copies it
  to its disk: a certificate must be for its name, valid now (it may
  start up to five minutes ahead), and stored with its key; its
  metadata must be what certmagic reads, and challenges JSON; no value
  may exceed 64 KiB. An edge logs anything else and keeps its disk's
  copy; with none, it orders the name again. An expired certificate it
  has no copy of is taken and renewed. This keeps a value no edge could
  use (a damaged file, a wrong name, a mismatched or expired pair) from
  reaching every edge. A well-formed certificate for the right name
  passes, from any CA: whoever holds the AppRole can still replace one,
  and reads every key on the path.

The AppRole's policy should allow its path and nothing else:

```hcl
path "edge-certs/data/prod/public/*"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "edge-certs/metadata/prod/public/*" { capabilities = ["create", "read", "update", "delete", "list"] }
```

Its tokens may be short-lived and renewable: the edge renews them, and
logs in again when Vault forgets them. Give each edge a secret ID of its
own, bound, with its tokens, to that edge's address, and without expiry
(the role's `secret_id_ttl` 0, the default), since the edge logs in at
each boot:

```sh
vault write auth/approle/role/edge-prod/secret-id \
  cidr_list=10.0.10.21/32 token_bound_cidrs=10.0.10.21/32
```

A secret ID taken from one edge's drive is then useless anywhere else,
and destroying it cuts off that edge alone. The secret ID is never in
the ISO, and the ops API never shows it. Every edge with the AppRole can
read the private keys of every name on the path: give one path to edges
that serve the same names, and keep each edge's `user-data` as you keep
the keys.

`cert_store` in the [status](operations.md) says whether Vault is
`reachable`, when a call last worked (`last_ok`), failed calls by
operation, the last error, and how many keys wait to be written
(`pending`); `fortressedge_cert_store_errors_total{op}`,
`fortressedge_cert_store_last_success_timestamp_seconds`, and
`fortressedge_cert_store_pending` are the same in the metrics.

## Which names get an answer

The edge answers the tunnel name and each hostname a dark node currently
publishes, including names a wildcard route covers. Everything else gets
no bytes back:

- A TLS handshake for another name, or with no name, is closed before the
  edge sends a certificate or an alert.
- Plain HTTP for another name, and plain HTTP on the TLS port, are closed
  without a response. Port 80 redirects only the names HTTPS serves.
- A name whose dark node left goes silent the same way, once
  `tunnel_grace` (in the policy, 10 minutes by default) is up.

Until then, and for that long after a boot for the names whose
certificates are on the data disk, the edge answers such a name with its
last certificate and `503 Service Unavailable`, `Retry-After: 1`, and an
empty body, so browsers and HTTP clients retry while a dark node or the
edge restarts. A wildcard route that covers the name gets none of its
requests, during the grace or after it. Only names a dark node published,
whose certificates are still valid, are answered: they are public in
Certificate Transparency logs already, and a name nobody published stays
silent. `tunnel_grace: 0` turns this off.

A name is one dark node's, by its certificate, while any of its proxies
publishes it, and for `tunnel_grace` after the last leaves: another node
that publishes it meanwhile is refused, so it cannot take the name while
its node reconnects. A changed `tunnel_grace` applies at once, to names
already in their grace too. The edge does not keep this across its own
reboot yet: right after a boot, the first node to publish a name has it.

A published name whose origin does not answer gets `502`, or `504` after
a minute without response headers (`response_header_timeout` in the
[policy](operations.md#limits)), with an empty body. Nothing the edge
sends names frp or a version.

The tunnel name needs a client certificate. A request that names a site
in TLS and the tunnel in `Host` gets `421`.

Port 80 sends nothing to a request it cannot read either (no `Host`, a
bad one, an unknown HTTP version, headers over `max_header_size`): Go's
HTTP server would answer those with its own `400`, `431` or `505`. It
closes each connection after its one redirect, so the request after it
gets nothing either.

Some bytes remain: the QUIC listener closes a handshake for another name
with a QUIC error rather than silence; and ICMPv6 passes XDP, so the
address answers IPv6 ping.
