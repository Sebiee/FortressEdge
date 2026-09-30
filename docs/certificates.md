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
`/var/fortressedge/certs`, and no other private key is ever given to the
edge. TCP 443 and QUIC present the same tunnel certificate; QUIC shows it
only to the tunnel name.

- **The tunnel name** is issued at boot, before anything listens.
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
edge restarts. Only names a dark node published, whose certificates are
still valid, are answered: they are public in Certificate Transparency
logs already, and a name nobody published stays silent. `tunnel_grace:
0` turns this off.

A published name whose origin does not answer gets `502`, or `504` after
a minute without response headers (`response_header_timeout` in the
[policy](operations.md#limits)), with an empty body. Nothing the edge
sends names frp or a version.

The tunnel name needs a client certificate. A request that names a site
in TLS and the tunnel in `Host` gets `421`.

Some bytes remain: Go's HTTP server answers a malformed request on port
80 (HTTP/1.1 with no `Host`) with its own `400`; the QUIC listener closes
a handshake for another name with a QUIC error rather than silence; and
ICMPv6 passes XDP, so the address answers IPv6 ping.
