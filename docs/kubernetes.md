# Kubernetes

`fortresskube` is frpc for a cluster. It reads a normal frpc config and
also publishes every hostname of the HTTPRoutes that one Gateway has
accepted. Each hostname becomes its own http proxy, forwarded to the
Gateway's Service, so the edge gets a certificate for each exact name. A
new app needs only its HTTPRoute; deleting the route, or the Gateway
rejecting it, removes the name, and other names keep running.

- The Gateway's `allowedRoutes` decides which namespaces may publish:
  only routes with `Accepted=True` from that Gateway count.
- Wildcards and routes without `hostnames` are skipped.
- The Gateway needs a plain HTTP listener on port 80; the edge terminates
  TLS. `-backend` defaults to Cilium's Service name,
  `cilium-gateway-NAME.NAMESPACE.svc:80`.
- Nothing is published until the first full list of routes arrives, and
  an API server outage keeps the last list.
- The frpc admin API's reload is refused: it would replace the routes
  with the file's proxies.
- Outside a cluster, `-kubeconfig` (or `KUBECONFIG`) points it at one.
- TLSRoutes it has accepted become [TCP routes](#tcp-routes).
- `-metrics :9100` serves its own Prometheus metrics on `/metrics`:
  `fortresskube_published_names{kind}` and the TLSRoutes it refuses
  (`fortresskube_refused_tlsroutes{reason}`,
  `fortresskube_tlsroute_refusals_total{reason}`). Off by default.

Releases attach the binary and push the image
`ghcr.io/sebiee/fortressedge/fortresskube:<tag>`.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: fortresskube, namespace: fortress }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: fortresskube }
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes", "tlsroutes"] # tlsroutes for TCP routes
    verbs: ["list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: fortresskube }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: fortresskube }
subjects: [{ kind: ServiceAccount, name: fortresskube, namespace: fortress }]
---
apiVersion: v1
kind: Secret
metadata: { name: fortresskube, namespace: fortress }
stringData:
  frpc.toml: |
    serverAddr = "tunnel.example.com"
    serverPort = 443
    transport.protocol = "wss"
    transport.wireProtocol = "v2"
    transport.tls.certFile = "/etc/frp/node1.crt"
    transport.tls.keyFile = "/etc/frp/node1.key"
    transport.tls.trustedCaFile = "/etc/ssl/certs/ca-certificates.crt"
    transport.tls.serverName = "tunnel.example.com"
  node1.crt: "..."
  node1.key: "..."
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: fortresskube, namespace: fortress }
spec:
  replicas: 2 # one group: the edge spreads requests across them
  selector: { matchLabels: { app: fortresskube } }
  template:
    metadata: { labels: { app: fortresskube } }
    spec:
      serviceAccountName: fortresskube
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: ScheduleAnyway
          labelSelector: { matchLabels: { app: fortresskube } }
      containers:
        - name: fortresskube
          image: ghcr.io/sebiee/fortressedge/fortresskube:v0.7.0
          args: ["-c", "/etc/frp/frpc.toml", "-gateway", "infra/public"]
          volumeMounts: [{ name: config, mountPath: /etc/frp, readOnly: true }]
      volumes: [{ name: config, secret: { secretName: fortresskube } }]
```

`trustedCaFile` is what the edge's certificates chain to: the system
roots for Let's Encrypt, or an internal ACME server's root. Without it,
`fortresskube` checks the edge against the system roots;
`transport.tls.insecureSkipVerify = true` turns the check off.

**Coming back.** `fortresskube` is built to find a lost edge fast and
get back to it by itself. Where frpc's defaults suit a process on a
laptop, its own are, for keys the config file leaves out:

| Key | fortresskube | frpc | Why |
| --- | --- | --- | --- |
| `transport.deadServerTimeout` | `3` | `0` (off) | A tunnel whose edge went away without closing it (a reset, a crash, a network cut) is dropped after 3 seconds without acknowledgments: TCP_USER_TIMEOUT, and keepalive probes each second while idle. A busy tunnel is not affected, however long its queue: acknowledgments keep coming. Raise it for a link that goes silent for seconds and recovers |
| `transport.dialServerTimeout` | `2` | `10` | A dial into an edge that is still booting is given up soon, so the next finds it up |
| `loginFailExit` | `false` | `true` | A first login that fails is retried like any other, never an exit into a crash loop |
| `user` | the host name | none | Each replica's own, so frps tells their proxies apart (see below) |

After it loses the edge, it dials every quarter to three eighths of a
second for a minute, each dial starting a fresh connection attempt every
quarter second while the edge's machine is still down, as TCP would only
resend a lost one after a second, then backs off to every 20 seconds; a login the edge
refuses backs off at once. `transport.deadServerTimeout` is a key of
FortressEdge's frp fork, which stock frpc does not know; the rest are
frp's. For QUIC, set `transport.quic.maxIdleTimeout` and
`keepalivePeriod` instead.

**Work connections.** Each site request rides a work connection, a
stream in the tunnel that frpc opens when the edge asks for one. With
`transport.poolCount = N`, frpc opens N ahead, so a burst does not wait
for them; the edge keeps at most 5 (frps's `maxPoolCount`), and holds up
to 10 more that arrive while it asks. frpc answers every request for one,
so after a burst a few arrive when none is waiting: the edge closes those
unused, without the error message older edges sent (frpc logged it as
`StartWorkConn contains error ... discarding`), and counts them in
`fortressedge_work_connections_discarded_total`. `poolCount = 5` is the
most that helps. The edge's [metrics](operations.md#metrics) cover `fortresskube`'s
health: `fortressedge_tunnel_clients{node="<name>"}` counts its open
tunnels; `-metrics` adds what it publishes and refuses.

**Several replicas.** Every replica of the Deployment uses the same
node certificate, so the edge sees them as one dark node,
`node/<name>`, with several frpc: one group. They publish the same
names, and the edge spreads each name's requests across them in turn.
A replica that stops (a rollout, a drain, a deleted pod) closes its
tunnel, and from then on the others carry its share. One that goes
silent (a lost node, a network cut) is dropped after the policy's
`tunnel_dead_timeout`, 3 seconds by default; a request that was
already sent to it is answered `502`, but one that finds it gives
no work connection goes to the next replica. A certificate with
another name cannot publish a name the group holds, as before.

frps tells the replicas' proxies apart by frp's `user`, which
`fortresskube` sets to the host name, the pod's name, when the
config file leaves it out; leave it out. `tunnel_groups` in the edge's
status and `fortressedge_tunnel_group_members{group="<name>"}`
count the replicas logged in. Spread them across zones, as above, so
that losing a node or a zone leaves the sites up.

An app then declares its names once:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: blog, namespace: blog }
spec:
  parentRefs: [{ name: public, namespace: infra }]
  hostnames: ["blog.example.com"]
  rules: [{ backendRefs: [{ name: blog, port: 80 }] }]
```

## TCP routes

A TLSRoute (`gateway.networking.k8s.io/v1`) that the Gateway has
accepted publishes a [TCP route](operations.md#tcp-routes) per
hostname: the edge ends TLS, as it does for an HTTPRoute, and the
decrypted stream goes to the route's first `backendRefs` entry. A
developer can then reach a database in a dark cluster with direct TLS:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: postgresql
  namespace: dev
  annotations:
    fortressedge.io/alpn: postgresql   # comma list; leave out for none
spec:
  parentRefs: [{ name: public, namespace: infra }]
  hostnames: ["db.dev.example.com"]
  rules: [{ backendRefs: [{ name: postgresql-rw, port: 5432 }] }]
```

```sh
psql "host=db.dev.example.com port=443 sslmode=verify-full sslnegotiation=direct sslrootcert=system dbname=app"
# pgJDBC 42.7.4+: jdbc:postgresql://db.dev.example.com:443/app?sslmode=verify-full&sslNegotiation=direct
```

- `fortresskube` dials the Service itself,
  `<name>.<namespace>.svc:<port>`, not the Gateway: the Gateway's proxy
  routes a TLS stream by its server name, and the edge has already
  ended that TLS. The Gateway needs a TLS listener that accepts the
  route (`allowedRoutes` decides which namespaces may publish, as for
  HTTPRoutes), and a network policy must let `fortresskube` reach the
  Service.
- The backend must be a `Service` in the route's own namespace, with a
  `port`; a route that names another namespace is refused, as
  `fortresskube` does not check ReferenceGrants.
- Wildcard hostnames are refused. A hostname an HTTPRoute publishes
  stays an HTTP name, and the TLSRoute's is refused; of two TLSRoutes
  with one hostname, the older keeps it. A refused route or hostname is
  logged once, and counted in its metrics; the others go on.
- `fortresskube` needs `list` and `watch` on `tlsroutes` (above). A
  cluster without TLSRoutes is logged at start and left out. A discovery
  that fails otherwise is tried again, and a missing permission is
  warned about after 30 s; HTTPRoutes are published meanwhile, and the
  TLSRoutes join once their first full list is in.
- An edge older than 0.7.0 refuses the `tcp-tls` proxies:
  `fortresskube` logs that the edge needs an upgrade, and its HTTP
  names are unaffected.
