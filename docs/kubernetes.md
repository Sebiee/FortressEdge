# Kubernetes

`fortresskube` is frpc for a cluster. It reads a normal frpc config and
also publishes every hostname of the HTTPRoutes that one Gateway has
accepted. Each hostname becomes its own http proxy, forwarded to the
Gateway's Service, so the edge gets a certificate for each exact name. A
new app needs only its HTTPRoute; deleting the route, or the Gateway
rejecting it, removes the name, and other names keep running.

- The Gateway's listeners decide which namespace may publish which
  name. A route's hostname is published only when a listener that
  accepted the route takes it: the listener's protocol carries the
  route's kind (`HTTP` or `HTTPS` for an HTTPRoute, `TLS` for a
  TLSRoute), its `allowedRoutes` admit the route's namespace and kind,
  and its `hostname` covers the name (a listener without one covers
  every name, `*.example.com` every name under `example.com`). A
  `parentRefs` entry's `sectionName` and `port` pick the listeners, as
  Gateway API defines them. The Gateway ignores a route's other
  hostnames, and so does `fortresskube`.
- Only routes with `Accepted=True` from that Gateway count, as the
  controller of its GatewayClass (`controllerName`) wrote it for the
  route's current `metadata.generation`, at a `parentRefs` entry the
  route still has. A status another controller or a tenant wrote, or
  one older than the route's spec, does not count.
- Wildcards and routes without `hostnames` are skipped.
- A name a proxy of the frpc config has (its `customDomains`) stays that
  proxy's: a route of either kind that names it is refused
  (`static_proxy`). frps would otherwise put the tenant's proxy and the
  operator's in one group, and split the name's requests between them.
- The Gateway needs a plain HTTP listener on port 80; the edge terminates
  TLS. `-backend` defaults to Cilium's Service,
  `cilium-gateway-NAME.NAMESPACE.svc:80`. `fortresskube` dials a Service
  at its cluster IP, read from the API, never by name: a pod's DNS
  search list tries a relative name such as `gw.infra.svc` as
  `gw.infra.svc.svc.cluster.local` first, which can name a pod in a
  namespace called `svc`. `-backend` takes `NAME.NAMESPACE.svc:PORT`
  for a Service, or an IP or a name ending with a dot
  (`gw.example.internal.:80`), and a port; another name is refused at
  start. While the Service has no cluster IP (missing, headless, or
  `ExternalName`) the HTTP names are not published, and each is logged
  and counted (`backend_service`).
- Nothing is published until the first full list of each resource it
  reads arrives, and an API server outage keeps the last lists. A list
  still missing after 30 s is warned about: usually a permission the
  ClusterRole below lacks.
- The frpc admin API's reload is refused: it would replace the routes
  with the file's proxies.
- Outside a cluster, `-kubeconfig` (or `KUBECONFIG`) points it at one.
- TLSRoutes it has accepted become [TCP routes](#tcp-routes).
- `-metrics :9100` serves its own Prometheus metrics on `/metrics`:
  `fortresskube_published_names{kind}`, the HTTPRoutes and TLSRoutes it
  refuses (`fortresskube_refused_httproutes{reason}`,
  `fortresskube_httproute_refusals_total{reason}`, and the same for
  `tlsroute`), and its tunnel (see **An edge service with several edges**
  below). Off by default.
- `-renew 5m` opens a new tunnel at about that age and retires the old
  one, for an edge service that spreads tunnels over several edges. Off
  by default. See **An edge service with several edges** below.
- `-health :8081` serves `/healthz`, for a liveness probe on a replica
  that cannot reach its backend. Off by default. See **A replica without
  its backend** below.

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
    resources: ["gateways", "gatewayclasses", "httproutes", "tlsroutes"] # tlsroutes for TCP routes
    verbs: ["list", "watch"]
  - apiGroups: [""]
    resources: ["namespaces", "services"] # allowedRoutes selectors; the Services dialed
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
          image: ghcr.io/sebiee/fortressedge/fortresskube:v0.8.0
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

**A replica without its backend.** A replica forwards every request it
gets to `-backend`. If it cannot reach the backend while the others can,
its tunnel stays up and the edge keeps sending it its share, which fails.
`-health :8081` lets the kubelet take such a replica out: `/healthz`
answers `200` while a TCP connection to `-backend` opens and `503` while
not, with the reason. A Service is checked at its cluster IP, as the
proxies dial it, and passes until the replica has listed the Services.
A liveness probe on it restarts the replica, its tunnel closes, and the
edge sends its share to the others.

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 8081 }
  periodSeconds: 1
  timeoutSeconds: 1
  failureThreshold: 3
```

- It helps when the failure is one replica's own: its node's networking,
  or a Gateway served per node. Cilium is the common case: a connection to
  a Gateway's address goes only to the node's own Envoy, never another
  node's, so a replica whose Envoy is gone fails the check. With the probe
  above, a short restart of the backend (Cilium's Envoy restarts in about
  2 s) does not trip it.
- Use it with two or more replicas on different nodes. It has no fail-open:
  when the backend is down for every replica, or there is only one, every
  replica restarts, the tunnels come and go, and the kubelet's growing
  restart delay can hold them back for a while after the backend returns.
  Without the probe the edge would answer `502` meanwhile; with it, `503`
  for `tunnel_grace`, then nothing.
- It reports the backend only, not the tunnel: frpc reconnects a tunnel by
  itself, and a restart would not help it.
- It checks the HTTP backend only. [TCP routes](#tcp-routes) go to each
  TLSRoute's own Service, which it does not check.
- A backend that accepts connections but does not answer passes: the check
  opens a TCP connection and sends nothing, so it adds nothing to the
  backend's request logs.
- The name is resolved on each check, so a new Service address is
  followed. When the lookup fails, the last address is used: the
  cluster's DNS being away is not the backend being away. A check takes at
  most 0.8 s, within the probe's timeout. Each change between up and down
  is logged once, with its reason.

**An edge service with several edges.** A replica holds one tunnel. When
`serverAddr` stands for several edges, three things keep that tunnel in
the right place:

- **The address.** A name with several addresses (one per location of
  the service) is dialled at one of them. Each replica has its own place
  among the sorted addresses: the number its name ends with, so the
  replicas 0, 1, 2 of a StatefulSet take the addresses in turn, else a
  hash of its name, which is the same at every dial. An address that
  does not answer is passed over: the next dial goes to the next
  address, and the first dial after one that worked starts at the
  replica's own again. The name is looked up at every dial, and it stays
  the TLS server name.
- **The renewal.** A balancer in front of several edges chooses the edge
  only when a tunnel is dialled. An edge that comes back, or a new one,
  gets no tunnel until some tunnel breaks. With `-renew 5m` the replica
  opens a new tunnel about every 5 minutes (within a fifth of it, so
  replicas do not renew together), and the balancer can give it to the
  edge with the fewest. The new tunnel logs in under its own frp `user`
  (`<host name>-<n>`), so the edge tells it from the old one. If it does
  not log in and publish within 15 seconds it is dropped and the old one
  stays.
- **The retirement.** The old tunnel takes its names back, so the edge
  sends it no new request, and closes when the requests and TCP sessions
  it carries have ended. A long TCP session or a stream is not cut. The
  edge keeps a work connection for the next request for up to a minute,
  so the old tunnel closes up to a minute after its last request, or at
  once when its connection ends by itself.

`-metrics` adds the tunnel's own: `fortresskube_tunnel_up`,
`fortresskube_tunnel_info{server}` (the address it dialled last),
`fortresskube_tunnel_age_seconds`, `fortresskube_tunnel_streams` (the
requests and TCP sessions it carries now), `fortresskube_tunnels_retiring`,
`fortresskube_tunnel_dials_total{result}` and
`fortresskube_tunnel_renewals_total{result}`.

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

The group is the certificate's, not the Deployment's: two
`fortresskube` Deployments with one certificate are one node to the
edge, and a name both publish joins one group, whatever Gateway each
watches. Give a Deployment that watches another Gateway its own
certificate.

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

- `fortresskube` dials the Service itself, at its cluster IP read from
  the API, not the Gateway: the Gateway's proxy routes a TLS stream by
  its server name, and the edge has already ended that TLS. The Gateway
  needs a TLS listener that accepts the route and covers its hostnames
  (as above), the route's status needs `ResolvedRefs=True` too, and a
  network policy must let `fortresskube` reach the Service.
- The backend must be a `Service` in the route's own namespace, with a
  `port`; a route that names another namespace is refused, as
  `fortresskube` does not check ReferenceGrants. A missing Service, a
  headless one, and an `ExternalName` one are refused
  (`backend_service`): a name to resolve could lead anywhere, the cloud's
  metadata service and the API server included.
- Wildcard hostnames are refused. A hostname an HTTPRoute publishes
  stays an HTTP name, and the TLSRoute's is refused; of two TLSRoutes
  with one hostname, the older keeps it, even while it cannot publish
  it (its Service gone for a while, say). A route deleted and created
  again is the younger, so give each team its own listener hostname:
  then no other namespace can wait for its names. A refused route or
  hostname is logged once, and counted in its metrics; the others go
  on.
- `fortresskube` needs `list` and `watch` on `tlsroutes` (above). A
  cluster without TLSRoutes is logged at start and left out. A discovery
  that fails otherwise is tried again, and a missing permission is
  warned about after 30 s; HTTPRoutes are published meanwhile, and the
  TLSRoutes join once their first full list is in.
- Limit what `fortresskube` itself can reach: it connects on the
  internet's behalf, so a NetworkPolicy keeps a mistaken route away
  from the cloud's metadata service, the nodes, and the control plane.
  It needs the edge, the API server, DNS for the edge's name, and the
  Gateway's and the TLSRoutes' pods:

  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata: { name: fortresskube, namespace: fortress }
  spec:
    podSelector: { matchLabels: { app: fortresskube } }
    policyTypes: [Egress]
    egress:
      - to: [{ namespaceSelector: {} }] # pods, not nodes: the Gateway, the TLSRoutes' backends, DNS
      - to: [{ ipBlock: { cidr: 203.0.113.10/32 } }] # the edge
        ports: [{ protocol: TCP, port: 443 }]
      - to: [{ ipBlock: { cidr: 192.0.2.20/32 } }] # the API server's endpoint: kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes
        ports: [{ protocol: TCP, port: 6443 }]
  ```

  Services are matched after their cluster IP is translated, so the
  pods behind them are what the policy sees; 169.254.0.0/16 and the
  nodes stay out. With Cilium, a CiliumNetworkPolicy with
  `toEntities: [kube-apiserver]` replaces the API server's `ipBlock`.
- An edge older than 0.7.0 refuses the `tcp-tls` proxies:
  `fortresskube` logs that the edge needs an upgrade, and its HTTP
  names are unaffected.
