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
  hostnames, and so does `fortresskube`. For a TLSRoute, whose Service
  `fortresskube` dials in the Gateway's place, only the most specific
  TLS listener that covers a name counts, whatever its port (`db.example.com`
  before `*.team-a.example.com` before `*.example.com`): the Gateway
  routes the name to that listener alone.
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
  the API server forbids at start stops `fortresskube` with an error that
  names the resource, so a Deployment rolled out without the ClusterRole
  below keeps its old pods; a list missing after 30 s for another reason
  is warned about, and waited for.
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
- `-renew 5m` is how often the replica looks for a better edge, for an
  edge service with several edges: it moves its tunnel only when that
  spreads the tunnels more evenly over the edges. Off by default. See
  **An edge service with several edges** below.
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
          image: ghcr.io/sebiee/fortressedge/fortresskube:v0.10.0
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
proxies dial it. The check passes until the replica has listed the
Services, and while the Service has no cluster IP (missing, headless, or
ExternalName): the replica then refuses its routes, the same as every
other replica, and a restart would not bring it back; it logs that once.
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
- A Service is read from the replica's watch of Services on each check,
  so a new cluster IP is followed. An IP or a name ending with a dot is
  resolved on each check; when that lookup fails, the last address is
  used: the cluster's DNS being away is not the backend being away. A
  check takes at most 0.8 s, within the probe's timeout. Each change
  between up, down and not checked is logged once, with its reason.

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
- **The look.** A balancer in front of several edges chooses the edge
  only when a tunnel is dialled. An edge that comes back, or a new one,
  gets no tunnel until some tunnel breaks. With `-renew 5m` the replica
  looks for a better edge about every 5 minutes (within a fifth of it,
  so replicas do not look together):
  1. It logs in a second time, under its own frp `user`
     (`<host name>-<n>`), with nothing to publish. The balancer gives
     this login to one edge. That edge answers with a count: the tunnels
     of the dark node that serve there, and its logins that have not
     published yet, this one among them.
  2. The replica asks the edge of its tunnel, on that tunnel: may I
     leave for an edge with that count? The edge says yes only when more
     of the node's tunnels serve at it than the count. It answers one
     question at a time, and after a yes it no longer counts the tunnel.
     So a tunnel moves only when the move spreads the tunnels more
     evenly, an edge never lets its last tunnel go, and a second login
     that reached the tunnel's own edge is never a reason to move.
  3. After a yes, the second login publishes every name and becomes the
     tunnel, and the old tunnel retires (below). If it does not publish
     every name the old one publishes within 15 seconds of the look's
     start, the replica tells its edge that the tunnel stays, and closes
     the second login.
  4. After a no, the replica closes the second login. Nothing else has
     changed: no name moved, and no request was touched.

  With 4 replicas at one of 2 edges, a look moves one tunnel (3 and 1),
  a later look one more (2 and 2), and then none. One replica's tunnel
  never moves. Looks at the same moment are safe: at most as many
  tunnels leave as the rule allows, and sometimes none, until the next
  look.
- **The retirement.** A tunnel the replica left takes its names back, so
  the edge sends it no new request, and closes a few seconds after the
  requests and TCP sessions it carries have ended, or at once when its
  connection ends by itself. A replica keeps at most 4 such tunnels: a
  move that would keep a fifth closes the oldest, and cuts what it still
  carries. `fortresskube_tunnels_cut_total` and
  `fortresskube_tunnel_streams_cut_total` count the cuts, and each is
  logged with what it cut.

A tunnel now lives long: until the pod or its edge restarts, the
connection breaks, or the tunnels are spread unevenly. In a steady
service no look moves a tunnel, so a WebSocket, a stream or a TCP
session is not cut by `-renew`, however long it lasts. The edge checks a
node's client certificate at each login, as before, and not again while
the tunnel lasts: a certificate that has ended, or one whose CA the
edges no longer trust, keeps the tunnels it has. Each look logs in with
the certificate the replica holds now, so a certificate that no longer
logs in shows as looks that fail.

**Edges and replicas of different versions.** Update the edges first,
then `fortresskube`; either order is safe.

| Replica | Edges | What a look does |
| --- | --- | --- |
| this version | this version | as above |
| this version | 0.10.0 or older, the edge the look reaches or the edge of the tunnel | the edge gives no count and knows no question, and the replica asks it none: the second login publishes and becomes the tunnel, and the old one retires, as every renewal did before. The gaps of that renewal stay until the last edge is updated |
| 0.10.0 or older | this version | the replica opens a new tunnel at every `-renew` and retires the old one, as before. The edge does not count its retired tunnels, so replicas of this version beside it are counted right |

A tunnel that has no connection when the look comes has no edge to ask:
the second login becomes the tunnel, as before.

`-metrics` adds the tunnel's own: `fortresskube_tunnel_up`,
`fortresskube_tunnel_info{server}` (the address it dialled last),
`fortresskube_tunnel_age_seconds`, `fortresskube_tunnel_streams` (the
requests and TCP sessions it carries now), `fortresskube_tunnels_retiring`,
`fortresskube_tunnel_dials_total{result}`,
`fortresskube_tunnel_looks_total{result}`,
`fortresskube_tunnels_cut_total` and
`fortresskube_tunnel_streams_cut_total`. A look's `result` is `moved`,
`stayed` (its edge said no: the move would not spread the tunnels more
evenly), `old_edge` (moved without a question, see the table above), or
`failed` (the second login did not come up, the edge did not answer, or
the new tunnel did not publish; the tunnel stayed as it was). Each look
is one log line: a move and a stay at info, a failure at warning.
`fortresskube_tunnel_looks_total` replaces
`fortresskube_tunnel_renewals_total`. The edge counts its answers in
`fortressedge_tunnel_leaves_total{result}` (`granted`, `refused`).

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

Each edge limits one certificate to 64 logins, 4096 proxies and 256
names. A replica holds one login, its tunnel. With `-renew` it holds a
second one for the seconds of a look, at the edge the balancer offers,
and a tunnel it has left stays logged in while its streams last, up to 4
of them. In a steady service that is one login a replica and a look now
and then, so where edges are away and one edge takes every replica,
about 60 replicas of one certificate fit. With an edge of 0.10.0 or
older every look moves the tunnel, and a replica can hold 5 logins and
one more during a look, as before: 10 replicas fit. The tunnel publishes
every name and a look publishes none, so the proxies are the tunnels
times the names. Past a limit, the edge refuses the login or the proxy:
a look that cannot log in fails, and a move that cannot publish every
name keeps the tunnel it has.

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
  (as above), the route's status needs `ResolvedRefs=True` too (else
  it is refused, `unresolved_backend`), and a network policy must let
  `fortresskube` reach the Service.
- The backend must be a `Service` in the route's own namespace, with a
  `port`; a route that names another namespace is refused, as
  `fortresskube` does not check ReferenceGrants. A missing Service, a
  headless one, and an `ExternalName` one are refused
  (`backend_service`): a name to resolve could lead anywhere, the cloud's
  metadata service and the API server included.
- Wildcard hostnames are refused. A hostname an HTTPRoute publishes
  stays an HTTP name, and the TLSRoute's is refused: an HTTP listener
  whose hostname covers a TLS listener's (none, or `*.example.com`
  over `*.team-a.example.com`) lets every namespace it admits take that
  TLS listener's names, so keep their hostnames apart. Of two TLSRoutes
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
  `fortresskube` trusts a Service's endpoints as the Gateway does:
  whoever may write Endpoints or EndpointSlices in a namespace (not
  Kubernetes' `edit` or `admin` role since 1.22) can point its Services
  at any address this policy allows.
- An edge older than 0.7.0 refuses the `tcp-tls` proxies:
  `fortresskube` logs that the edge needs an upgrade, and its HTTP
  names are unaffected.
