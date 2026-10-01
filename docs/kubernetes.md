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
    resources: ["httproutes"]
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
  replicas: 1 # a second client registering the same names is refused by frps
  selector: { matchLabels: { app: fortresskube } }
  template:
    metadata: { labels: { app: fortresskube } }
    spec:
      serviceAccountName: fortresskube
      containers:
        - name: fortresskube
          image: ghcr.io/sebiee/fortressedge/fortresskube:v0.5.1
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
health: `fortressedge_tunnel_clients{node="<name>"}` is 1 while its
tunnel is up; it has no admin or metrics port of its own.

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
