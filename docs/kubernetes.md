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
          image: ghcr.io/sebiee/fortressedge/fortresskube:v0.1.0
          args: ["-c", "/etc/frp/frpc.toml", "-gateway", "infra/public"]
          volumeMounts: [{ name: config, mountPath: /etc/frp, readOnly: true }]
      volumes: [{ name: config, secret: { secretName: fortresskube } }]
```

`trustedCaFile` is what the edge's certificates chain to: the system
roots for Let's Encrypt, or an internal ACME server's root. Without it,
`fortresskube` checks the edge against the system roots;
`transport.tls.insecureSkipVerify = true` turns the check off.

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
