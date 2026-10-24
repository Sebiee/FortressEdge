// Command fortresskube is frpc for a Kubernetes cluster. Besides the
// proxies in its frpc config, it publishes the hostnames of the HTTPRoutes
// that one Gateway's listeners have accepted, one http proxy per name, all
// forwarded to that Gateway, and those of the TLSRoutes they have
// accepted, one tcp-tls proxy per name, forwarded to the route's Service.
// The edge then gets a certificate for each exact name.
package main

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const gatewayGroup = "gateway.networking.k8s.io"

var httpRoutes = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "httproutes"}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fortresskube: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("c", "frpc.toml", "frpc config: server, TLS, and any static proxies")
	gateway := flag.String("gateway", "", "Gateway whose accepted HTTPRoutes are published, as namespace/name")
	backendFlag := flag.String("backend", "", "where the published proxies forward to: NAME.NAMESPACE.svc:PORT, a Service, dialed at its cluster IP, "+
		"or an IP or a name ending with a dot, and a port (default cilium-gateway-NAME.NAMESPACE.svc:80)")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig path; empty means in-cluster")
	metricsAddr := flag.String("metrics", "", "host:port to serve Prometheus metrics on, such as :9100; empty serves none")
	healthAddr := flag.String("health", "", "host:port to serve /healthz on, such as :8081, for a liveness probe: "+
		"200 while a TCP connection to the backend opens, 503 while not; empty serves none")
	renew := flag.Duration("renew", 0, "age at which the replica opens a new tunnel and retires the old one, such as 5m, "+
		"for an edge service that spreads tunnels over several edges; 0 never renews")
	flag.Parse()

	gwNS, gwName, ok := strings.Cut(*gateway, "/")
	if !ok || gwNS == "" || gwName == "" {
		return fmt.Errorf("-gateway must be namespace/name, got %q", *gateway)
	}
	be := backend{svcNS: gwNS, svc: "cilium-gateway-" + gwName, port: 80}
	if *backendFlag != "" {
		var err error
		if be, err = parseBackend(*backendFlag); err != nil {
			return fmt.Errorf("-backend: %w", err)
		}
	}

	res, err := config.LoadClientConfigResult(*cfgPath, true)
	if err != nil {
		return err
	}
	common := res.Common
	if !res.IsLegacyFormat {
		// What the file itself sets, before frp's defaults fill the rest.
		var file v1.ClientConfig
		if err := config.LoadConfigureFromFile(*cfgPath, &file, false); err == nil {
			tunnelDefaults(common, &file.ClientCommonConfig)
		}
	}
	pxs, vis := config.FilterClientConfigurers(common, res.Proxies, res.Visitors)
	if warn, err := validation.ValidateAllClientConfig(common, config.CompleteProxyConfigurers(pxs), config.CompleteVisitorConfigurers(vis), nil); err != nil {
		return err
	} else if warn != nil {
		fmt.Fprintf(os.Stderr, "fortresskube: warning: %v\n", warn)
	}
	log.InitLogger(common.Log.To, common.Log.Level, int(common.Log.MaxDays), common.Log.DisablePrintColor)

	var rc *rest.Config
	if *kubeconfig == "" {
		rc, err = rest.InClusterConfig()
	} else {
		rc, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	}
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ts := newTunnels(common, res.Proxies, res.Visitors)
	if err := ts.start(ctx); err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- <-ts.failed; stop() }()
	if *renew > 0 {
		go ts.renewEvery(ctx, *renew)
	}

	changed := make(chan struct{}, 1)
	poke := func(any) {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0)
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    poke,
		UpdateFunc: func(_, obj any) { poke(obj) },
		DeleteFunc: poke,
	}
	infs := map[schema.GroupVersionResource]cache.SharedIndexInformer{}
	for _, r := range []schema.GroupVersionResource{httpRoutes, gateways, gatewayClasses, namespaces, services} {
		inf := factory.ForResource(r).Informer()
		if _, err := inf.AddEventHandler(handler); err != nil {
			return err
		}
		go inf.Run(ctx.Done())
		infs[r] = inf
	}
	// Up before the first lists, so a liveness probe never finds it
	// missing while the routes are listed.
	if *healthAddr != "" {
		go serveHealth(*healthAddr, newBackendHealth(be, infs[services].GetStore(), infs[services].HasSynced))
	}
	// TLSRoutes, when the cluster serves them. They never hold up the
	// HTTPRoutes: until their first full list, none is published.
	var tlsInf atomic.Pointer[cache.SharedIndexInformer]
	go watchTLSRoutes(ctx, rc, factory, handler, func(i cache.SharedIndexInformer) {
		tlsInf.Store(&i)
		poke(nil)
	})
	// Publishing before the first full lists would drop every name the
	// edge already serves.
	if !waitSynced(ctx, infs) {
		return <-errc
	}
	log.Infof("watching httproutes accepted by gateway %s/%s, forwarding to %s", gwNS, gwName, be)

	stats := &routeStats{}
	if *metricsAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
				stats.ServeHTTP(w, r)
				ts.writeMetrics(w)
			})
			srv := &http.Server{Addr: *metricsAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				log.Warnf("metrics: %v", err)
			}
		}()
	}
	edge := &edgeSupport{status: ts}
	pub := &publisher{gwNS: gwNS, gwName: gwName, backend: be, static: staticNames(res.Proxies)}
	v := view{
		gateways: infs[gateways].GetStore(), classes: infs[gatewayClasses].GetStore(),
		namespaces: infs[namespaces].GetStore(), services: infs[services].GetStore(),
		httpRoutes: infs[httpRoutes].GetStore(),
	}
	tlsSynced := false
	for {
		select {
		case err := <-errc:
			return err
		case <-changed:
			if i := tlsInf.Load(); i != nil {
				if !tlsSynced {
					tlsSynced = true
					log.Infof("watching tlsroutes accepted by gateway %s/%s, forwarding to their Services", gwNS, gwName)
				}
				v.tlsRoutes = (*i).GetStore()
			}
			httpProxies, tlsProxies, refused := pub.publication(v)
			for _, r := range stats.update(len(httpProxies), len(tlsProxies), refused) {
				log.Warnf("%s not published: %s", strings.ToLower(r.kind), r)
			}
			// Static proxies come last so they win a proxy name clash.
			all := append(append(httpProxies, tlsProxies...), res.Proxies...)
			if err := ts.publish(all); err != nil {
				log.Warnf("publish routes: %v", err)
			}
			if len(tlsProxies) > 0 {
				edge.check(tlsProxies)
			}
		}
	}
}

// publisher publishes the routes its Gateway accepted.
type publisher struct {
	gwNS, gwName string
	backend      backend         // where the http proxies forward to
	static       map[string]bool // the names the frpc config's own proxies have
}

// staticNames is the names proxies publish.
func staticNames(proxies []v1.ProxyConfigurer) map[string]bool {
	names := map[string]bool{}
	for _, p := range proxies {
		var m msg.NewProxy
		p.MarshalToMsg(&m)
		for _, d := range m.CustomDomains {
			names[strings.ToLower(d)] = true
		}
	}
	return names
}

// backend is where the http proxies forward to: a Service, at its
// cluster IP, or an address. Never a relative name, which the pod's DNS
// search list can resolve to a pod of another namespace.
type backend struct {
	svcNS, svc string // the Service; "" for host
	host       string // an IP, or a fully qualified name ending with a dot
	port       int
}

// parseBackend reads -backend: NAME.NAMESPACE.svc:PORT for a Service, or
// an IP or a fully qualified name ending with a dot, and a port.
func parseBackend(s string) (backend, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return backend{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return backend{}, fmt.Errorf("port %q", portStr)
	}
	if _, err := netip.ParseAddr(host); err == nil || strings.HasSuffix(host, ".") {
		return backend{host: host, port: port}, nil
	}
	if l := strings.Split(host, "."); len(l) == 3 && l[2] == "svc" &&
		len(k8svalidation.IsDNS1035Label(l[0])) == 0 && len(k8svalidation.IsDNS1123Label(l[1])) == 0 {
		return backend{svcNS: l[1], svc: l[0], port: port}, nil
	}
	return backend{}, fmt.Errorf("%s is a relative name, which the pod's DNS search list can resolve to a pod of another namespace: "+
		"give NAME.NAMESPACE.svc for a Service, an IP, or a name ending with a dot", host)
}

// addr is what b dials now: its Service's cluster IP, which a missing,
// headless, or ExternalName Service has none of, or its host.
func (b backend) addr(services cache.Store) (string, bool) {
	if b.svc == "" {
		return b.host, true
	}
	return clusterIP(services, b.svcNS, b.svc)
}

func (b backend) String() string {
	if b.svc == "" {
		return net.JoinHostPort(b.host, strconv.Itoa(b.port))
	}
	return fmt.Sprintf("Service %s/%s port %d, at its cluster IP", b.svcNS, b.svc, b.port)
}

// view is what a publication reads: the informers' stores. tlsRoutes is
// nil while TLSRoutes are not watched.
type view struct {
	gateways, classes     cache.Store
	namespaces, services  cache.Store
	httpRoutes, tlsRoutes cache.Store
}

// publication is what p publishes from v: an http proxy per HTTPRoute
// name, then a tcp-tls proxy per TLSRoute name that no HTTPRoute has.
// Without its Gateway, or the Gateway's class, it publishes none.
func (p *publisher) publication(v view) (httpProxies, tlsProxies []v1.ProxyConfigurer, refused []refusal) {
	gw := gatewayOf(v, p.gwNS, p.gwName)
	if gw == nil {
		return nil, nil, nil
	}
	names, httpProxies, refused := p.published(v, gw)
	if v.tlsRoutes == nil {
		return httpProxies, nil, refused
	}
	tlsProxies, tlsRefused := p.publishedTLS(v, gw, names)
	return httpProxies, tlsProxies, append(refused, tlsRefused...)
}

// waitSynced waits for the informers' first full lists, and warns once
// of each still missing after 30 seconds.
func waitSynced(ctx context.Context, infs map[schema.GroupVersionResource]cache.SharedIndexInformer) bool {
	var synced []cache.InformerSynced
	for _, i := range infs {
		synced = append(synced, i.HasSynced)
	}
	for warned := false; ; warned = true {
		wait, cancel := context.WithTimeout(ctx, 30*time.Second)
		ok := cache.WaitForCacheSync(wait.Done(), synced...)
		cancel()
		if ok {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		for r, i := range infs {
			if !warned && !i.HasSynced() {
				log.Warnf("%s: no full list after 30s; fortresskube needs list and watch on %s", r.Resource, r.GroupResource())
			}
		}
	}
}

// watchTLSRoutes starts watching TLSRoutes once discovery says the
// cluster serves them, and calls synced with the informer once its first
// full list is in. A cluster without them is logged, and left out; a
// discovery that fails otherwise (the API server away, no permission)
// is tried again.
func watchTLSRoutes(ctx context.Context, rc *rest.Config, factory dynamicinformer.DynamicSharedInformerFactory,
	handler cache.ResourceEventHandler, synced func(cache.SharedIndexInformer),
) {
	for delay := time.Second; ; delay = min(2*delay, time.Minute) {
		served, err := tlsRoutesServed(rc)
		if err == nil && !served || apierrors.IsNotFound(err) {
			log.Infof("tlsroutes (%s) not served by this cluster: TCP routes off", tlsRoutes.GroupVersion())
			return
		}
		if err == nil {
			break
		}
		log.Warnf("tlsroutes: discovery of %s: %v; trying again in %s", tlsRoutes.GroupVersion(), err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
	inf := factory.ForResource(tlsRoutes).Informer()
	if _, err := inf.AddEventHandler(handler); err != nil {
		log.Warnf("tlsroutes: %v", err)
		return
	}
	go inf.Run(ctx.Done())
	if waitSynced(ctx, map[schema.GroupVersionResource]cache.SharedIndexInformer{tlsRoutes: inf}) {
		synced(inf)
	}
}

// tlsRoutesServed reports whether the API server serves TLSRoutes in
// the version fortresskube reads.
func tlsRoutesServed(rc *rest.Config) (bool, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(rc)
	if err != nil {
		return false, err
	}
	list, err := dc.ServerResourcesForGroupVersion(tlsRoutes.GroupVersion().String())
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(list.APIResources, func(r metav1.APIResource) bool { return r.Name == tlsRoutes.Resource }), nil
}

// edgeSupport tells, once, that the edge refuses tcp-tls proxies: it is
// older than fortresskube. HTTP names are not affected.
type edgeSupport struct {
	status interface {
		GetProxyStatus(string) (*proxy.WorkingStatus, bool)
	}
	mu       sync.Mutex
	told     bool
	checking bool
}

// check looks at the proxies' status a little after they were sent.
func (e *edgeSupport) check(proxies []v1.ProxyConfigurer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.told || e.checking {
		return
	}
	e.checking = true
	names := make([]string, len(proxies))
	for i, p := range proxies {
		names[i] = p.GetBaseConfig().Name
	}
	var look func()
	look = func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		pending := false
		for _, n := range names {
			st, ok := e.status.GetProxyStatus(n)
			switch {
			case !ok:
			case st.Phase == proxy.ProxyPhaseStartErr && oldEdge(st.Err):
				log.Warnf("the edge does not take TCP routes (%s): it is older than fortresskube; "+
					"TLSRoutes stay unpublished until it is upgraded, HTTPRoutes are unaffected", st.Err)
				e.told, e.checking = true, false
				return
			case st.Phase == proxy.ProxyPhaseNew || st.Phase == proxy.ProxyPhaseWaitStart:
				pending = true // not logged in yet, or no answer yet
			}
		}
		if pending {
			time.AfterFunc(10*time.Second, look)
			return
		}
		e.checking = false
	}
	time.AfterFunc(10*time.Second, look)
}

// oldEdge is frps's refusal of a proxy type it does not know, or one it
// does not route.
func oldEdge(err string) bool {
	return strings.Contains(err, "unknown proxy type") || strings.Contains(err, "type [tcp-tls] not supported")
}

// Where frpc's defaults suit a process on a laptop, fortresskube's suit a
// tunnel that must come back by itself, fast, when the edge restarts:
const (
	// deadServerTimeout finds an edge that went away without closing the
	// tunnel (a reset, a crash, a network cut) in seconds, not minutes.
	deadServerTimeout = 3
	// dialServerTimeout gives up on a dial into an edge whose machine is
	// still starting, whose SYNs go nowhere, so the next dial can find it
	// up. Two seconds are three round trips of TCP, TLS, and the WebSocket
	// upgrade over a slow intercontinental link.
	dialServerTimeout = 2
)

// tunnelDefaults sets fortresskube's defaults in common for the keys the
// config file (file) leaves out: the dead-server and dial timeouts,
// loginFailExit false, so a first login that fails is retried like any,
// instead of exiting into a crash loop, and user the host name. The edge
// spreads a node's requests across all its replicas, which register the
// same names; frps tells their proxies apart by user, so each replica
// needs its own, and a pod's host name is its pod name.
func tunnelDefaults(common, file *v1.ClientCommonConfig) {
	if file.User == "" {
		if h, err := os.Hostname(); err == nil {
			common.User = h
		}
	}
	if file.Transport.DeadServerTimeout == 0 {
		common.Transport.DeadServerTimeout = deadServerTimeout
	}
	if file.Transport.DialServerTimeout == 0 {
		common.Transport.DialServerTimeout = dialServerTimeout
	}
	if file.LoginFailExit == nil {
		f := false
		common.LoginFailExit = &f
	}
}

// published is the hostnames (names) of the HTTPRoutes gw accepted that
// a listener which accepted them takes: the listeners' hostnames and
// allowedRoutes decide which namespace may publish which name. Wildcards
// and routes without hostnames are skipped: the edge only gets
// certificates for exact names, and a name a static proxy has is
// refused: frps would put both proxies in one group. Each name is an
// http proxy to p's backend; while the backend has no address, each is
// refused instead.
func (p *publisher) published(v view, gw *gateway) (names map[string]bool, proxies []v1.ProxyConfigurer, refused []refusal) {
	names = map[string]bool{}
	ip, ok := p.backend.addr(v.services)
	for _, r := range routes(v.httpRoutes) {
		ls := gw.accepted(&r, &httpKind, labelsOf(v, r.Metadata.Namespace))
		for _, h := range r.Spec.Hostnames {
			h = strings.ToLower(h)
			if len(k8svalidation.IsDNS1123Subdomain(h)) > 0 || !covers(ls, h) {
				continue
			}
			if p.static[h] {
				refused = append(refused, refusal{httpKind.name, r.key(), h, refusedStatic})
				continue
			}
			names[h] = true
			if !ok {
				refused = append(refused, refusal{httpKind.name, r.key(), h, refusedService})
			}
		}
	}
	if !ok {
		return names, nil, refused
	}
	for _, h := range slices.Sorted(maps.Keys(names)) {
		proxies = append(proxies, &v1.HTTPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{Name: h, Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: ip, LocalPort: p.backend.port}},
			DomainConfig:    v1.DomainConfig{CustomDomains: []string{h}},
		})
	}
	return names, proxies, refused
}

func deref(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}
