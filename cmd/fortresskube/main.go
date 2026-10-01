// Command fortresskube is frpc for a Kubernetes cluster. Besides the
// proxies in its frpc config, it publishes every hostname of the HTTPRoutes
// that one Gateway has accepted, one http proxy per name, all forwarded to
// that Gateway. The edge then gets a certificate for each exact name.
package main

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/util/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
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
	backend := flag.String("backend", "", "host:port the published proxies forward to (default cilium-gateway-NAME.NAMESPACE.svc:80)")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig path; empty means in-cluster")
	flag.Parse()

	gwNS, gwName, ok := strings.Cut(*gateway, "/")
	if !ok || gwNS == "" || gwName == "" {
		return fmt.Errorf("-gateway must be namespace/name, got %q", *gateway)
	}
	if *backend == "" {
		*backend = fmt.Sprintf("cilium-gateway-%s.%s.svc:80", gwName, gwNS)
	}
	host, portStr, err := net.SplitHostPort(*backend)
	if err != nil {
		return fmt.Errorf("-backend: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("-backend port: %w", err)
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

	src := source.NewConfigSource()
	if err := src.ReplaceAll(res.Proxies, res.Visitors); err != nil {
		return err
	}
	// No ConfigFilePath: an admin-API reload would replace the published
	// routes with the file's proxies, so it is refused instead.
	svc, err := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(src)})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- svc.Run(ctx); stop() }()

	changed := make(chan struct{}, 1)
	poke := func(any) {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	inf := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0).ForResource(httpRoutes).Informer()
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    poke,
		UpdateFunc: func(_, obj any) { poke(obj) },
		DeleteFunc: poke,
	}); err != nil {
		return err
	}
	go inf.Run(ctx.Done())
	// Publishing before the first full list would drop every name the
	// edge already serves.
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return <-errc
	}
	log.Infof("watching httproutes accepted by gateway %s/%s, forwarding to %s", gwNS, gwName, *backend)

	for {
		select {
		case err := <-errc:
			return err
		case <-changed:
			// Static proxies come last so they win a name clash.
			all := append(published(inf.GetStore().List(), gwNS, gwName, host, port), res.Proxies...)
			if err := svc.UpdateConfigSource(common, all, res.Visitors); err != nil {
				log.Warnf("publish httproutes: %v", err)
			}
		}
	}
}

type httpRoute struct {
	Spec struct {
		Hostnames []string `json:"hostnames"`
	} `json:"spec"`
	Status struct {
		Parents []struct {
			ParentRef struct {
				Group     *string `json:"group"`
				Kind      *string `json:"kind"`
				Namespace *string `json:"namespace"`
				Name      string  `json:"name"`
			} `json:"parentRef"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"parents"`
	} `json:"status"`
}

// published is one http proxy per hostname of each route the Gateway
// gwNS/gwName reports as Accepted. The Gateway's allowedRoutes decides which
// namespaces may publish. Wildcards and routes without hostnames are
// skipped: the edge only gets certificates for exact names.
// ponytail: a hostname outside the Gateway listener's hostname is still
// published and gets a certificate, then a 404 from the Gateway; intersect
// with the listeners if that ever matters.
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

func published(objs []any, gwNS, gwName, host string, port int) []v1.ProxyConfigurer {
	names := map[string]bool{}
	for _, o := range objs {
		u, ok := o.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		var r httpRoute
		if runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &r) != nil || !r.acceptedBy(u.GetNamespace(), gwNS, gwName) {
			continue
		}
		for _, h := range r.Spec.Hostnames {
			h = strings.ToLower(h)
			if len(k8svalidation.IsDNS1123Subdomain(h)) == 0 {
				names[h] = true
			}
		}
	}
	out := make([]v1.ProxyConfigurer, 0, len(names))
	for _, h := range slices.Sorted(maps.Keys(names)) {
		out = append(out, &v1.HTTPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{Name: h, Type: "http", ProxyBackend: v1.ProxyBackend{LocalIP: host, LocalPort: port}},
			DomainConfig:    v1.DomainConfig{CustomDomains: []string{h}},
		})
	}
	return out
}

func (r *httpRoute) acceptedBy(routeNS, gwNS, gwName string) bool {
	for _, p := range r.Status.Parents {
		ref := p.ParentRef
		if deref(ref.Group, gatewayGroup) != gatewayGroup || deref(ref.Kind, "Gateway") != "Gateway" ||
			deref(ref.Namespace, routeNS) != gwNS || ref.Name != gwName {
			continue
		}
		for _, c := range p.Conditions {
			if c.Type == "Accepted" && c.Status == "True" {
				return true
			}
		}
	}
	return false
}

func deref(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}
