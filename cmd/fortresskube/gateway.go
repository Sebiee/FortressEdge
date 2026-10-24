package main

import (
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

var (
	gateways       = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "gateways"}
	gatewayClasses = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "gatewayclasses"}
	namespaces     = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	services       = schema.GroupVersionResource{Version: "v1", Resource: "services"}
)

// gateway is fortresskube's Gateway, as far as it decides what is
// published: the controller whose status of a route counts, and the
// listeners, whose hostnames and allowedRoutes say which namespace may
// publish which name.
type gateway struct {
	ns, name   string
	controller string
	listeners  []listener
}

type listener struct {
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	Port          int32  `json:"port"`
	Protocol      string `json:"protocol"`
	AllowedRoutes struct {
		Namespaces struct {
			From     string                `json:"from"`
			Selector *metav1.LabelSelector `json:"selector"`
		} `json:"namespaces"`
		Kinds []routeGroupKind `json:"kinds"`
	} `json:"allowedRoutes"`
}

type routeGroupKind struct {
	Group *string `json:"group"`
	Kind  string  `json:"kind"`
}

// routeKind is what fortresskube's reading of a route takes from its
// kind.
type routeKind struct {
	name      string   // as a listener's allowedRoutes kinds name it
	protocols []string // of the listeners that take it
	// dialed: fortresskube dials the route's backend itself, in the place
	// of the Gateway's proxy, so it routes a name as the Gateway would, by
	// its most specific listener alone.
	dialed   bool
	refusals []string // why one, or a hostname of it, may be refused
}

var (
	httpKind = routeKind{"HTTPRoute", []string{"HTTP", "HTTPS"}, false, []string{refusedService, refusedStatic}}
	tlsKind  = routeKind{"TLSRoute", []string{"TLS"}, true, []string{
		refusedNoHostnames, refusedHostname, refusedBackend, refusedNamespace, refusedService, refusedUnresolved, refusedALPN,
		refusedHTTPRoute, refusedOlderTLSRoute, refusedStatic,
	}}
)

// gatewayOf is the Gateway ns/name in v, with its GatewayClass's
// controller; nil without either.
func gatewayOf(v view, ns, name string) *gateway {
	var gw struct {
		Spec struct {
			GatewayClassName string     `json:"gatewayClassName"`
			Listeners        []listener `json:"listeners"`
		} `json:"spec"`
	}
	var class struct {
		Spec struct {
			ControllerName string `json:"controllerName"`
		} `json:"spec"`
	}
	if !get(v.gateways, ns+"/"+name, &gw) || !get(v.classes, gw.Spec.GatewayClassName, &class) || class.Spec.ControllerName == "" {
		return nil
	}
	return &gateway{ns, name, class.Spec.ControllerName, gw.Spec.Listeners}
}

// route is an HTTPRoute or a TLSRoute, as fortresskube reads it.
type route struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		ParentRefs []parentRef `json:"parentRefs"`
		Hostnames  []string    `json:"hostnames"`
		Rules      []struct {
			BackendRefs []backendRef `json:"backendRefs"`
		} `json:"rules"`
	} `json:"spec"`
	Status struct {
		Parents []struct {
			ParentRef      parentRef   `json:"parentRef"`
			ControllerName string      `json:"controllerName"`
			Conditions     []condition `json:"conditions"`
		} `json:"parents"`
	} `json:"status"`
}

func (r *route) key() string { return r.Metadata.Namespace + "/" + r.Metadata.Name }

type condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	ObservedGeneration int64  `json:"observedGeneration"`
}

// parentRef is a route's reference to a parent, in its spec and in its
// status. A field left out has Gateway API's default.
type parentRef struct {
	Group       *string `json:"group"`
	Kind        *string `json:"kind"`
	Namespace   *string `json:"namespace"`
	Name        string  `json:"name"`
	SectionName string  `json:"sectionName"`
	Port        int32   `json:"port"`
}

// parentKey is a parentRef with its defaults filled in, so that a status
// entry's compares equal to the spec's it describes.
type parentKey struct {
	group, kind, namespace, name, sectionName string
	port                                      int32
}

func (p parentRef) key(routeNS string) parentKey {
	return parentKey{deref(p.Group, gatewayGroup), deref(p.Kind, "Gateway"), deref(p.Namespace, routeNS), p.Name, p.SectionName, p.Port}
}

// accepted is the listeners of g that accepted r, a route of kind k
// from a namespace labelled nsLabels: at each of r's parentRefs to g
// that g's controller says, for r's current generation, accepted r, the
// listeners the parentRef selects by sectionName and port that take k
// from r's namespace. A status entry another controller wrote, one older
// than r's spec, or one for a parentRef r no longer has does not count;
// nor does a listener that the status names but that does not take r.
// resolved is whether the controller also says, at one of those
// parentRefs, that it resolved r's references.
func (g *gateway) accepted(r *route, k *routeKind, nsLabels labels.Set) (ls []listener, resolved bool) {
	for _, p := range r.Spec.ParentRefs {
		ref := p.key(r.Metadata.Namespace)
		if ref.group != gatewayGroup || ref.kind != "Gateway" || ref.namespace != g.ns || ref.name != g.name || !g.says(r, ref, "Accepted") {
			continue
		}
		n := len(ls)
		for _, l := range g.listeners {
			if (ref.sectionName == "" || ref.sectionName == l.Name) && (ref.port == 0 || ref.port == l.Port) && l.takes(k, r.Metadata.Namespace, g.ns, nsLabels) {
				ls = append(ls, l)
			}
		}
		resolved = resolved || len(ls) > n && g.says(r, ref, "ResolvedRefs")
	}
	return ls, resolved
}

// takes reports whether l, of a Gateway in gwNS, takes routes of kind k
// from the namespace ns, labelled nsLabels: its protocol carries k, its
// allowedRoutes kinds, if it lists any, have k, and its allowedRoutes
// namespaces (Same when left out) have ns.
func (l *listener) takes(k *routeKind, ns, gwNS string, nsLabels labels.Set) bool {
	if !slices.Contains(k.protocols, l.Protocol) {
		return false
	}
	if kinds := l.AllowedRoutes.Kinds; len(kinds) > 0 && !slices.ContainsFunc(kinds, func(gk routeGroupKind) bool {
		return deref(gk.Group, gatewayGroup) == gatewayGroup && gk.Kind == k.name
	}) {
		return false
	}
	switch from := l.AllowedRoutes.Namespaces; from.From {
	case "", "Same":
		return ns == gwNS
	case "All":
		return true
	case "Selector":
		sel, err := metav1.LabelSelectorAsSelector(from.Selector)
		return err == nil && sel.Matches(nsLabels)
	}
	return false
}

// covers reports whether a listener of ls, accepted listeners of g for
// a route of kind k, takes the exact hostname h. For a kind fortresskube
// dials itself, the listener must also be one of g's most specific for
// h among those of k's protocols, whatever their port: the Gateway sends
// h to that listener alone, and the edge has one port for all of them.
func (g *gateway) covers(ls []listener, k *routeKind, h string) bool {
	best := -1
	for _, l := range g.listeners {
		if k.dialed && slices.Contains(k.protocols, l.Protocol) && l.matches(h) {
			best = max(best, l.rank())
		}
	}
	return slices.ContainsFunc(ls, func(l listener) bool { return l.matches(h) && l.rank() >= best })
}

// matches reports whether l takes the exact hostname h: l has no
// hostname, has h, or has a wildcard h is under, by one label or more.
func (l *listener) matches(h string) bool {
	lh := strings.ToLower(l.Hostname)
	suffix, wildcard := strings.CutPrefix(lh, "*")
	return lh == "" || lh == h || wildcard && strings.HasSuffix(h, suffix)
}

// rank orders the listeners that match one name, most specific last, as
// Gateway API does: none, then the shorter wildcard, then the longer,
// then the exact name.
func (l *listener) rank() int {
	switch {
	case l.Hostname == "":
		return 0
	case strings.HasPrefix(l.Hostname, "*"):
		return 2 * len(l.Hostname)
	}
	return 2*len(l.Hostname) + 1
}

// says reports whether g's controller set the condition typ True for
// r's current generation, in its status of r's parentRef k.
func (g *gateway) says(r *route, k parentKey, typ string) bool {
	for _, s := range r.Status.Parents {
		if s.ControllerName == g.controller && s.ParentRef.key(r.Metadata.Namespace) == k {
			return slices.ContainsFunc(s.Conditions, func(c condition) bool {
				return c.Type == typ && c.Status == "True" && c.ObservedGeneration == r.Metadata.Generation
			})
		}
	}
	return false
}

// routes is the routes a store holds.
func routes(s cache.Store) []route {
	var out []route
	for _, o := range s.List() {
		var r route
		if u, ok := o.(*unstructured.Unstructured); ok && runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// labelsOf is the labels of the namespace ns in v.
func labelsOf(v view, ns string) labels.Set {
	var n struct {
		Metadata metav1.ObjectMeta `json:"metadata"`
	}
	get(v.namespaces, ns, &n)
	return n.Metadata.Labels
}

// get decodes the object a store holds under key into out.
func get(s cache.Store, key string, out any) bool {
	o, ok, err := s.GetByKey(key)
	if err != nil || !ok {
		return false
	}
	u, ok := o.(*unstructured.Unstructured)
	return ok && runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, out) == nil
}
