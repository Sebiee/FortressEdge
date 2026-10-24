package main

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

var (
	gateways       = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "gateways"}
	gatewayClasses = schema.GroupVersionResource{Group: gatewayGroup, Version: "v1", Resource: "gatewayclasses"}
)

// gateway is fortresskube's Gateway, as far as it decides what is
// published: the controller whose status of a route counts.
type gateway struct {
	ns, name   string
	controller string
}

// gatewayOf is the Gateway ns/name in v, with its GatewayClass's
// controller; nil without either.
func gatewayOf(v view, ns, name string) *gateway {
	var gw struct {
		Spec struct {
			GatewayClassName string `json:"gatewayClassName"`
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
	return &gateway{ns, name, class.Spec.ControllerName}
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

// accepts reports whether g accepted r: one of r's parentRefs is g, and
// g's controller says, for r's current generation, that it accepted r
// there. A status entry another controller wrote, one older than r's
// spec, or one for a parentRef r no longer has does not count.
func (g *gateway) accepts(r *route) bool {
	for _, p := range r.Spec.ParentRefs {
		k := p.key(r.Metadata.Namespace)
		if k.group == gatewayGroup && k.kind == "Gateway" && k.namespace == g.ns && k.name == g.name && g.says(r, k, "Accepted") {
			return true
		}
	}
	return false
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

// get decodes the object a store holds under key into out.
func get(s cache.Store, key string, out any) bool {
	o, ok, err := s.GetByKey(key)
	if err != nil || !ok {
		return false
	}
	u, ok := o.(*unstructured.Unstructured)
	return ok && runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, out) == nil
}
