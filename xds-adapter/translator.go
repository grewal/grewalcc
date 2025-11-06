package main

import (
	"fmt"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// (generateSnapshot, makeClusters, makeRoutes are unchanged)

func generateSnapshot(manifest *Manifest) (cachev3.Snapshot, error) {
	const version = "1"
	clusters := makeClusters(manifest.Clusters)
	routes := makeRoutes(manifest.Routes)
	listeners, err := makeListeners(manifest.Listeners, routes)
	if err != nil {
		return cachev3.Snapshot{}, fmt.Errorf("failed to create listeners: %w", err)
	}
	snapshot, err := cachev3.NewSnapshot(
		version,
		map[resource.Type][]types.Resource{
			resource.ClusterType:  clusters,
			resource.RouteType:    routes,
			resource.ListenerType: listeners,
		},
	)
	if err != nil {
		return cachev3.Snapshot{}, fmt.Errorf("failed to create snapshot: %w", err)
	}
	return *snapshot, nil
}
func makeClusters(manifestClusters []Cluster) []types.Resource {
	resources := make([]types.Resource, len(manifestClusters))
	for i, mCluster := range manifestClusters {
		dnsFamily := cluster.Cluster_AUTO
		if mCluster.DnsLookupFamily == "V4_ONLY" {
			dnsFamily = cluster.Cluster_V4_ONLY
		}
		c := &cluster.Cluster{
			Name:                 mCluster.Name,
			ConnectTimeout:       durationpb.New(time.Duration(mCluster.ConnectTimeoutSeconds) * time.Second),
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			DnsLookupFamily:      dnsFamily,
			LbPolicy:             cluster.Cluster_ROUND_ROBIN,
			LoadAssignment: &endpoint.ClusterLoadAssignment{
				ClusterName: mCluster.Name,
				Endpoints: []*endpoint.LocalityLbEndpoints{
					{
						LbEndpoints: []*endpoint.LbEndpoint{
							{
								HostIdentifier: &endpoint.LbEndpoint_Endpoint{
									Endpoint: &endpoint.Endpoint{
										Address: &core.Address{
											Address: &core.Address_SocketAddress{
												SocketAddress: &core.SocketAddress{
													Address:       mCluster.DNSName,
													PortSpecifier: &core.SocketAddress_PortValue{PortValue: mCluster.Port},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		if mCluster.IsHTTP2 {
			c.Http2ProtocolOptions = &core.Http2ProtocolOptions{}
		}
		resources[i] = c
	}
	return resources
}
func makeRoutes(manifestRoutes []RouteConfig) []types.Resource {
	resources := make([]types.Resource, len(manifestRoutes))
	for i, mRouteConfig := range manifestRoutes {
		var virtualHosts []*route.VirtualHost
		for _, mVh := range mRouteConfig.VirtualHosts {
			var routes []*route.Route
			for _, mRoute := range mVh.Routes {
				r := &route.Route{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_Prefix{Prefix: mRoute.Match.Prefix},
					},
				}

				if mRoute.Action.Redirect != nil {
					r.Action = &route.Route_Redirect{
						Redirect: &route.RedirectAction{
							SchemeRewriteSpecifier: &route.RedirectAction_HttpsRedirect{
								HttpsRedirect: mRoute.Action.Redirect.HttpsRedirect,
							},
						},
					}
				} else {
					r.Action = &route.Route_Route{
						Route: &route.RouteAction{
							ClusterSpecifier: &route.RouteAction_Cluster{Cluster: mRoute.Action.Cluster},
						},
					}
				}
				routes = append(routes, r)
			}
			vh := &route.VirtualHost{
				Name:    mVh.Name,
				Domains: mVh.Domains,
				Routes:  routes,
			}
			virtualHosts = append(virtualHosts, vh)
		}
		rc := &route.RouteConfiguration{
			Name:         mRouteConfig.Name,
			VirtualHosts: virtualHosts,
		}
		resources[i] = rc
	}
	return resources
}

// UPDATED: Now correctly builds the router filter with its typed config.
func makeHTTPConnectionManager(mHcm *HTTPConnectionManager, routeConfigs []types.Resource) (*hcm.HttpConnectionManager, error) {
	// Create the router filter config. For default behavior, it's an empty object.
	routerConfigProto, err := anypb.New(&router.Router{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router config: %w", err)
	}

	// Create the full HttpFilter object, including the name and the typed config.
	routerFilter := &hcm.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: routerConfigProto,
		},
	}

	var matchedRouteConfig *route.RouteConfiguration
	for _, rcResource := range routeConfigs {
		rc, ok := rcResource.(*route.RouteConfiguration)
		if !ok {
			continue
		}
		if rc.Name == mHcm.RouteConfigName {
			matchedRouteConfig = rc
			break
		}
	}
	if matchedRouteConfig == nil {
		return nil, fmt.Errorf("route_config_name '%s' not found", mHcm.RouteConfigName)
	}

	hcmConfig := &hcm.HttpConnectionManager{
		StatPrefix: mHcm.StatPrefix,
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: matchedRouteConfig,
		},
		HttpFilters: []*hcm.HttpFilter{
			// Add other filters here in the future
			routerFilter, // Add the correctly constructed router filter.
		},
	}
	return hcmConfig, nil
}

// (makeListeners is unchanged, but will now receive a correctly built HCM)
func makeListeners(manifestListeners []Listener, routeConfigs []types.Resource) ([]types.Resource, error) {
	resources := make([]types.Resource, len(manifestListeners))
	for i, mListener := range manifestListeners {
		var filters []*listener.Filter
		for _, mFilter := range mListener.Filters {
			if mFilter.Type == "http_connection_manager" {
				hcmConfig, err := makeHTTPConnectionManager(mFilter.HTTPConnectionManager, routeConfigs)
				if err != nil {
					return nil, fmt.Errorf("listener %s: %w", mListener.Name, err)
				}
				pbst, err := anypb.New(hcmConfig)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal hcm config for listener %s: %w", mListener.Name, err)
				}
				filter := &listener.Filter{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: pbst,
					},
				}
				filters = append(filters, filter)
			}
		}

		l := &listener.Listener{
			Name: mListener.Name,
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Address:       mListener.Address,
						PortSpecifier: &core.SocketAddress_PortValue{PortValue: mListener.Port},
					},
				},
			},
			FilterChains: []*listener.FilterChain{
				{
					Filters: filters,
				},
			},
		}
		resources[i] = l
	}
	return resources, nil
}
