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
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// generateSnapshot translates a manifest into a full xDS snapshot.
func generateSnapshot(manifest *Manifest) (*cachev3.Snapshot, error) {
	version := fmt.Sprintf("v%d", time.Now().Unix())

	clusters := makeClusters(manifest.Clusters)
	routes := makeRoutes(manifest.Routes)
	listeners, err := makeListeners(manifest.Listeners)
	if err != nil {
		return nil, fmt.Errorf("failed to create listeners: %w", err)
	}

	// Create the resource map with all required resource types
	resourceMap := map[resource.Type][]types.Resource{
		resource.ClusterType:  clusters,
		resource.RouteType:    routes,
		resource.ListenerType: listeners,
		resource.EndpointType: {}, // Empty but required for consistency
	}

	snapshot, err := cachev3.NewSnapshot(version, resourceMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}

	return snapshot, nil
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

// makeHTTPConnectionManager creates an HCM that references routes via RDS
func makeHTTPConnectionManager(mHcm *HTTPConnectionManager) (*hcm.HttpConnectionManager, error) {
	routerConfigProto, err := anypb.New(&router.Router{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router config: %w", err)
	}
	
	routerFilter := &hcm.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: routerConfigProto,
		},
	}

	// KEY CHANGE: Use Rds (Route Discovery Service) instead of embedding RouteConfig
	// This tells Envoy to fetch the route configuration dynamically via xDS
	hcmConfig := &hcm.HttpConnectionManager{
		StatPrefix: mHcm.StatPrefix,
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource: &core.ConfigSource{
					ResourceApiVersion: core.ApiVersion_V3,
					ConfigSourceSpecifier: &core.ConfigSource_Ads{
						Ads: &core.AggregatedConfigSource{},
					},
				},
				RouteConfigName: mHcm.RouteConfigName,
			},
		},
		HttpFilters: []*hcm.HttpFilter{
			routerFilter,
		},
	}
	return hcmConfig, nil
}

// makeListeners creates listeners that reference routes via RDS (not embedded)
// NOTE: This function no longer needs routeConfigs as a parameter
func makeListeners(manifestListeners []Listener) ([]types.Resource, error) {
	resources := make([]types.Resource, len(manifestListeners))
	for i, mListener := range manifestListeners {
		var filters []*listener.Filter
		for _, mFilter := range mListener.Filters {
			if mFilter.Type == "http_connection_manager" {
				// No longer pass routeConfigs - HCM uses RDS to reference by name
				hcmConfig, err := makeHTTPConnectionManager(mFilter.HTTPConnectionManager)
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
