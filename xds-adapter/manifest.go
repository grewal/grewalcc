package main

import "gopkg.in/yaml.v3"

type Manifest struct {
	Listeners []Listener    `yaml:"listeners"`
	Clusters  []Cluster     `yaml:"clusters"`
	Routes    []RouteConfig `yaml:"routes"`
}

// Listener defines a network listener for Envoy.
type Listener struct {
	Name    string   `yaml:"name"`
	Address string   `yaml:"address"`
	Port    uint32   `yaml:"port"`
	TLS     *TLS     `yaml:"tls,omitempty"`
	Filters []Filter `yaml:"filters"`
}

// TLS defines the TLS configuration for a listener.
type TLS struct {
	CertChainPath  string   `yaml:"cert_chain_path"`
	PrivateKeyPath string   `yaml:"private_key_path"`
	AlpnProtocols  []string `yaml:"alpn_protocols"`
}

// Filter represents a network filter in an Envoy listener's filter chain.
type Filter struct {
	Type                  string                 `yaml:"type"` // e.g., "network.rbac", "http_connection_manager"
	RBAC                  *RBAC                  `yaml:"rbac,omitempty"`
	NetworkExtAuthz       *NetworkExtAuthz       `yaml:"network_ext_authz,omitempty"`
	HTTPConnectionManager *HTTPConnectionManager `yaml:"http_connection_manager,omitempty"`
}

// RBAC defines the configuration for the L4 network RBAC filter for IP-based blocking.
type RBAC struct {
	StatPrefix string       `yaml:"stat_prefix"`
	Policies   []RBACPolicy `yaml:"policies"`
}

type RBACPolicy struct {
	Name      string   `yaml:"name"`
	Action    string   `yaml:"action"` // DENY or ALLOW
	SourceIPs []string `yaml:"source_ips"`
}

// NetworkExtAuthz defines the config for the L4 external authorization filter.
type NetworkExtAuthz struct {
	StatPrefix       string `yaml:"stat_prefix"`
	GRPCCluster      string `yaml:"grpc_cluster"`
	FailureModeAllow bool   `yaml:"failure_mode_allow"`
	TimeoutMS        int    `yaml:"timeout_ms"`
}

// HTTPConnectionManager defines the configuration for the main HTTP handling filter.
type HTTPConnectionManager struct {
	StatPrefix      string       `yaml:"stat_prefix"`
	RouteConfigName string       `yaml:"route_config_name"`
	HTTPFilters     []HTTPFilter `yaml:"http_filters"`
	AccessLogFormat string       `yaml:"access_log_format"`
}

// HTTPFilter represents a filter within the HTTP connection manager.
type HTTPFilter struct {
	Type     string       `yaml:"type"` // e.g., "ext_authz", "grpc_web", "router"
	ExtAuthz *HTTPExtAuthz  `yaml:"ext_authz,omitempty"`
}

// HTTPExtAuthz defines the config for the L7 external authorization HTTP filter.
type HTTPExtAuthz struct {
	HTTPCluster      string `yaml:"http_cluster"`
	FailureModeAllow bool   `yaml:"failure_mode_allow"`
	TimeoutMS        int    `yaml:"timeout_ms"`
}

// RouteConfig defines a named set of routes that can be referenced by an HTTPConnectionManager.
type RouteConfig struct {
	Name         string        `yaml:"name"`
	VirtualHosts []VirtualHost `yaml:"virtual_hosts"`
}

// VirtualHost defines a set of domains and their routing rules.
type VirtualHost struct {
	Name    string   `yaml:"name"`
	Domains []string `yaml:"domains"`
	Routes  []Route  `yaml:"routes"`
}

// Route defines a single routing rule.
type Route struct {
	Match           RouteMatch  `yaml:"match"`
	Action          RouteAction `yaml:"action"`
	DisableExtAuthz bool        `yaml:"disable_ext_authz,omitempty"` // NEW
}

// RouteMatch specifies the criteria for matching a request.
type RouteMatch struct {
	Path   string `yaml:"path,omitempty"`
	Prefix string `yaml:"prefix,omitempty"`
}

// RouteAction specifies what to do when a route matches.
type RouteAction struct {
	Cluster        string          `yaml:"cluster,omitempty"`
	TimeoutSeconds int             `yaml:"timeout_seconds,omitempty"`
	Redirect       *Redirect       `yaml:"redirect,omitempty"`
	DirectResponse *DirectResponse `yaml:"direct_response,omitempty"` // NEW
}

// Redirect defines an HTTP redirect action.
type Redirect struct {
	HttpsRedirect bool `yaml:"https_redirect"`
}

// DirectResponse defines a direct HTTP response without proxying. (NEW)
type DirectResponse struct {
	Status int    `yaml:"status"`
	Body   string `yaml:"body"`
}

// Cluster defines an upstream service cluster, correctly using DNS for discovery.
type Cluster struct {
	Name                  string `yaml:"name"`
	ConnectTimeoutSeconds int    `yaml:"connect_timeout_seconds"`
	Type                  string `yaml:"type"` // e.g., STRICT_DNS
	DnsLookupFamily       string `yaml:"dns_lookup_family,omitempty"` // e.g., V4_ONLY
	DNSName               string `yaml:"dns_name"`
	Port                  uint32 `yaml:"port"`
	IsHTTP2               bool   `yaml:"is_http2"`
}

// Function to parse the manifest from a YAML byte slice.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	err := yaml.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}
	// Here, we can add validation logic in the future.
	return &m, nil
}
