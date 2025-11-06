package main

import (
	"flag"
	"log"
	"os"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

func main() {
	// Define command-line flags for input and output files.
	manifestPath := flag.String("manifest", "manifest.yaml", "Path to the input manifest.yaml file")
	outputPath := flag.String("output", "generated-envoy.yaml", "Path to the output Envoy bootstrap file")
	flag.Parse()

	if *manifestPath == "" {
		log.Fatalf("Error: --manifest flag cannot be empty")
	}

	// Read and parse the manifest file.
	yamlFile, err := os.ReadFile(*manifestPath)
	if err != nil {
		log.Fatalf("Error reading manifest file %s: %v", *manifestPath, err)
	}
	manifest, err := ParseManifest(yamlFile)
	if err != nil {
		log.Fatalf("Error parsing manifest: %v", err)
	}

	// Run the manifest through our translation functions.
	routeResources := makeRoutes(manifest.Routes)
	clusterResources := makeClusters(manifest.Clusters)
	listenerResources, err := makeListeners(manifest.Listeners, routeResources)
	if err != nil {
		log.Fatalf("Error generating listeners: %v", err)
	}

	// The Bootstrap object is the top-level configuration for Envoy.
	config := &bootstrap.Bootstrap{
		StaticResources: &bootstrap.Bootstrap_StaticResources{},
	}

	// Convert the generic []types.Resource slices to their concrete types.
	for _, res := range listenerResources {
		l, _ := res.(*listener.Listener)
		config.StaticResources.Listeners = append(config.StaticResources.Listeners, l)
	}
	for _, res := range clusterResources {
		c, _ := res.(*cluster.Cluster)
		config.StaticResources.Clusters = append(config.StaticResources.Clusters, c)
	}

	// Marshal the bootstrap config using the Protobuf-aware JSON marshaller.
	// This correctly omits empty fields like 'StatsEviction: null'.
	jsonBytes, err := protojson.Marshal(config)
	if err != nil {
		log.Fatalf("Failed to marshal bootstrap config to JSON: %v", err)
	}

	// Convert the clean JSON to YAML.
	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		log.Fatalf("Failed to convert JSON to YAML: %v", err)
	}

	// Write the final YAML to the specified output file.
	err = os.WriteFile(*outputPath, yamlBytes, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file %s: %v", *outputPath, err)
	}

	log.Printf("Successfully generated Envoy configuration at %s", *outputPath)
}
