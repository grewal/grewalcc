package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryservice "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
)

const (
	nodeID               = "default-envoy-node"
	grpcKeepaliveTime    = 15 * time.Second
	grpcKeepaliveTimeout = 5 * time.Second
	grpcKeepaliveMinTime = 10 * time.Second
	maxMsgSize           = 4 * 1024 * 1024 // 4MB
	maxConcurrentStreams = 100
)

type logger struct{}

func (l logger) Debugf(format string, args ...interface{}) { log.Printf("[DEBUG] "+format, args...) }
func (l logger) Infof(format string, args ...interface{})  { log.Printf("[INFO] "+format, args...) }
func (l logger) Warnf(format string, args ...interface{})  { log.Printf("[WARN] "+format, args...) }
func (l logger) Errorf(format string, args ...interface{}) { log.Printf("[ERROR] "+format, args...) }

func main() {
	manifestPath := flag.String("manifest", "manifest.yaml", "Path to the manifest.yaml file")
	listenPort := flag.Int("port", 18000, "gRPC server port")
	metricsPort := flag.Int("metrics-port", 9090, "HTTP metrics/health port")
	debug := flag.Bool("debug", false, "Enable verbose xDS protocol logging")
	flag.Parse()

	cache := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, logger{})

	yamlFile, err := os.ReadFile(*manifestPath)
	if err != nil {
		log.Fatalf("Error reading manifest file %s: %v", *manifestPath, err)
	}
	manifest, err := ParseManifest(yamlFile)
	if err != nil {
		log.Fatalf("Error parsing manifest: %v", err)
	}

	// generateSnapshot now returns a pointer.
	snapshot, err := generateSnapshot(manifest)
	if err != nil {
		log.Fatalf("Error generating snapshot: %v", err)
	}
	if err := snapshot.Consistent(); err != nil {
		log.Fatalf("FATAL: Generated snapshot is not consistent: %v", err)
	}
	log.Printf("Snapshot validation passed successfully.")

	// SetSnapshot expects a pointer, which we now have.
	if err := cache.SetSnapshot(context.Background(), nodeID, snapshot); err != nil {
		log.Fatalf("Failed to set initial snapshot: %v", err)
	}
	log.Printf("Loaded initial snapshot version %s for node %s",
		snapshot.GetVersion(resource.ClusterType), nodeID)

	callbacks := createCallbacks(*debug)
	srv := serverv3.NewServer(context.Background(), cache, callbacks)

	grpcServer := createGRPCServer()
	healthServer := registerHealthServices(grpcServer)
	registerDiscoveryServices(grpcServer, srv)

	go startMetricsServer(*metricsPort, healthServer)
	setupGracefulShutdown(grpcServer, healthServer)

	log.Printf("xDS gRPC server listening on :%d", *listenPort)
	log.Printf("Expecting Envoy connections with node.id='%s'", nodeID)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *listenPort))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", *listenPort, err)
	}
	if err := grpcServer.Serve(lis); err != nil {
		log.Printf("gRPC server terminated: %v", err)
	}
}

func createGRPCServer() *grpc.Server {
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	)
}
func registerHealthServices(grpcServer *grpc.Server) *health.Server {
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	return healthServer
}
func registerDiscoveryServices(grpcServer *grpc.Server, srv serverv3.Server) {
	discoveryservice.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, srv)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, srv)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, srv)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, srv)
}
func createCallbacks(debug bool) serverv3.Callbacks {
	return &serverv3.CallbackFuncs{
		StreamOpenFunc: func(ctx context.Context, id int64, typ string) error {
			log.Printf("[INFO] xDS stream opened: stream_id=%d type=%s", id, typ)
			return nil
		},
		StreamClosedFunc: func(id int64, node *core.Node) {
			log.Printf("[INFO] xDS stream closed: stream_id=%d node=%s", id, node.Id)
		},
		StreamRequestFunc: func(id int64, req *discoveryservice.DiscoveryRequest) error {
			if debug {
				log.Printf("[DEBUG] xDS request: stream_id=%d type=%s version=%s resources=%d",
					id, req.TypeUrl, req.VersionInfo, len(req.ResourceNames))
			}
			return nil
		},
		StreamResponseFunc: func(ctx context.Context, id int64, req *discoveryservice.DiscoveryRequest, resp *discoveryservice.DiscoveryResponse) {
			if debug {
				log.Printf("[DEBUG] xDS response: stream_id=%d type=%s version=%s num_resources=%d",
					id, req.TypeUrl, resp.VersionInfo, len(resp.Resources))
			}
		},
		DeltaStreamOpenFunc: func(ctx context.Context, id int64, typ string) error {
			if debug {
				log.Printf("[DEBUG] Delta stream opened: stream_id=%d type=%s", id, typ)
			}
			return nil
		},
		DeltaStreamClosedFunc: func(id int64, node *core.Node) {
			if debug {
				log.Printf("[DEBUG] Delta stream closed: stream_id=%d node=%s", id, node.Id)
			}
		},
	}
}
func startMetricsServer(port int, healthServer *health.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		resp, err := healthServer.Check(r.Context(), &healthpb.HealthCheckRequest{})
		if err != nil || resp.Status != healthpb.HealthCheckResponse_SERVING {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "unhealthy")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "healthy")
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ready")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "# TODO: Implement Prometheus metrics")
	})

	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	log.Printf("HTTP metrics and health server listening on :%d", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("HTTP server error: %v", err)
	}
}
func setupGracefulShutdown(grpcServer *grpc.Server, healthServer *health.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		log.Println("Server stopped gracefully")
	}()
}
