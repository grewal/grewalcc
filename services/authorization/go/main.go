// FILE: services/authorization/go/main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"grewal.cc/services/authorization/go/authz"
	"grewal.cc/services/authorization/go/kernel"
	pb "grewal.cc/services/authorization/go/pkg/genproto/envoy/service/auth/v3"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

func getConfigValue(flagValue, envKey, defaultValue string) string {
	if flagValue != defaultValue {
		return flagValue
	}
	if envVal, exists := os.LookupEnv(envKey); exists {
		return envVal
	}
	return defaultValue
}

func main() {
	var (
		grpcAddr     = flag.String("grpc-addr", ":9001", "gRPC server listen address (Env: GRPC_ADDR)")
		httpAddr     = flag.String("http-addr", ":9090", "Metrics & Health server listen address (Env: HTTP_ADDR)")
		consulAddr   = flag.String("consul-addr", "", "Consul agent address (Env: CONSUL_ADDR)")
		valkeyAddr   = flag.String("valkey-addr", "", "Valkey server address (Env: VALKEY_ADDR)")
		valkeyPass   = flag.String("valkey-password", "", "Valkey server password (Env: VALKEY_PASSWORD)")
		xdpInterface = flag.String("xdp-interface", "ens4", "Network interface to attach XDP program (Env: XDP_INTERFACE)")
		pollInterval = flag.Int("poll-interval-sec", 30, "Interval in seconds to poll Consul KV (Env: POLL_INTERVAL_SEC)")
		skipFirewall = flag.Bool("skip-xdp-firewall", false, "Skip XDP firewall initialization (Env: SKIP_XDP_FIREWALL)")
	)
	flag.Parse()

	finalGRPCAddr := getConfigValue(*grpcAddr, "GRPC_ADDR", ":9001")
	finalHTTPAddr := getConfigValue(*httpAddr, "HTTP_ADDR", ":9090")
	finalConsulAddr := getConfigValue(*consulAddr, "CONSUL_ADDR", "")
	finalValkeyAddr := getConfigValue(*valkeyAddr, "VALKEY_ADDR", "")
	finalValkeyPass := getConfigValue(*valkeyPass, "VALKEY_PASSWORD", "")
	finalXDPInterface := getConfigValue(*xdpInterface, "XDP_INTERFACE", "ens4")
	finalPollIntervalStr := getConfigValue(strconv.Itoa(*pollInterval), "POLL_INTERVAL_SEC", "30")
	finalPollIntervalSec, _ := strconv.Atoi(finalPollIntervalStr)

	// Check if XDP firewall should be skipped
	skipFirewallStr := getConfigValue(strconv.FormatBool(*skipFirewall), "SKIP_XDP_FIREWALL", "false")
	finalSkipFirewall, _ := strconv.ParseBool(skipFirewallStr)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	logger.Info("Starting authz-service v2.0.5...", "version", "2.0.5")

	if finalValkeyAddr == "" {
		logger.Error("FATAL: Valkey address is not configured. Set --valkey-addr flag or VALKEY_ADDR environment variable.")
		os.Exit(1)
	}

	if finalConsulAddr == "" {
		logger.Error("FATAL: Consul address is not configured. Set --consul-addr flag or CONSUL_ADDR environment variable.")
		os.Exit(1)
	}

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = finalConsulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("FATAL: Failed to create Consul client", "error", err, "address", finalConsulAddr)
		os.Exit(1)
	}

	valkeyClient := redis.NewClient(&redis.Options{
		Addr:         finalValkeyAddr,
		Password:     finalValkeyPass,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := valkeyClient.Ping(ctx).Err(); err != nil {
		logger.Error("FATAL: Failed to connect to Valkey",
			"error", err,
			"address", finalValkeyAddr)
		os.Exit(1)
	}
	logger.Info("Successfully connected to Valkey", "address", finalValkeyAddr)

	// Initialize firewall manager or create a no-op version
	var firewallManager interface{ IsAttached() bool }
	var coreService *authz.Service
	var wg sync.WaitGroup
	var quitSignal chan struct{}
	var backgroundCtx context.Context
	var backgroundCancel context.CancelFunc

	if finalSkipFirewall {
		logger.Warn("XDP firewall DISABLED via SKIP_XDP_FIREWALL flag - service running in degraded mode without kernel-level protection")
		firewallManager = &noopFirewallManager{}
		coreService = authz.NewServiceWithoutFirewall(logger, consulClient.KV(), valkeyClient)
	} else {
		allowedPorts := []uint16{443, 80}
		fm, err := kernel.NewFirewallManager(valkeyClient, finalXDPInterface, allowedPorts, logger)
		if err != nil {
			logger.Error("FATAL: Failed to initialize kernel firewall manager", "error", err, "interface", finalXDPInterface)
			logger.Error("HINT: If running in a restricted environment, set SKIP_XDP_FIREWALL=true to run without XDP")
			os.Exit(1)
		}
		firewallManager = fm
		defer fm.Close()

		coreService = authz.NewService(logger, consulClient.KV(), valkeyClient, fm)

		backgroundCtx, backgroundCancel = context.WithCancel(context.Background())
		quitSignal = make(chan struct{})
		wg.Add(1)
		go authz.RunBackgroundTasks(backgroundCtx, coreService, time.Duration(finalPollIntervalSec)*time.Second, logger, &wg, quitSignal)
	}

	grpcServer := grpc.NewServer()
	authzServer := authz.NewAuthzServer(logger, coreService)
	pb.RegisterAuthorizationServer(grpcServer, authzServer)

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !firewallManager.IsAttached() {
			http.Error(w, "DEGRADED: XDP firewall is not active", http.StatusOK) // Still return 200 if XDP is optional
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		if err := valkeyClient.Ping(ctx).Err(); err != nil {
			http.Error(w, fmt.Sprintf("DEGRADED: Valkey unreachable: %v", err), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	httpMux.Handle("/metrics", promhttp.Handler())
	httpServer := &http.Server{Addr: finalHTTPAddr, Handler: httpMux}

	go func() {
		logger.Info("gRPC server listening", "address", finalGRPCAddr)
		lis, err := net.Listen("tcp", finalGRPCAddr)
		if err != nil {
			logger.Error("gRPC listen failed, shutting down", "error", err)
			os.Exit(1)
		}
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Error("gRPC server failed", "error", err)
		}
	}()

	go func() {
		logger.Info("Metrics & Health server listening", "address", finalHTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server failed", "error", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received, starting graceful shutdown...")

	shutdownCtx, cancelHTTP := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHTTP()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	grpcServer.GracefulStop()

	if !finalSkipFirewall && quitSignal != nil {
		close(quitSignal)
		backgroundCancel()
		wg.Wait()
		logger.Info("Background tasks stopped.")
	}

	logger.Info("Shutdown complete.")
}

// noopFirewallManager is a no-op implementation when XDP is disabled
type noopFirewallManager struct{}

func (n *noopFirewallManager) IsAttached() bool {
	return false
}
