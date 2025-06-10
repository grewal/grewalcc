// FILE: services/security-service/go/main.go
package main

import (
	"context"
	"errors"
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

	"grewal.cc/services/security-service/go/authz"
	"grewal.cc/services/security-service/go/ebpfctrl"
	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type Config struct {
	HTTPListenAddr       string
	GRPCListenAddr       string
	ConsulAddr           string
	RedisAddr            string
	RedisPassword        string
	XDPLinkInterfaceName string
	XDPEnabledFromEnv    bool
	KVPollerInterval     time.Duration
}

func LoadConfig(logger *slog.Logger) Config {
	getEnv := func(key, fallback string) string {
		if value, exists := os.LookupEnv(key); exists {
			return value
		}
		return fallback
	}
	getEnvBool := func(key string, fallback bool) bool {
		if valueStr, exists := os.LookupEnv(key); exists {
			if parsedVal, err := strconv.ParseBool(valueStr); err == nil {
				return parsedVal
			}
		}
		return fallback
	}

	cfg := Config{
		HTTPListenAddr:       getEnv("HTTP_LISTEN_ADDR", ":9001"),
		GRPCListenAddr:       getEnv("GRPC_LISTEN_ADDR", ":9002"),
		ConsulAddr:           getEnv("CONSUL_HTTP_ADDR", "10.128.0.22:8500"),
		RedisAddr:            getEnv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:        os.Getenv("REDIS_PASSWORD"),
		XDPLinkInterfaceName: getEnv("XDP_INTERFACE_NAME", "ens4"),
		XDPEnabledFromEnv:    getEnvBool("XDP_ENABLED", true),
	}

	pollerIntervalSecStr := getEnv("CONSUL_KV_POLLER_INTERVAL_SECONDS", "300")
	pollerIntervalSec, _ := strconv.ParseInt(pollerIntervalSecStr, 10, 64)
	if pollerIntervalSec <= 0 {
		pollerIntervalSec = 300
	}
	cfg.KVPollerInterval = time.Duration(pollerIntervalSec) * time.Second

	return cfg
}

func handleHealthz(client *consulapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if client != nil {
			if _, err := client.Agent().NodeName(); err == nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, "OK")
				return
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "Service Unavailable")
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	slog.SetDefault(logger)
	logger.Info("Starting Grewal Security Service...")

	cfg := LoadConfig(logger)

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = cfg.ConsulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal: failed to create Consul client", "error", err); os.Exit(1)
	}

	var rdb *redis.Client
	if cfg.RedisAddr != "REDIS_DISABLED_FOR_TESTING" {
		rdbOpts := &redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: 0}
		rdb = redis.NewClient(rdbOpts)
		ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelPing()
		if err := rdb.Ping(ctxPing).Err(); err != nil {
			logger.Error("Fatal: failed to connect to Redis", "error", err); os.Exit(1)
		}
		logger.Info("Successfully connected to Redis", "address", cfg.RedisAddr)
	}

	var xdpController authz.XDPMapSyncer

	if cfg.XDPEnabledFromEnv {
		logger.Info("XDP is enabled via environment config, initializing controller...")
		controller, xdpErr := ebpfctrl.New(logger, cfg.XDPLinkInterfaceName)
		if xdpErr != nil {
			logger.Error("Failed to initialize and attach XDP program", "error", xdpErr)
			logger.Warn("Continuing without XDP kernel-level IP blocking active.")
		} else {
			xdpController = controller
		}
	} else {
		logger.Info("XDP is disabled via environment variable.")
	}

	authzService := authz.NewService(logger, consulClient.KV(), rdb)

	var wg sync.WaitGroup
	appCtx, appCancel := context.WithCancel(context.Background())
	pollerQuitSignal := make(chan struct{})
	wg.Add(1)
	go authz.PollConsulKV(appCtx, authzService, consulClient.KV(), cfg.KVPollerInterval, logger, xdpController, &wg, pollerQuitSignal)

	httpMux := http.NewServeMux()
	httpAuthzHandler := authz.NewHTTPAuthzServer(logger, authzService)
	httpMux.HandleFunc("/authz/", httpAuthzHandler.HandleAuthzRequest)
	httpMux.HandleFunc("/healthz", handleHealthz(consulClient))
	httpMux.Handle("/metrics", promhttp.Handler())

	httpServer := &http.Server{Addr: cfg.HTTPListenAddr, Handler: httpMux}
	httpServerErrChan := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpServerErrChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	grpcListener, err := net.Listen("tcp", cfg.GRPCListenAddr)
	if err != nil { logger.Error("Failed to listen for gRPC", "error", err); os.Exit(1) }
	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, httpAuthzHandler)

	grpcServerErrChan := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			grpcServerErrChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	shutdownSignalChan := make(chan os.Signal, 1)
	signal.Notify(shutdownSignalChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("All servers running. Waiting for shutdown signal or server error...")

	select {
	case err := <-httpServerErrChan: if err != nil { logger.Error("HTTP Server failed", "error", err) }; appCancel(); grpcServer.GracefulStop()
	case err := <-grpcServerErrChan: if err != nil { logger.Error("gRPC Server failed", "error", err) }; appCancel(); _ = httpServer.Shutdown(context.Background())
	case sig := <-shutdownSignalChan: logger.Info("Shutdown signal received", "signal", sig.String()); appCancel(); grpcServer.GracefulStop(); shutdownCtxHttp, httpShutdownCancel := context.WithTimeout(context.Background(), 10*time.Second); defer httpShutdownCancel(); _ = httpServer.Shutdown(shutdownCtxHttp)
	}

	close(pollerQuitSignal)
	pollerDoneChan := make(chan struct{})
	go func() { wg.Wait(); close(pollerDoneChan) }()
	select {
	case <-pollerDoneChan: logger.Info("Consul KV Poller completed.")
	case <-time.After(10 * time.Second): logger.Warn("Timeout waiting for Consul KV Poller.")
	}

	if rdb != nil { _ = rdb.Close() }

	if xdpController != nil {
		if realController, ok := xdpController.(*ebpfctrl.XDPController); ok {
			if err := realController.Close(); err != nil {
				logger.Error("Error closing XDP controller during shutdown", "error", err)
			}
		}
	}

	logger.Info("Grewal Security Service finished.")
}
