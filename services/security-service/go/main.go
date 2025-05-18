// File: services/security-service/go/main.go
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
	"sync"
	"syscall"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"grewal.cc/services/security-service/go/authz"
	"grewal.cc/services/security-service/go/ebpfctrl"
	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3"
)

func handleHealthz(client *consulapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		consulOK := false
		if client != nil {
			if _, err := client.Agent().NodeName(); err == nil {
				consulOK = true
			} else {
				slog.Default().Error("Consul agent health check failed in /healthz", "error", err)
			}
		} else {
			slog.Default().Warn("/healthz check performed before Consul client was initialized")
		}

		if consulOK {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "OK")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "Service Unavailable")
		}
	}
}

func pollConsulKV(app *authz.Service, ebpfController *ebpfctrl.XDPController, logger *slog.Logger, wg *sync.WaitGroup, quit chan struct{}) {
	defer wg.Done()
	pollInterval := 300 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	logger.Info("Starting Consul KV poller", "interval", pollInterval)
	for {
		select {
		case <-ticker.C:
			logger.Debug("Polling Consul KV...")
			var currentIPBlocklist map[string]struct{}
			if err := app.FetchAndUpdateIPBlocklist(); err != nil {
				logger.Error("Error polling Consul KV for IP blocklist", "error", err)
			} else {
				logger.Debug("Successfully polled IP blocklist for authz.Service")
				currentIPBlocklist = app.GetIPBlocklistSnapshot()
			}

			if ebpfController != nil && currentIPBlocklist != nil {
				if err := ebpfController.SyncIPBlocklistToMap(currentIPBlocklist); err != nil {
					logger.Error("Error syncing IP blocklist to eBPF map", "error", err)
				} else {
					logger.Debug("Successfully synced IP blocklist to eBPF map")
				}
			} else if ebpfController != nil && currentIPBlocklist == nil {
				logger.Warn("IP blocklist fetch for authz.Service failed, cannot sync to eBPF map")
			}


			if err := app.FetchAndUpdateUABlocklist(); err != nil {
				logger.Error("Error polling Consul KV for User-Agent blocklist", "error", err)
			} else {
				logger.Debug("Successfully polled User-Agent blocklist")
			}
			if err := app.FetchAndUpdateRateLimitConfig(); err != nil {
				logger.Error("Error polling Consul KV for L7 HTTP Rate Limit config", "error", err)
			} else {
				logger.Debug("Successfully polled L7 HTTP Rate Limit config")
			}
			if err := app.FetchAndUpdateL4ConnRateLimitConfig(); err != nil {
				logger.Error("Error polling Consul KV for L4 Connection Rate Limit config", "error", err)
			} else {
				logger.Debug("Successfully polled L4 Connection Rate Limit config")
			}
		case <-quit:
			logger.Info("Stopping Consul KV poller.")
			return
		}
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	logger.Info("Starting Grewal Security Service")

	httpListenAddr := os.Getenv("HTTP_LISTEN_ADDR")
	if httpListenAddr == "" {
		httpListenAddr = ":9001"
	}
	grpcListenAddr := os.Getenv("GRPC_LISTEN_ADDR")
	if grpcListenAddr == "" {
		grpcListenAddr = ":9002"
	}
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	if consulAddr == "" {
		consulAddr = "127.0.0.1:8500"
	}
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")

	logger.Info("Configuration loaded",
		"http_listen_address", httpListenAddr, "grpc_listen_address", grpcListenAddr,
		"consul_address", consulAddr, "redis_address", redisAddr,
		"redis_password_set", redisPassword != "")

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal error creating Consul client", "error", err, "address", consulConfig.Address)
		os.Exit(1)
	}
	if nodeName, err := consulClient.Agent().NodeName(); err != nil {
		logger.Warn("Could not verify Consul agent connection on startup", "error", err, "address", consulConfig.Address)
	} else {
		logger.Info("Successfully connected to Consul agent", "node_name", nodeName, "address", consulConfig.Address)
	}

	rdbOpts := &redis.Options{Addr: redisAddr, Password: redisPassword, DB: 0}
	if redisAddr == "REDIS_DISABLED_FOR_TESTING" {
	    rdbOpts = nil 
	    logger.Warn("Redis client explicitly disabled for testing.")
	}
	var rdb *redis.Client
	if rdbOpts != nil {
	    rdb = redis.NewClient(rdbOpts)
	    ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	    pingErr := rdb.Ping(ctxPing).Err()
	    cancelPing()
	    if pingErr != nil {
	        logger.Error("Fatal error connecting to Redis", "address", redisAddr, "error", pingErr)
	        os.Exit(1)
	    }
	    logger.Info("Successfully connected to Redis", "address", redisAddr)
	}


	app := authz.NewService(logger, consulClient.KV(), rdb)
	if err := app.FetchAndUpdateIPBlocklist(); err != nil {
		logger.Error("Initial IP blocklist fetch failed", "error", err)
	} else {
		logger.Info("Successfully fetched initial IP blocklist")
	}
	if err := app.FetchAndUpdateUABlocklist(); err != nil {
		logger.Error("Initial User-Agent blocklist fetch failed", "error", err)
	} else {
		logger.Info("Successfully fetched initial User-Agent blocklist")
	}
	if err := app.FetchAndUpdateRateLimitConfig(); err != nil {
		logger.Error("Initial L7 HTTP Rate Limit config fetch failed, using defaults", "error", err)
	} else {
		logger.Info("Successfully fetched initial L7 HTTP Rate Limit config")
	}
	if err := app.FetchAndUpdateL4ConnRateLimitConfig(); err != nil {
		logger.Error("Initial L4 Connection Rate Limit config fetch failed, using defaults", "error", err)
	} else {
		logger.Info("Successfully fetched initial L4 Connection Rate Limit config")
	}
	
	var xdpController *ebpfctrl.XDPController

	xdpIfaceName := os.Getenv("XDP_INTERFACE_NAME")
	if xdpIfaceName == "" {
		xdpIfaceName = ebpfctrl.DefaultXDPLinkInterface
	}
	logger.Info("XDP target interface selected", "interface", xdpIfaceName)

	xdpObjectPath := os.Getenv("XDP_OBJECT_PATH")
	if xdpObjectPath == "" {
		xdpObjectPath = ebpfctrl.DefaultXDPObjPath
	}
	logger.Info("XDP object path selected", "path", xdpObjectPath)

	xdpMapRootPath := os.Getenv("XDP_MAP_ROOT_PATH")
	if xdpMapRootPath == "" {
		xdpMapRootPath = ebpfctrl.DefaultBPFMapRootPath
	}
	logger.Info("XDP map root path selected", "path", xdpMapRootPath)

	xdpIPBlocklistMapName := os.Getenv("XDP_IP_BLOCKLIST_MAP_NAME")
	if xdpIPBlocklistMapName == "" {
		xdpIPBlocklistMapName = ebpfctrl.DefaultIPBlocklistMapName
	}
	logger.Info("XDP IP blocklist map name selected", "name", xdpIPBlocklistMapName)


	xdpOpts := ebpfctrl.XDPControllerOptions{
		Logger:           logger,
		ObjPath:          xdpObjectPath,
		ProgramName:      ebpfctrl.DefaultXDPProgramName,
		LinkInterface:    xdpIfaceName,
		BPFFSMapRootPath: xdpMapRootPath,
		IPBlocklistMapName: xdpIPBlocklistMapName,
	}

	xdpController, err = ebpfctrl.NewXDPController(xdpOpts)
	if err != nil {
		logger.Error("Failed to initialize XDP controller", "error", err)
		xdpController = nil
		logger.Warn("Continuing without XDP kernel-level IP blocking.")
	} else {
		if err := xdpController.EnsureMapPinPathDir(); err != nil {
			logger.Error("Failed to ensure BPF map pin path directory exists", "error", err)
		}
		if err := xdpController.LoadAndAttachProgram(); err != nil {
			logger.Error("Failed to load and attach XDP program", "error", err)
			if detachErr := xdpController.DetachProgram(); detachErr != nil {
				logger.Error("Error detaching XDP program after load/attach failure", "error", detachErr)
			}
			xdpController = nil
			logger.Warn("Continuing without XDP kernel-level IP blocking active.")
		} else {
			logger.Info("XDP program successfully loaded and attached.", "interface", xdpIfaceName)
			initialIPs := app.GetIPBlocklistSnapshot()
			if initialIPs != nil && len(initialIPs) > 0 {
				if err := xdpController.SyncIPBlocklistToMap(initialIPs); err != nil {
					logger.Error("Initial sync of IP blocklist to eBPF map failed", "error", err)
				} else {
					logger.Info("Successfully performed initial sync of IP blocklist to eBPF map")
				}
			}
		}
	}

	var wg sync.WaitGroup
	quit := make(chan struct{})
	wg.Add(1)
	go pollConsulKV(app, xdpController, logger, &wg, quit)

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", app.HandleAuthzRequest)
	httpMux.HandleFunc("/healthz", handleHealthz(consulClient))
	httpMux.Handle("/metrics", promhttp.Handler())
	httpServer := &http.Server{Addr: httpListenAddr, Handler: httpMux, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	httpServerErrChan := make(chan error, 1)
	go func() {
		logger.Info("HTTP Server listening", "address", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpServerErrChan <- fmt.Errorf("HTTP server ListenAndServe error: %w", err)
		} else {
			httpServerErrChan <- nil
		}
	}()

	grpcListener, err := net.Listen("tcp", grpcListenAddr)
	if err != nil {
		logger.Error("Failed to listen for gRPC", "address", grpcListenAddr, "error", err)
		os.Exit(1)
	}
	networkAuthzController := authz.NewNetworkAuthzServer(app, logger)
	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, networkAuthzController)
	grpcServerErrChan := make(chan error, 1)
	go func() {
		logger.Info("gRPC Server listening", "address", grpcListenAddr)
		if err := grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			grpcServerErrChan <- fmt.Errorf("gRPC server Serve error: %w", err)
		} else {
			grpcServerErrChan <- nil
		}
	}()

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("All servers running. Waiting for signal or server error...")

	select {
	case err := <-httpServerErrChan:
		if err != nil {
			logger.Error("HTTP Server failed or stopped unexpectedly", "error", err)
			grpcServer.Stop()
		} else {
			logger.Info("HTTP Server stopped.")
		}
	case err := <-grpcServerErrChan:
		if err != nil {
			logger.Error("gRPC Server failed or stopped unexpectedly", "error", err)
			_ = httpServer.Shutdown(context.Background())
		} else {
			logger.Info("gRPC Server stopped.")
		}
	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())
	}

	logger.Info("Initiating graceful shutdown of all components...")
	close(quit)
	waitTimeout := 20 * time.Second
	waitChan := make(chan struct{})
	go func() { wg.Wait(); close(waitChan) }()
	select {
	case <-waitChan:
		logger.Info("All background tasks completed.")
	case <-time.After(waitTimeout):
		logger.Warn("Timeout waiting for background tasks to complete.")
	}

	if rdb != nil {
	    if err := rdb.Close(); err != nil {
	        logger.Error("Error closing Redis client", "error", err)
	    } else {
	        logger.Debug("Redis client closed.")
	    }
	}


	if xdpController != nil {
		logger.Info("Detaching XDP program...")
		if err := xdpController.DetachProgram(); err != nil {
			logger.Error("Error detaching XDP program during shutdown", "error", err)
		} else {
			logger.Info("XDP program detached successfully.")
		}
	}

	grpcServer.GracefulStop()
	logger.Info("gRPC server shutdown gracefully.")
	if err, ok := <-grpcServerErrChan; ok && err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		logger.Warn("gRPC server goroutine error after GracefulStop", "error", err)
	}

	shutdownCtxHttp, shutdownCancelHttp := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancelHttp()
	if err := httpServer.Shutdown(shutdownCtxHttp); err != nil {
		logger.Error("Graceful HTTP server shutdown failed", "error", err)
	} else {
		logger.Info("HTTP server shutdown gracefully.")
	}
	if err, ok := <-httpServerErrChan; ok && err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Warn("HTTP server goroutine error after Shutdown", "error", err)
	}

	logger.Info("Grewal Security Service finished.")
}
