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
	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3"
)

func handleHealthz(client *consulapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		consulOK := false
		if client != nil {
			_, err := client.Agent().NodeName()
			if err != nil {
				slog.Default().Error("Consul agent health check failed in /healthz", "error", err)
			} else {
				consulOK = true
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

func pollConsulKV(app *authz.Service, logger *slog.Logger, wg *sync.WaitGroup, quit chan struct{}) {
	defer wg.Done()

	pollInterval := 300 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	logger.Info("Starting Consul KV poller", "interval", pollInterval)

	for {
		select {
		case <-ticker.C:
			logger.Debug("Polling Consul KV...")

			if err := app.FetchAndUpdateIPBlocklist(); err != nil {
				logger.Error("Error polling Consul KV for IP blocklist", "error", err)
			} else {
				logger.Debug("Successfully polled IP blocklist")
			}

			if err := app.FetchAndUpdateUABlocklist(); err != nil {
				logger.Error("Error polling Consul KV for User-Agent blocklist", "error", err)
			} else {
				logger.Debug("Successfully polled User-Agent blocklist")
			}

			if err := app.FetchAndUpdateRateLimitConfig(); err != nil {
				logger.Error("Error polling Consul KV for Rate Limit config", "error", err)
			} else {
				logger.Debug("Successfully polled Rate Limit config")
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

	// HTTP Listener Address
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
		"http_listen_address", httpListenAddr,
		"grpc_listen_address", grpcListenAddr,
		"consul_address", consulAddr,
		"redis_address", redisAddr,
		"redis_password_set", redisPassword != "",
	)

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal error creating Consul client", "error", err, "address", consulConfig.Address)
		os.Exit(1)
	}
	nodeName, err := consulClient.Agent().NodeName()
	if err != nil {
		logger.Warn("Could not verify connection to Consul agent on startup", "error", err, "address", consulConfig.Address)
	} else {
		logger.Info("Successfully connected to Consul agent.", "node_name", nodeName, "address", consulConfig.Address)
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr, Password: redisPassword, DB: 0})
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	pingErr := rdb.Ping(ctxPing).Err()
	cancelPing()
	if pingErr != nil {
		logger.Error("Fatal error connecting to Redis", "address", redisAddr, "error", pingErr)
		os.Exit(1)
	}
	logger.Info("Successfully connected to Redis", "address", redisAddr)

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
		logger.Error("Initial Rate Limit config fetch failed, using defaults", "error", err)
	} else {
		logger.Info("Successfully fetched initial Rate Limit config")
	}

	var wg sync.WaitGroup
	quit := make(chan struct{})
	wg.Add(1)
	go pollConsulKV(app, logger, &wg, quit)

	// --- HTTP Server Setup ---
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", app.HandleAuthzRequest) // L7 HTTP ext_authz handler
	httpMux.HandleFunc("/healthz", handleHealthz(consulClient))
	httpMux.Handle("/metrics", promhttp.Handler())

	httpServer := &http.Server{
		Addr:         httpListenAddr,
		Handler:      httpMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	httpServerErrChan := make(chan error, 1)
	go func() {
		logger.Info("HTTP Server listening", "address", httpServer.Addr)
		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	networkAuthzController := authz.NewNetworkAuthzServer(app, logger) // Create L4 gRPC handler
	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServer(grpcServer, networkAuthzController) // Register it

	grpcServerErrChan := make(chan error, 1)
	go func() {
		logger.Info("gRPC Server listening", "address", grpcListenAddr)
		if err := grpcServer.Serve(grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			grpcServerErrChan <- fmt.Errorf("gRPC server Serve error: %w", err)
		} else {
			grpcServerErrChan <- nil
		}

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("All servers running. Waiting for signal or server error...")

	select {
	case err := <-httpServerErrChan:
		if err != nil {
			logger.Error("HTTP Server failed or stopped unexpectedly", "error", err)
			grpcServer.Stop()
		} else {
			logger.Info("HTTP Server stopped gracefully (likely via shutdown).")
		}
	case err := <-grpcServerErrChan:
		if err != nil {
			logger.Error("gRPC Server failed or stopped unexpectedly", "error", err)
			_ = httpServer.Shutdown(context.Background())
		} else {
			logger.Info("gRPC Server stopped gracefully (likely via shutdown).")
		}
	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())
		// Graceful shutdown initiated by signal
	}
	// Common shutdown logic follows, whether due to signal or one server stopping.
	// If one server stops due to an error, the other will be stopped here too.
	// If one server stops gracefully (e.g. ListenAndServe returns nil), the other is also shut down.

	logger.Info("Initiating graceful shutdown of all components...")
	logger.Debug("Signaling background tasks to stop...")
	close(quit)

	logger.Debug("Waiting for background tasks to complete...")
	waitTimeout := 20 * time.Second
	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()
	select {
	case <-waitChan:
		logger.Info("All background tasks completed.")
	case <-time.After(waitTimeout):
		logger.Warn("Timeout waiting for background tasks to complete.")
	}

	logger.Debug("Closing Redis client connection...")
	if err := rdb.Close(); err != nil {
		logger.Error("Error closing Redis client during graceful shutdown", "error", err)
	} else {
		logger.Debug("Redis client closed.")
	}

	// Gracefully stop gRPC server first (or concurrently)
	logger.Debug("Shutting down gRPC server gracefully...")
	grpcServer.GracefulStop() // wait for active RPCs to finish
	logger.Info("gRPC server shutdown gracefully.")
	if err, ok := <-grpcServerErrChan; ok && err != nil && !errors.Is(err, grpc.ErrServerStopped) {
         logger.Warn("gRPC server goroutine returned error after GracefulStop", "error", err)
    }


	// Gracefully stop HTTP server
	logger.Debug("Shutting down HTTP server gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Graceful HTTP server shutdown failed", "error", err)
	} else {
		logger.Info("HTTP server shutdown gracefully.")
	}
	if err, ok := <-httpServerErrChan; ok && err != nil && !errors.Is(err, http.ErrServerClosed) {
         logger.Warn("HTTP server goroutine returned error after Shutdown", "error", err)
    }

	logger.Info("Grewal Security Service finished.")
}
