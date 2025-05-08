package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"grewal.cc/services/security-service/go/authz"
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

	listenAddr := os.Getenv("LISTEN_ADDR"); if listenAddr == "" { listenAddr = ":9001" }
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR"); if consulAddr == "" { consulAddr = "127.0.0.1:8500" }
	redisAddr := os.Getenv("REDIS_ADDR"); if redisAddr == "" { redisAddr = "127.0.0.1:6379" }
	redisPassword := os.Getenv("REDIS_PASSWORD")
	logger.Info("Configuration loaded",
		"listen_address", listenAddr,
		"consul_address", consulAddr,
		"redis_address", redisAddr,
		"redis_password_set", redisPassword != "",
	)

	consulConfig := consulapi.DefaultConfig(); consulConfig.Address = consulAddr
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

	rdb := redis.NewClient(&redis.Options{ Addr: redisAddr, Password: redisPassword, DB: 0 })
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	pingErr := rdb.Ping(ctxPing).Err()
	cancelPing()
	if pingErr != nil {
		logger.Error("Fatal error connecting to Redis", "address", redisAddr, "error", pingErr)
		os.Exit(1)
	}
	logger.Info("Successfully connected to Redis", "address", redisAddr)

	app := authz.NewService(logger, consulClient.KV(), rdb)

	if err := app.FetchAndUpdateIPBlocklist(); err != nil { logger.Error("Initial IP blocklist fetch failed", "error", err) } else { logger.Info("Successfully fetched initial IP blocklist") }
	if err := app.FetchAndUpdateUABlocklist(); err != nil { logger.Error("Initial User-Agent blocklist fetch failed", "error", err) } else { logger.Info("Successfully fetched initial User-Agent blocklist") }
	if err := app.FetchAndUpdateRateLimitConfig(); err != nil { logger.Error("Initial Rate Limit config fetch failed, using defaults", "error", err) } else { logger.Info("Successfully fetched initial Rate Limit config") }

	var wg sync.WaitGroup; quit := make(chan struct{})
	wg.Add(1); go pollConsulKV(app, logger, &wg, quit)

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.HandleAuthzRequest)
	mux.HandleFunc("/healthz", handleHealthz(consulClient))
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	shutdownChan := make(chan os.Signal, 1); signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	serverErrChan := make(chan error, 1)
	go func() {
		logger.Info("Server listening", "address", server.Addr)
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- fmt.Errorf("HTTP server ListenAndServe error: %w", err)
		} else {
			serverErrChan <- nil
		}
	}()

	logger.Info("Server running. Waiting for signal or server error...")

	select {
	case err := <-serverErrChan:
		if err != nil {
			logger.Error("Server failed to start or stopped unexpectedly", "error", err)
			close(quit)
			_ = rdb.Close()
			os.Exit(1)
		} else {
			logger.Info("Server stopped gracefully (likely via shutdown completion).")
			close(quit)
			wg.Wait()
			if errClose := rdb.Close(); errClose != nil {
				logger.Error("Error closing Redis client after clean server stop", "error", errClose)
			}
		}

	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())
		logger.Info("Initiating graceful shutdown...")
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

		logger.Debug("Shutting down HTTP server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful server shutdown failed", "error", err)
		} else {
			logger.Info("HTTP server shutdown gracefully.")
		}

		finalServerErr := <-serverErrChan
		if finalServerErr != nil {
		    logger.Warn("Server goroutine returned error after shutdown", "error", finalServerErr)
		}
		logger.Debug("Server goroutine confirmed finished.")
	}

	logger.Info("Grewal Security Service finished.")
}
