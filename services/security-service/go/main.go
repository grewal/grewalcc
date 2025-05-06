package main

import (
	"context" // Redis checks
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	// External dependencies
	consulapi "github.com/hashicorp/consul/api"
	"github.com/redis/go-redis/v9"

	// Internal package containing our core application logic
	"grewal.cc/services/security-service/go/authz"
)

// handleHealthz provides a simple liveness probe endpoint.
// It remains in main for now as it directly uses the consulClient initialized here.
// TODO: Refactor health checks to potentially include Redis ping.
func handleHealthz(client *consulapi.Client /*, rdb *redis.Client - Add later if needed */) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		consulOK := false
		// Check Consul
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

		// TODO: Add Redis PING check here later if desired for stricter health check
		// redisOK := false
		// if rdb != nil { ... }

		// Decide overall health
		if consulOK /* && redisOK */ {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "OK")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "Service Unavailable")
		}
	}
}

// pollConsulKV periodically fetches configuration from Consul KV.
// It takes the authz service, logger, waitgroup, and quit channel.
func pollConsulKV(app *authz.Service, logger *slog.Logger, wg *sync.WaitGroup, quit chan struct{}) {
	defer wg.Done() // Signal that this goroutine has finished when it returns

	// Define the polling interval
	// TODO: Make this configurable via environment variable
	pollInterval := 300 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop() // Ensure the ticker is stopped when the function exits

	logger.Info("Starting Consul KV poller", "interval", pollInterval)

	for {
		select {
		case <-ticker.C:
			logger.Debug("Polling Consul KV for IP blocklist updates...")
			if err := app.FetchAndUpdateIPBlocklist(); err != nil {
				// Log the error but continue polling
				logger.Error("Error polling Consul KV for IP blocklist", "error", err)
			} else {
				logger.Debug("Successfully polled and updated IP blocklist from Consul KV")
			}

			// Add polling for UA blocklist here as well
			logger.Debug("Polling Consul KV for User-Agent blocklist updates...")
			if err := app.FetchAndUpdateUABlocklist(); err != nil {
				logger.Error("Error polling Consul KV for User-Agent blocklist", "error", err)
			} else {
				logger.Debug("Successfully polled and updated User-Agent blocklist from Consul KV")
			}

			// --- TODO: Add polling for Rate Limit Config ---
			// logger.Debug("Polling Consul KV for Rate Limit config updates...")
			// if err := app.FetchAndUpdateRateLimitConfig(); err != nil { ... }

		case <-quit:
			logger.Info("Stopping Consul KV poller.")
			return // Exit the goroutine
		}
	}
}

// --- Main Application ---

func main() {
	// Initialize structured JSON logger as the default.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("Starting Grewal Security Service")

	// Configuration primarily driven by environment variables.
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9001"
	}
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	if consulAddr == "" {
		consulAddr = "127.0.0.1:8500"
	}
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379" // Default for host networking
	}
	redisPassword := os.Getenv("REDIS_PASSWORD") // Provided by Ansible

	logger.Info("Configuration loaded",
		"listen_address", listenAddr,
		"consul_address", consulAddr,
		"redis_address", redisAddr,
		"redis_password_set", redisPassword != "",
	)

	// --- Initialize Shared Dependencies ---
	// Initialize Consul Client
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal error creating Consul client", "error", err, "address", consulConfig.Address)
		os.Exit(1)
	}
	// Verify initial Consul connectivity.
	nodeName, err := consulClient.Agent().NodeName()
	if err != nil {
		logger.Warn("Could not verify connection to Consul agent on startup", "error", err, "address", consulConfig.Address)
	} else {
		logger.Info("Successfully connected to Consul agent.", "node_name", nodeName, "address", consulConfig.Address)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword, // Read from env var
		DB:       0,             // Default DB
	})

	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing() // Ensure context cancels even on success path
	if err := rdb.Ping(ctxPing).Err(); err != nil { // Use .Err() for direct error check
		logger.Error("Fatal error connecting to Redis", "address", redisAddr, "error", err)
		// For now, make Redis connection mandatory on startup
		os.Exit(1)
	}
	logger.Info("Successfully connected to Redis", "address", redisAddr)
	// --- End Dependency Initialization ---

	// --- Create Application Instance ---
	// Instantiate the core authorization service logic from the authz package.
	// Pass consulClient.KV() which satisfies the authz.consulKV interface.
	app := authz.NewService(logger, consulClient.KV(), rdb) // Inject the Redis client

	// --- Initial Configuration Load ---
	// Call the exported method on the authz service instance to load initial rules.
	if err := app.FetchAndUpdateIPBlocklist(); err != nil {
		logger.Error("Initial IP blocklist fetch failed", "error", err)
	} else {
		logger.Info("Successfully fetched initial IP blocklist from Consul KV")
	}
	// Add initial fetch for UA blocklist using exported app method.
	if err := app.FetchAndUpdateUABlocklist(); err != nil {
		logger.Error("Initial User-Agent blocklist fetch failed", "error", err)
	} else {
		logger.Info("Successfully fetched initial User-Agent blocklist from Consul KV")
	}
	// --- TODO: Add initial fetch for Rate Limit Config ---
	// if err := app.FetchAndUpdateRateLimitConfig(); err != nil { ... }

	// --- Start Background Tasks ---
	var wg sync.WaitGroup       // WaitGroup to manage background goroutines
	quit := make(chan struct{}) // Channel to signal shutdown to background tasks

	wg.Add(1) // Increment WaitGroup counter for the polling goroutine
	go pollConsulKV(app, logger, &wg, quit)
	// --- End Background Tasks Start ---

	// --- Setup HTTP Server and Routes ---
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.HandleAuthzRequest)
	mux.HandleFunc("/healthz", handleHealthz(consulClient /*, rdb - Pass later if needed */)) // Health check

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// --- Setup Graceful Shutdown ---
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
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
			close(quit) // Signal background tasks to stop
			logger.Debug("Closing Redis client connection due to server error...")
			_ = rdb.Close() // Ignore error during unclean shutdown
			os.Exit(1)
		} else {
			logger.Info("Server stopped gracefully (likely via shutdown completion).")
			close(quit) // Ensure quit is closed if shutdown wasn't triggered by signal
			wg.Wait()   // Wait for background tasks to finish AFTER server stop confirmation
			logger.Debug("Closing Redis client connection after server stop...")
			_ = rdb.Close()
			if errClose := rdb.Close(); errClose != nil {
				logger.Error("Error closing Redis client after clean server stop", "error", errClose)
			}
		}

	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())

		// --- Start Graceful Shutdown Sequence ---
		logger.Info("Initiating graceful shutdown...")

		// 1. Signal background tasks to stop
		logger.Debug("Signaling background tasks to stop...")
		close(quit) // Close the quit channel

		// 2. Wait for background tasks to finish
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

		// Close Redis connection after background tasks (which might use it) are done.
		logger.Debug("Closing Redis client connection...")
		if err := rdb.Close(); err != nil {
			logger.Error("Error closing Redis client during graceful shutdown", "error", err)
		} else {
			logger.Debug("Redis client closed.")
		}

		// 3. Shutdown HTTP server
		logger.Debug("Shutting down HTTP server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful server shutdown failed", "error", err)
			if closeErr := server.Close(); closeErr != nil {
				logger.Error("Server Close failed after shutdown error", "error", closeErr)
			}
		} else {
			logger.Info("HTTP server shutdown gracefully.")
		}

		// Wait for the server goroutine to actually finish
		<-serverErrChan
		logger.Debug("Server goroutine finished.")
		// --- End Graceful Shutdown Sequence ---
	}

	logger.Info("Grewal Security Service finished.")
}
