package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync" // Import the sync package
	"syscall"
	"time"

	// External dependencies
	consulapi "github.com/hashicorp/consul/api"

	// Internal package containing our core application logic
	"grewal.cc/services/security-service/go/authz"
)

// handleHealthz provides a simple liveness probe endpoint.
// It remains in main for now as it directly uses the consulClient initialized here.
// TODO: Refactor health checks.
func handleHealthz(client *consulapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if client != nil {
			_, err := client.Agent().NodeName()
			if err != nil {
				slog.Default().Error("Consul agent health check failed in /healthz", "error", err)
				// Optionally return 503 if Consul connection is critical for health
				// w.WriteHeader(http.StatusServiceUnavailable)
				// return
			}
		} else {
			slog.Default().Warn("/healthz check performed before Consul client was initialized")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	}
}

// pollConsulKV periodically fetches configuration from Consul KV.
// It takes the authz service, logger, waitgroup, and quit channel.
func pollConsulKV(app *authz.Service, logger *slog.Logger, wg *sync.WaitGroup, quit chan struct{}) {
	defer wg.Done() // Signal that this goroutine has finished when it returns

	// Define the polling interval
	pollInterval := 60 * time.Second
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

		case <-quit:
			logger.Info("Stopping Consul KV poller.")
			return
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
	logger.Info("Configuration loaded", "listen_address", listenAddr, "consul_address", consulAddr)

	// --- Initialize Shared Dependencies ---
	// Initialize Consul Client (dependency for the authz service)
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal error creating Consul client", "error", err, "address", consulConfig.Address)
		os.Exit(1)
	}

	// Optional: Verify initial Consul connectivity.
	nodeName, err := consulClient.Agent().NodeName()
	if err != nil {
		logger.Warn("Could not verify connection to Consul agent on startup", "error", err, "address", consulConfig.Address)
	} else {
		logger.Info("Successfully connected to Consul agent.", "node_name", nodeName, "address", consulConfig.Address)
	}
	// --- End Dependency Initialization ---

	// --- Create Application Instance ---
	// Instantiate the core authorization service logic from the authz package.
	// Pass consulClient.KV() which satisfies the authz.consulKV interface.
	app := authz.NewService(logger, consulClient.KV()) // Inject the KV store object

	// --- Initial Configuration Load ---
	// Call the exported method on the authz service instance to load initial rules.
	if err := app.FetchAndUpdateIPBlocklist(); err != nil {
		logger.Error("Initial IP blocklist fetch failed", "error", err)
		// Decide policy: exit or continue? For now, continue.
		// os.Exit(1)
	} else {
		logger.Info("Successfully fetched initial IP blocklist from Consul KV")
	}

	// --- Start Background Tasks ---
	var wg sync.WaitGroup       // WaitGroup to manage background goroutines
	quit := make(chan struct{}) // Channel to signal shutdown to background tasks

	wg.Add(1) // Increment WaitGroup counter for the polling goroutine
	go pollConsulKV(app, logger, &wg, quit)
	// --- End Background Tasks Start ---

	// --- Setup HTTP Server and Routes ---
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.HandleAuthzRequest)
	mux.HandleFunc("/healthz", handleHealthz(consulClient)) // Health check still uses the base client

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
			// If server fails, signal background tasks to stop too
			close(quit)
			// Optionally wait for background tasks even on server error, though unlikely to succeed
			// wg.Wait()
			os.Exit(1)
		} else {
			logger.Info("Server stopped gracefully (likely via shutdown completion).")
			// Server stopped cleanly, but we still need to ensure background tasks stop if quit wasn't closed
			close(quit) // Ensure quit is closed if shutdown wasn't triggered by signal
			wg.Wait()   // Wait for background tasks to finish
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
		// Setup a timeout for waiting on background tasks
		waitTimeout := 20 * time.Second // Slightly less than server shutdown timeout
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

		// 3. Shutdown HTTP server
		logger.Debug("Shutting down HTTP server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful server shutdown failed", "error", err)
			// Force close if shutdown fails
			if closeErr := server.Close(); closeErr != nil {
				logger.Error("Server Close failed after shutdown error", "error", closeErr)
			}
		} else {
			logger.Info("HTTP server shutdown gracefully.")
		}

		// 4. Wait for server goroutine to finish (optional, but good practice)
		<-serverErrChan
		logger.Debug("Server goroutine finished.")
		// --- End Graceful Shutdown Sequence ---
	}

	logger.Info("Grewal Security Service finished.")
}
