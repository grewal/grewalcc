package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
			}
		} else {
			slog.Default().Warn("/healthz check performed before Consul client was initialized")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
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
		// Decide policy: exit or continue?
		// os.Exit(1)
	}
	// TODO: Add initial fetch for UA blocklist using exported app method.
	// TODO: Start background goroutine here for periodic Consul polling using exported app method.

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
			os.Exit(1)
		} else {
			logger.Info("Server stopped gracefully (likely via shutdown completion).")
		}

	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())

		// TODO: Implement graceful shutdown for background tasks.

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful server shutdown failed", "error", err)
			if closeErr := server.Close(); closeErr != nil {
				logger.Error("Server Close failed after shutdown error", "error", closeErr)
			}
		} else {
			logger.Info("Server shutdown gracefully.")
		}

		<-serverErrChan
		logger.Info("Server goroutine finished.")
	}

	logger.Info("Grewal Security Service finished.")
}
