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

	consulapi "github.com/hashicorp/consul/api"
)

// Global variable for the Consul client
var consulClient *consulapi.Client

// handleAuthzRequest is the placeholder for Envoy ext_authz checks
func handleAuthzRequest(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestLogger := logger.With(
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
		)
		requestLogger.Info("Received authz request")

		// TODO: Implement actual checks (IP, UA, Rate Limit) using Consul/Redis
		decision := "Allow-Placeholder"
		statusCode := http.StatusOK
		w.Header().Set("X-Authz-Decision", decision)
		w.WriteHeader(statusCode)
	}
}

// handleHealthz provides a health check endpoint
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if consulClient != nil {
		_, err := consulClient.Agent().NodeName()
		if err != nil {
			slog.Default().Error("Consul agent health check failed in /healthz", "error", err)
		}
		// If err is nil, Consul check passed, proceed to return OK
	} else {
		// Log a warning if the health check is called before the client is ready
		slog.Default().Warn("/healthz called before Consul client was initialized")
		// Still return OK for basic liveness
	}

	// Always return OK status for liveness regardless of Consul state (as per current logic)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// Set as default logger for convenience in places like handleHealthz
	slog.SetDefault(logger)

	logger.Info("Starting Grewal Security Service")

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9001" // Server port address
	}
	logger.Info("Configuration loaded", "listen_address", listenAddr)

	// --- Configure Consul Client ---
	var err error
	consulConfig := consulapi.DefaultConfig()
	// Allow overriding via environment variable if needed (CONSUL_HTTP_ADDR)
	if consulAddr := os.Getenv("CONSUL_HTTP_ADDR"); consulAddr != "" {
		consulConfig.Address = consulAddr
	} else {
		consulConfig.Address = "127.0.0.1:8500" // Default Consul agent address
	}

	consulClient, err = consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Error("Fatal error creating Consul client", "error", err, "address", consulConfig.Address)
		os.Exit(1)
	}

	nodeName, err := consulClient.Agent().NodeName()
	if err != nil {
		logger.Warn("Could not connect to Consul agent on startup", "error", err, "address", consulConfig.Address)
	} else {
		logger.Info("Successfully connected to Consul agent.", "node_name", nodeName, "address", consulConfig.Address)
	}
	// --- End Consul Client Config ---

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/", handleAuthzRequest(logger)) // Root handles authz requests

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

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

	select {
	case err := <-serverErrChan:
		if err != nil {
			logger.Error("Server failed to start or stopped unexpectedly", "error", err)
			os.Exit(1)
		} else {
			logger.Info("Server stopped gracefully (likely via shutdown).")
		}

	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		// Attempt graceful shutdown
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful server shutdown failed", "error", err)
			// Force close if shutdown fails
			if closeErr := server.Close(); closeErr != nil {
				logger.Error("Server Close failed after shutdown error", "error", closeErr)
			}
		} else {
			logger.Info("Server shutdown gracefully.")
		}

		<-serverErrChan
		logger.Info("Server goroutine finished.")
	}
	logger.Info("Grewal Security Service shutting down.")
}
