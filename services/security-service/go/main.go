package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"    // Added for mutex
	"syscall"
	"time"

	consulapi "github.com/hashicorp/consul/api"
)

// Global variable for the Consul client
var consulClient *consulapi.Client

// --- Configuration Storage ---
var (
	// Mutex protects access to the configuration maps
	configMutex sync.RWMutex
	// ipBlocklist stores blocked IP addresses
	(key: IP string, value: empty struct for set-like behavior)
	ipBlocklist map[string]struct{}
	// TODO: Add uaBlocklist map
)

// Initialize the maps
func init() {
	ipBlocklist = make(map[string]struct{})
	// TODO: Initialize uaBlocklist
}

// --- End Configuration Storage ---

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

		// --- Placeholder Logic ---
		// TODO: Implement actual checks (IP, UA, Rate Limit) using Consul/Redis

		// --- Example: Read IP Blocklist (Read Lock) ---
		// clientIP := r.Header.Get("X-Forwarded-For") // Need to parse this properly later
		// if clientIP != "" {
		//    configMutex.RLock() // Acquire Read Lock
		//    _, blocked := ipBlocklist[clientIP]
		//    configMutex.RUnlock() // Release Read Lock
		//
		//    if blocked {
		//        requestLogger.Warn("Request denied", "reason", "ip_blocklist", "client_ip", clientIP)
		//        w.Header().Set("X-Authz-Decision", "Deny-IPBlock")
		//        w.WriteHeader(http.StatusForbidden)
		// 	    fmt.Fprintf(w, "Denied: IP Blocked") // Example body
		//        return // Stop processing
		//    }
		// }
		// --- End Example ---


		decision := "Allow-Placeholder"
		statusCode := http.StatusOK
		// --- End Placeholder Logic ---

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
	} else {
		slog.Default().Warn("/healthz called before Consul client was initialized")
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("Starting Grewal Security Service")

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9001"
	}
	logger.Info("Configuration loaded", "listen_address", listenAddr)

	// --- Configure Consul Client ---
	var err error
	consulConfig := consulapi.DefaultConfig()
	if consulAddr := os.Getenv("CONSUL_HTTP_ADDR"); consulAddr != "" {
		consulConfig.Address = consulAddr
	} else {
		consulConfig.Address = "127.0.0.1:8500"
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

	// TODO: Start background goroutine here to poll Consul KV and update maps

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/", handleAuthzRequest(logger))

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

	logger.Info("Server running. Waiting for signal or error...")

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

		// TODO: Signal background goroutine to stop polling Consul

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
	}

	logger.Info("Grewal Security Service shutting down.")
}
