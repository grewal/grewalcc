package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings" // Required for parsing blocklist from KV
	"sync"    // Required for mutex
	"syscall"
	"time"

	consulapi "github.com/hashicorp/consul/api"
)

// Global variable for the Consul client, initialized in main.
var consulClient *consulapi.Client

// --- Configuration Storage & Constants ---
const (
	// ipBlocklistKey defines the Consul KV path for the IP blocklist.
	ipBlocklistKey = "config/security/ip_blocklist"
)

var (
	// configMutex protects concurrent access to the configuration maps below.
	// RWMutex allows multiple readers concurrently but only one writer.
	configMutex sync.RWMutex

	// ipBlocklist stores blocked IP addresses read from Consul KV.
	// The map acts as a set for efficient lookups.
	ipBlocklist map[string]struct{}

	// TODO: Add uaBlocklist map here later
)

// init ensures the configuration maps are initialized before use.
// This runs once before main() when the package is loaded.
func init() {
	ipBlocklist = make(map[string]struct{})
	// TODO: Initialize uaBlocklist here later
}

// --- End Configuration Storage ---

// --- Consul KV Interaction ---

// fetchAndUpdateIPBlocklist fetches the blocklist from Consul KV and updates the in-memory map safely.
func fetchAndUpdateIPBlocklist(logger *slog.Logger) error {
	if consulClient == nil {
		return errors.New("Consul client is not initialized")
	}

	kv := consulClient.KV()
	// Fetch the key from Consul KV using default query options.
	pair, _, err := kv.Get(ipBlocklistKey, nil)
	if err != nil {
		// Log error but allow service to continue with potentially stale config.
		logger.Error("Failed to fetch IP blocklist from Consul KV", "key", ipBlocklistKey, "error", err)
		return fmt.Errorf("failed to get key %s from Consul KV: %w", ipBlocklistKey, err)
	}

	// Create a new map to hold the updated rules; avoids modifying the live map during parsing.
	newBlocklist := make(map[string]struct{})

	if pair != nil && len(pair.Value) > 0 {
		// Key exists and has content; parse it (assuming comma-separated).
		ipListString := string(pair.Value)
		ips := strings.Split(ipListString, ",")
		validIPs := 0
		for _, ip := range ips {
			trimmedIP := strings.TrimSpace(ip)
			if trimmedIP != "" {
				// TODO: Add validation here to ensure it's a valid IP/CIDR format.
				newBlocklist[trimmedIP] = struct{}{}
				validIPs++
			}
		}
		logger.Info("Fetched IP blocklist from Consul KV", "key", ipBlocklistKey, "parsed_ips", validIPs)
	} else {
		// Key doesn't exist or is empty - results in an empty blocklist.
		logger.Warn("IP blocklist key not found or empty in Consul KV", "key", ipBlocklistKey)
	}

	// Safely swap the global map pointer with the newly parsed map.
	configMutex.Lock() // Acquire Write Lock - pauses readers in handleAuthzRequest.
	ipBlocklist = newBlocklist
	configMutex.Unlock() // Release Write Lock - readers can now access the new map.

	logger.Debug("Successfully updated in-memory IP blocklist")
	return nil
}

// --- End Consul KV Interaction ---

// --- HTTP Handlers ---

// handleAuthzRequest is the core handler for Envoy ext_authz check requests.
func handleAuthzRequest(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create a logger with request-specific context.
		requestLogger := logger.With(
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"),
			// TODO: Add X-Request-ID or trace ID if available from Envoy headers.
		)
		requestLogger.Info("Received authz request")

		// TODO: Implement actual IP check using ipBlocklist map (needs X-Forwarded-For parsing).
		// TODO: Implement UA check using uaBlocklist map.
		// TODO: Implement rate limiting using Redis.

		// Placeholder decision logic for now.
		decision := "Allow-Placeholder"
		statusCode := http.StatusOK

		// Example of how IP check would look:
		/*
			clientIP := parseClientIP(r.Header.Get("X-Forwarded-For")) // Needs implementation
			if clientIP != "" {
			    configMutex.RLock() // Acquire Read Lock before reading map.
			    _, blocked := ipBlocklist[clientIP]
			    configMutex.RUnlock() // Release Read Lock promptly.

			    if blocked {
			        requestLogger.Warn("Request denied", "reason", "ip_blocklist", "client_ip", clientIP)
			        decision = "Deny-IPBlock"
			        statusCode = http.StatusForbidden
			    }
			}
		*/

		// Respond to Envoy based on the decision.
		w.Header().Set("X-Authz-Decision", decision) // Custom header for visibility/debugging.
		w.WriteHeader(statusCode)
		if statusCode != http.StatusOK {
			fmt.Fprintf(w, "Denied: %s", decision) // Provide a body for denied responses.
		}
	}
}

// handleHealthz provides a simple Kubernetes-style liveness probe endpoint.
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if consulClient != nil {
		// Perform a quick check against the local agent API.
		_, err := consulClient.Agent().NodeName()
		if err != nil {
			slog.Default().Error("Consul agent health check failed in /healthz", "error", err)
		}
	} else {
		// Log a warning if the check runs before the client is ready.
		slog.Default().Warn("/healthz called before Consul client was initialized")
	}

	// Indicate the HTTP server itself is running.
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

// --- End HTTP Handlers ---

// --- Main Application ---

func main() {
	// Initialize structured JSON logger as the default.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("Starting Grewal Security Service")

	// --- Configuration ---
	// Read listen address from environment or use default.
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9001" // Default service port.
	}
	// Read Consul address from environment or use default.
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	if consulAddr == "" {
		consulAddr = "127.0.0.1:8500" // Default Consul agent address.
	}
	logger.Info("Configuration loaded", "listen_address", listenAddr, "consul_address", consulAddr)

	// --- Initialize Consul Client ---
	var err error // Declare error variable for reuse.
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = consulAddr
	consulClient, err = consulapi.NewClient(consulConfig)
	if err != nil {
		// Failure to create the client object itself is considered fatal.
		logger.Error("Fatal error creating Consul client", "error", err, "address", consulConfig.Address)
		os.Exit(1)
	}

	// Verify initial connectivity to the Consul agent.
	nodeName, err := consulClient.Agent().NodeName()
	if err != nil {
		// Warn if connection fails on startup, but allow service to continue.
		// Might operate with empty/stale rules until connection recovers.
		logger.Warn("Could not connect to Consul agent on startup", "error", err, "address", consulConfig.Address)
	} else {
		logger.Info("Successfully connected to Consul agent.", "node_name", nodeName, "address", consulConfig.Address)
	}
	// --- End Consul Client Init ---

	// --- Initial Configuration Load ---
	// Perform an initial fetch on startup to populate rules before serving traffic.
	if err := fetchAndUpdateIPBlocklist(logger); err != nil {
		// Decide if failure here is fatal. If rules are essential, exit.
		logger.Error("Initial IP blocklist fetch failed", "error", err)
	}
	// TODO: Add initial fetch for UA blocklist here.
	// TODO: Start background goroutine here to poll Consul KV periodically.

	// --- Setup HTTP Server ---
	// Use a dedicated mux for clarity and safety vs. DefaultServeMux.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/", handleAuthzRequest(logger)) // Root path handles authorization checks.

	// Create an explicit http.Server for better control over timeouts and shutdown.
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,  // Timeout for reading request headers/body.
		WriteTimeout: 10 * time.Second, // Timeout for writing response.
		IdleTimeout:  120 * time.Second, // Timeout for keep-alive connections.
	}

	// --- Setup Graceful Shutdown ---
	// Channel to listen for OS signals (Interrupt, Terminate).
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	// Channel to capture potential errors from the ListenAndServe goroutine.
	serverErrChan := make(chan error, 1)

	// Start the HTTP server in a background goroutine.
	go func() {
		logger.Info("Server listening", "address", server.Addr)
		// ListenAndServe blocks until Shutdown() or Close() is called, or an error occurs.
		// It always returns a non-nil error; check if it's ErrServerClosed for clean shutdown.
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- fmt.Errorf("HTTP server ListenAndServe error: %w", err)
		} else {
			// Indicates a clean shutdown initiated by server.Shutdown() or an unexpected stop.
			serverErrChan <- nil
		}
	}()

	logger.Info("Server running. Waiting for signal or server error...")

	// --- Wait for Shutdown Signal or Server Error ---
	// This select block waits for either the server goroutine to error out
	// or for an OS shutdown signal to be received.
	select {
	case err := <-serverErrChan:
		// Server goroutine exited. Check if it was due to an error.
		if err != nil {
			logger.Error("Server failed to start or stopped unexpectedly", "error", err)
			os.Exit(1) // Exit with error code if server couldn't run.
		} else {
			// Server stopped cleanly before a signal was received (less common).
			logger.Info("Server stopped gracefully (before signal).")
		}

	case sig := <-shutdownChan:
		// OS signal received, initiate graceful shutdown.
		logger.Info("Shutdown signal received", "signal", sig.String())

		// TODO: Signal background Consul polling goroutine to stop gracefully.

		// Create a deadline context for the shutdown process.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		// Attempt to gracefully shut down the server, allowing active connections to finish.
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful server shutdown failed", "error", err)
			// Force close if graceful shutdown fails within the deadline.
			if closeErr := server.Close(); closeErr != nil {
				logger.Error("Server Close failed after shutdown error", "error", closeErr)
			}
		} else {
			logger.Info("Server shutdown gracefully.")
		}

		// Wait for the ListenAndServe goroutine to actually exit.
		<-serverErrChan
		logger.Info("Server goroutine finished.")
	}

	logger.Info("Grewal Security Service finished.")
}
