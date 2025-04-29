package main

import (
	"context"         // For managing request contexts and cancellation signals
	"errors"          // For standard error types like http.ErrServerClosed
	"fmt"
	"log/slog"        // Structured, leveled logging
	"net/http"
	"os"              // For reading environment variables and signal handling
	"os/signal"       // For catching OS signals
	"syscall"         // For specific signal constants (SIGINT, SIGTERM)
	"time"            // For timeouts
)

// handleAuthzRequest is the placeholder for Envoy ext_authz checks
func handleAuthzRequest(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestLogger := logger.With(
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			// TODO: Add request ID/trace ID later if available from Envoy
		)
		requestLogger.Info("Received authz request")

		// TODO: Implement actual checks (IP, UA, Rate Limit) using Consul/Redis
		decision := "Allow-Placeholder" // Default allow for now
		statusCode := http.StatusOK

		/*
		if someCondition {
			decision = "Deny-Placeholder"
			statusCode = http.StatusForbidden
			requestLogger.Warn("Request denied", "reason", "some_reason")
		}
		*/

		w.Header().Set("X-Authz-Decision", decision)
		w.WriteHeader(statusCode)
		// TODO: write a body, especially for denials
		// if statusCode != http.StatusOK {
		// 	fmt.Fprintf(w, "Denied: %s", decision)
		// }
	}
}

// handleHealthz provides a health check endpoint
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func main() {
	// Initialize structured JSON logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	logger.Info("Starting Grewal Security Service")

	// --- Configuration ---
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9001" // Default port
	}
	logger.Info("Configuration loaded", "listen_address", listenAddr)

	// --- Set up HTTP Server and Routing ---
	mux := http.NewServeMux() // Use a dedicated mux instead of DefaultServeMux
	mux.HandleFunc("/healthz", handleHealthz)
	// Pass the logger to the handler factory function
	mux.HandleFunc("/", handleAuthzRequest(logger)) // All other requests go here for now

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// --- Graceful Shutdown Setup ---
	// Create a channel to listen for OS signals
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a channel to signal when server has finished starting
	serverErrChan := make(chan error, 1)

	// Start the server in a separate goroutine so it doesn't block
	go func() {
		logger.Info("Server listening", "address", server.Addr)
		// ListenAndServe always returns a non-nil error.
		// Use errors.Is() to check for the specific error signifying graceful shutdown.
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- fmt.Errorf("HTTP server ListenAndServe error: %w", err)
		} else {
			serverErrChan <- nil
		}
	}()

	// --- Wait for Shutdown Signal or Server Error ---
	select {
	case err := <-serverErrChan:
		// Server stopped unexpectedly (could be listen error or clean stop before signal)
		if err != nil {
			logger.Error("Server failed to start or stopped unexpectedly", "error", err)
			os.Exit(1) // Exit if server couldn't start
		} else {
			logger.Info("Server stopped gracefully (before signal).")
		}

	case sig := <-shutdownChan:
		logger.Info("Shutdown signal received", "signal", sig.String())

		// Create a context with a timeout for graceful shutdown
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		// Attempt to gracefully shut down the server
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful shutdown failed", "error", err)
			// Force close if shutdown fails
			if err := server.Close(); err != nil {
                 logger.Error("Server Close failed", "error", err)
            }
		} else {
			logger.Info("Server shutdown gracefully.")
		}
	}
}
