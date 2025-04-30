package authz // Defines the package for authorization logic

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	consulapi "github.com/hashicorp/consul/api"
)

// --- Constants (Specific to Authz) ---
const (
	// ipBlocklistKey defines the Consul KV path for the IP blocklist.
	ipBlocklistKey = "config/security/ip_blocklist"
	// TODO: Add uaBlocklistKey constant later
)

// --- Consul KV Interface ---

// consulKV abstracts the Consul KV interaction needed by the service.
type consulKV interface {
	Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
}

// --- Application Service Struct ---

// Service holds the application state and dependencies for the authorization service.
// Exported (uppercase 'S') so it can be instantiated in the main package.
type Service struct {
	logger      *slog.Logger
	kv          consulKV          // Holds an implementation of the consulKV interface (real or mock).
	configMutex sync.RWMutex      // Protects concurrent read/write access to configuration maps.
	ipBlocklist map[string]struct{}
	// TODO: Add uaBlocklist map here later
	// TODO: Add Redis client interface here later
}

// NewService creates and initializes a new authorization Service instance.
// Exported (uppercase 'N') to be callable from main.
// Accepts the consulKV interface, allowing injection of real or mock implementations.
func NewService(logger *slog.Logger, kv consulKV) *Service {
	return &Service{
		logger:       logger,
		kv:           kv, // Store the provided KV implementation (real or mock).
		ipBlocklist:  make(map[string]struct{}),
		// configMutex is ready by its zero-value.
	}
}

// --- Core Logic Methods ---

// FetchAndUpdateIPBlocklist fetches the blocklist from Consul KV (via the kv interface)
// and updates the in-memory map safely.
// Exported (uppercase 'F') so it can be called from main during startup or by background pollers.
func (app *Service) FetchAndUpdateIPBlocklist() error {
	if app.kv == nil { // Defensive check for the interface field.
		return errors.New("Consul KV interface is not initialized")
	}

	// Call Get using the injected kv implementation (real or mock).
	pair, _, err := app.kv.Get(ipBlocklistKey, nil) // Passing nil for QueryOptions for standard Get.
	if err != nil {
		// Log error but allow service to continue; prevents paralysis on transient Consul issues.
		app.logger.Error("Failed to fetch IP blocklist from Consul KV", "key", ipBlocklistKey, "error", err)
		return fmt.Errorf("failed to get key %s from Consul KV: %w", ipBlocklistKey, err)
	}

	// Create a new map locally first to avoid holding the lock during parsing.
	newBlocklist := make(map[string]struct{})

	if pair != nil && len(pair.Value) > 0 {
		ipListString := string(pair.Value)
		ips := strings.Split(ipListString, ",")
		validIPs := 0
		for _, ip := range ips {
			trimmedIP := strings.TrimSpace(ip)
			if trimmedIP != "" {
				// TODO: Add IP/CIDR validation here.
				newBlocklist[trimmedIP] = struct{}{}
				validIPs++
			}
		}
		app.logger.Info("Fetched IP blocklist from Consul KV", "key", ipBlocklistKey, "parsed_ips", validIPs)
	} else {
		app.logger.Warn("IP blocklist key not found or empty in Consul KV", "key", ipBlocklistKey)
	}

	// Atomically swap the application's active blocklist with the new one.
	app.configMutex.Lock() // Acquire Write Lock
	app.ipBlocklist = newBlocklist
	app.configMutex.Unlock() // Release Write Lock

	app.logger.Debug("Successfully updated in-memory IP blocklist")
	return nil
}

// HandleAuthzRequest is the core HTTP handler for Envoy ext_authz check requests.
// Exported (uppercase 'H') so it can be assigned to an http.ServeMux route in main.
// Note: This method does not directly use the 'kv' interface field, only the map populated by it.
func (app *Service) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	baseLogger := app.logger.With(
		"method", r.Method,
		"path", r.URL.Path,
		"remote_addr", r.RemoteAddr, // Direct peer (Envoy) address
		"user_agent", r.Header.Get("User-Agent"),
	)

	var clientIP string
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		clientIP = strings.TrimSpace(ips[0])
		baseLogger = baseLogger.With("client_ip", clientIP)
	} else {
		baseLogger.Warn("X-Forwarded-For header missing or empty")
		clientIP = "" // Define policy: Treat as empty/unidentifiable IP.
	}
	baseLogger.Info("Received authz request")

	if clientIP != "" {
		// Safely read the shared blocklist map.
		app.configMutex.RLock() // Acquire Read Lock (allows concurrent reads).
		_, blocked := app.ipBlocklist[clientIP]
		app.configMutex.RUnlock() // Release Read Lock promptly.

		if blocked {
			baseLogger.Warn("Request denied", "reason", "ip_blocklist")
			w.Header().Set("X-Authz-Decision", "Deny-IPBlock") // Custom header aids debugging/observability.
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Access denied.") // Minimal response body.
			return                            // Stop processing.
		}
	}

	// TODO: Implement UA check.
	// TODO: Implement rate limiting.

	decision := "Allow"
	statusCode := http.StatusOK
	w.Header().Set("X-Authz-Decision", decision)
	w.WriteHeader(statusCode)
}

// --- End Core Logic Methods ---
