package authz

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	consulapi "github.com/hashicorp/consul/api"
)

const (
	ipBlocklistKVKey = "config/security/ip_blocklist"
	uaBlocklistKVKey = "config/security/ua_blocklist"
)

// consulKV defines the interface we need from the Consul KV client.
// This allows for easier testing by mocking.
type consulKV interface {
	Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
	// Put(p *consulapi.KVPair, q *consulapi.WriteOptions) (*consulapi.WriteMeta, error)
}

// Service holds the core application logic and dependencies.
type Service struct {
	logger             *slog.Logger
	kv                 consulKV // Use the interface type
	configMutex        sync.RWMutex
	ipBlocklist        map[string]struct{}
	userAgentBlocklist map[string]struct{} // map for User-Agent blocklists
}

// NewService creates a new instance of the authorization Service.
func NewService(logger *slog.Logger, kv consulKV) *Service {
	return &Service{
		logger:             logger,
		kv:                 kv,
		ipBlocklist:        make(map[string]struct{}),
		userAgentBlocklist: make(map[string]struct{}), // Initialize the new map
	}
}

// FetchAndUpdateIPBlocklist retrieves the IP blocklist from Consul KV
// and updates the in-memory cache safely.
func (s *Service) FetchAndUpdateIPBlocklist() error {
	s.logger.Debug("Fetching IP blocklist from Consul KV", "key", ipBlocklistKVKey)
	pair, _, err := s.kv.Get(ipBlocklistKVKey, nil)
	if err != nil {
		// Log the error but don't necessarily fail hard, maybe the key just doesn't exist yet
		s.logger.Error("Failed to fetch IP blocklist from Consul", "key", ipBlocklistKVKey, "error", err)
		return fmt.Errorf("failed to get key '%s' from consul: %w", ipBlocklistKVKey, err)
	}

	newBlocklist := make(map[string]struct{})
	count := 0
	if pair != nil && len(pair.Value) > 0 {
		ips := strings.Split(string(pair.Value), ",")
		for _, ip := range ips {
			trimmedIP := strings.TrimSpace(ip)
			if trimmedIP != "" {
				newBlocklist[trimmedIP] = struct{}{}
				count++
			}
		}
		s.logger.Info("Fetched IP blocklist from Consul KV", "key", ipBlocklistKVKey, "parsed_ips", count)
	} else {
		s.logger.Info("IP blocklist key not found or empty in Consul KV", "key", ipBlocklistKVKey)
	}

	// Lock for writing and update the map
	s.configMutex.Lock()
	s.ipBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Debug("Updated in-memory IP blocklist")

	return nil
}

// FetchAndUpdateUABlocklist retrieves the User-Agent blocklist from Consul KV
// and updates the in-memory cache safely.
func (s *Service) FetchAndUpdateUABlocklist() error {
	s.logger.Debug("Fetching User-Agent blocklist from Consul KV", "key", uaBlocklistKVKey)
	pair, _, err := s.kv.Get(uaBlocklistKVKey, nil)
	if err != nil {
		s.logger.Error("Failed to fetch User-Agent blocklist from Consul", "key", uaBlocklistKVKey, "error", err)
		return fmt.Errorf("failed to get key '%s' from consul: %w", uaBlocklistKVKey, err)
	}

	newBlocklist := make(map[string]struct{})
	count := 0
	if pair != nil && len(pair.Value) > 0 {
		userAgents := strings.Split(string(pair.Value), ",")
		for _, ua := range userAgents {
			trimmedUA := strings.TrimSpace(ua)
			if trimmedUA != "" {
				newBlocklist[trimmedUA] = struct{}{}
				count++
			}
		}
		s.logger.Info("Fetched User-Agent blocklist from Consul KV", "key", uaBlocklistKVKey, "parsed_uas", count)
	} else {
		s.logger.Info("User-Agent blocklist key not found or empty in Consul KV", "key", uaBlocklistKVKey)
	}

	// Lock for writing and update the map
	s.configMutex.Lock()
	s.userAgentBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Debug("Updated in-memory User-Agent blocklist")

	return nil
}

// HandleAuthzRequest is the HTTP handler for Envoy's ext_authz filter.
func (s *Service) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	// Log basic request info
	// Extract relevant headers
	method := r.Method
	path := r.URL.Path
	userAgent := r.Header.Get("User-Agent")
	xff := r.Header.Get("X-Forwarded-For")
	clientIP := ""

	// Basic request logging context
	logAttrs := []any{
		slog.String("method", method),
		slog.String("path", path),
		slog.String("remote_addr", r.RemoteAddr),
		slog.String("user_agent", userAgent),
	}

	// Extract the first IP from X-Forwarded-For if present
	if xff != "" {
		ips := strings.Split(xff, ",")
		clientIP = strings.TrimSpace(ips[0])
		logAttrs = append(logAttrs, slog.String("client_ip", clientIP))
	} else {
		s.logger.Warn("X-Forwarded-For header missing or empty", logAttrs...)
		// Policy decision: Allow or deny requests without XFF? For now, allow.
	}

	// --- Decision Logic ---
	// Acquire read lock to safely access configuration maps
	s.configMutex.RLock()
	defer s.configMutex.RUnlock() // Ensure lock is released

	// 1. Check IP Blocklist (if clientIP is determined)
	if clientIP != "" {
		if _, blocked := s.ipBlocklist[clientIP]; blocked {
			logAttrs = append(logAttrs, slog.String("reason", "ip_blocklist"))
			s.logger.Warn("Request denied", logAttrs...)
			w.Header().Set("X-Authz-Decision", "Deny-IPBlock")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Access denied.")
			return
		}
	}

	// 2. Check User-Agent Blocklist
	if userAgent != "" {
		if _, blocked := s.userAgentBlocklist[userAgent]; blocked {
			// Make sure clientIP attribute is added if available before logging denial
			if clientIP != "" {
				logAttrs = append(logAttrs, slog.String("client_ip", clientIP))
			}
			logAttrs = append(logAttrs, slog.String("reason", "ua_blocklist"))
			s.logger.Warn("Request denied", logAttrs...)
			w.Header().Set("X-Authz-Decision", "Deny-UABlock") // Specific denial reason
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Access denied.")
			return
		}
	}

	// --- End Decision Logic ---

	// If no checks resulted in denial, allow the request.
	// Add clientIP if available before logging the final decision
	if clientIP != "" {
		logAttrs = append(logAttrs, slog.String("client_ip", clientIP))
	}
	s.logger.Info("Request allowed", logAttrs...)
	w.Header().Set("X-Authz-Decision", "Allow")
	w.WriteHeader(http.StatusOK)
	// No body needed for allowed requests according to Envoy spec unless passing headers back
}
