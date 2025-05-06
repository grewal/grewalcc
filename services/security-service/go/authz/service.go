package authz

import (
	"context" // Needed for interface method signatures
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time" // Needed for interface method signatures

	consulapi "github.com/hashicorp/consul/api"
	"github.com/redis/go-redis/v9"
)

// Define constants for Consul KV keys
const (
	ipBlocklistKVKey = "config/security/ip_blocklist"
	uaBlocklistKVKey = "config/security/ua_blocklist"
	// Add rate limit keys later:
	// rateLimitEnabledKey      = "config/security/ratelimit/enabled"
	// rateLimitLimitPerWindowKey = "config/security/ratelimit/limit_per_window"
	// rateLimitWindowSecondsKey  = "config/security/ratelimit/window_seconds"
)

// consulKV defines the minimal interface needed for interacting with Consul KV.
type consulKV interface {
	Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
}

// redisClientInterface defines the subset of Redis commands used by the authz service.
// This allows for mocking during testing.
type redisClientInterface interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Ping(ctx context.Context) *redis.StatusCmd // For potential internal health checks
	Close() error                             // For graceful shutdown
}

// Service holds the dependencies and state for the authorization service.
type Service struct {
	logger             *slog.Logger
	consulKV           consulKV             // Interface for Consul KV access
	redisClient        redisClientInterface // Use the interface type
	ipBlocklist        map[string]struct{}
	userAgentBlocklist map[string]struct{}
	configMutex        sync.RWMutex
	// Future: Add fields for rate limit config (enabled, limit, window)
}

// NewService creates a new authorization service instance.
func NewService(logger *slog.Logger, kv consulKV, rdb redisClientInterface) *Service { // Accept interface
	return &Service{
		logger:             logger.With("component", "authz_service"),
		consulKV:           kv,
		redisClient:        rdb, // Store the provided client (interface)
		ipBlocklist:        make(map[string]struct{}),
		userAgentBlocklist: make(map[string]struct{}),
	}
}

// FetchAndUpdateIPBlocklist fetches the IP blocklist from Consul KV and updates the in-memory map.
func (s *Service) FetchAndUpdateIPBlocklist() error {
	kvPair, _, err := s.consulKV.Get(ipBlocklistKVKey, nil)
	if err != nil {
		return fmt.Errorf("failed to get ip_blocklist from consul: %w", err)
	}
	if kvPair == nil || len(kvPair.Value) == 0 {
		s.logger.Info("IP blocklist key not found or empty in Consul KV.", "key", ipBlocklistKVKey)
		s.configMutex.Lock()
		s.ipBlocklist = make(map[string]struct{})
		s.configMutex.Unlock()
		return nil
	}

	ips := strings.Split(string(kvPair.Value), ",")
	newBlocklist := make(map[string]struct{}, len(ips))
	ipCount := 0
	for _, ip := range ips {
		trimmedIP := strings.TrimSpace(ip)
		if trimmedIP != "" {
			newBlocklist[trimmedIP] = struct{}{}
			ipCount++
		}
	}

	s.configMutex.Lock()
	s.ipBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Debug("Updated IP blocklist", "source", "Consul KV", "parsed_ips", ipCount)
	return nil
}

// FetchAndUpdateUABlocklist fetches the User-Agent blocklist from Consul KV.
func (s *Service) FetchAndUpdateUABlocklist() error {
	kvPair, _, err := s.consulKV.Get(uaBlocklistKVKey, nil)
	if err != nil {
		return fmt.Errorf("failed to get ua_blocklist from consul: %w", err)
	}
	if kvPair == nil || len(kvPair.Value) == 0 {
		s.logger.Info("User-Agent blocklist key not found or empty in Consul KV.", "key", uaBlocklistKVKey)
		s.configMutex.Lock()
		s.userAgentBlocklist = make(map[string]struct{})
		s.configMutex.Unlock()
		return nil
	}

	userAgents := strings.Split(string(kvPair.Value), "\n")
	newBlocklist := make(map[string]struct{}, len(userAgents))
	uaCount := 0
	for _, ua := range userAgents {
		trimmedUA := strings.TrimSpace(ua)
		if trimmedUA != "" {
			newBlocklist[trimmedUA] = struct{}{}
			uaCount++
		}
	}

	s.configMutex.Lock()
	s.userAgentBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Debug("Updated User-Agent blocklist", "source", "Consul KV", "parsed_uas", uaCount)
	return nil
}

// HandleAuthzRequest is the HTTP handler for Envoy's external authorization check.
func (s *Service) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	// Extract relevant headers
	xff := r.Header.Get("X-Forwarded-For")
	clientIP := ""
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP = strings.TrimSpace(ips[0])
		}
	}
	userAgent := r.Header.Get("User-Agent")

	// Structured logging context
	logAttrs := []any{
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("client_ip", clientIP),
		slog.String("user_agent", userAgent),
	}

	s.logger.Debug("Received authz request", logAttrs...)

	// --- Decision Logic ---
	s.configMutex.RLock() // Use Read Lock for checking rules
	defer s.configMutex.RUnlock()

	// 1. Check IP Blocklist
	if clientIP != "" {
		if _, blocked := s.ipBlocklist[clientIP]; blocked {
			s.logger.Warn("Request denied", append(logAttrs, slog.String("reason", "ip_blocklist"))...)
			w.Header().Set("X-Authz-Decision", "Deny-IPBlock") 
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Access Denied: IP blocked.")
			return
		}
	}

	// 2. Check User-Agent Blocklist
	if userAgent != "" {
		if _, blocked := s.userAgentBlocklist[userAgent]; blocked {
			s.logger.Warn("Request denied", append(logAttrs, slog.String("reason", "ua_blocklist"))...)
			w.Header().Set("X-Authz-Decision", "Deny-UABlock")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Access Denied: Client blocked.")
			return
		}
	}

	// if s.rateLimitEnabled { ... }

	// Allow if no checks failed
	s.logger.Info("Request allowed", logAttrs...)
	w.Header().Set("X-Authz-Decision", "Allow")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
