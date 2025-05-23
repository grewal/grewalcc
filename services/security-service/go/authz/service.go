// File: services/security-service/go/authz/service.go
package authz

import (
	"context"
	"crypto/rand" // For fallback request ID
	"encoding/hex"  // For fallback request ID
	"errors"
	"fmt"
	"log/slog"
	"net" // For getClientIP
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3"

	"github.com/envoyproxy/go-control-plane/envoy/type/v3" // For pb.DeniedHttpResponse status
	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	// promhttp is implicitly used by main.go for the /metrics endpoint
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes" // For gRPC status codes
	"google.golang.org/grpc/status" // For gRPC status creation
)

// XDPMapSyncer is a type alias for *ebpfctrl.XDPController.
// This interface is what PollConsulKV will expect for syncing to eBPF map.
type XDPMapSyncer interface {
	SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error
}

// KV Key constants
const (
	ipBlocklistKVKey                  = "config/security/ip_blocklist"
	uaBlocklistKVKey                  = "config/security/ua_blocklist"
	l7RateLimitEnabledKey             = "config/security/ratelimit/enabled" // L7 HTTP RL
	l7RateLimitLimitPerWindowKey      = "config/security/ratelimit/limit_per_window"
	l7RateLimitWindowSecondsKey       = "config/security/ratelimit/window_seconds"
	l4ConnRateLimitEnabledKey         = "config/security/l4_conn_ratelimit/enabled"
	l4ConnRateLimitLimitPerWindowKey  = "config/security/l4_conn_ratelimit/limit_per_window"
	l4ConnRateLimitWindowSecondsKey   = "config/security/l4_conn_ratelimit/window_seconds"
	l4XDPBlocklistLogicEnabledKey     = "config/security/l4_xdp_blocklist_logic/enabled" // Controls if L4 gRPC handler checks IP list if XDP missed
	xdpGlobalEnabledKey               = "config/security/xdp/enabled"                    // Master switch for XDP map syncing
)

// Default configuration values
const (
	defaultL7RateLimitEnabled             = false
	defaultL7RateLimitCount               = 100
	defaultL7RateLimitWindowSeconds       = 60
	defaultL4ConnRateLimitEnabled         = false
	defaultL4ConnRateLimitCount           = 50
	defaultL4ConnRateLimitWindowSeconds   = 10
	defaultL4XDPBlocklistLogicEnabled     = true // Enable L4 Go blocklist check by default as defense-in-depth
	defaultXDPGlobalEnabled               = true // Enable XDP map syncing by default
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "http_authz", Name: "requests_total",
			Help: "Total number of L7 HTTP authorization requests processed.",
		},
		[]string{"decision", "reason"},
	)
	networkRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "network_authz", Name: "requests_total",
			Help: "Total number of L4 Network authorization requests processed.",
		},
		[]string{"decision", "reason"},
	)
	l4ConnectionsRateLimitedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "network_authz", Name: "connections_rate_limited_total",
			Help: "Total number of L4 TCP connections denied due to rate limiting.",
		},
	)
	redisErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "dependencies", Name: "redis_errors_total",
			Help: "Total number of errors encountered while interacting with Redis.",
		},
	)
	consulKVErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "dependencies", Name: "consul_kv_errors_total",
			Help: "Total number of errors encountered while fetching from Consul KV.",
		},
	)
	configReloadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "config", Name: "reloads_total",
			Help: "Total number of successful configuration reloads from Consul KV.",
		},
		[]string{"type"},
	)
	EbpfMapSyncTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authz", Subsystem: "ebpf", Name: "map_sync_total",
			Help: "Total number of eBPF map synchronization attempts.",
		},
		[]string{"status"}, // "success", "failure", "skipped_nil_controller", "clear_success", "clear_failure"
	)
)

// consulKVGetter abstracts the Consul KV client's Get method for testability.
type consulKVGetter interface {
	Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
}

// redisClientInterface abstracts the Redis client methods used by the service.
type redisClientInterface interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
	Pipeline() redis.Pipeliner
}

// Service holds the core application logic and state.
type Service struct {
	logger                     *slog.Logger
	consulKVClient             consulKVGetter
	redisClient                redisClientInterface
	configMutex                sync.RWMutex
	ipBlocklist                map[string]struct{}
	userAgentBlocklist         map[string]struct{}
	l7RateLimitEnabled         bool
	l7RateLimitCount           int64
	l7RateLimitWindow          time.Duration
	l4ConnRateLimitEnabled     bool
	l4ConnRateLimitCount       int64
	l4ConnRateLimitWindow      time.Duration
	l4XDPBlocklistLogicEnabled bool // If L4 gRPC handler should check IP list (defense-in-depth if XDP misses)
	xdpGlobalEnabled           bool // Master switch for XDP map syncing
}

// NewService creates a new authorization service instance.
func NewService(logger *slog.Logger, kv consulKVGetter, rdb redisClientInterface) *Service {
	return &Service{
		logger:                     logger.With("component", "authz_service_core"),
		consulKVClient:             kv,
		redisClient:                rdb,
		ipBlocklist:                make(map[string]struct{}),
		userAgentBlocklist:         make(map[string]struct{}),
		l7RateLimitEnabled:         defaultL7RateLimitEnabled,
		l7RateLimitCount:           defaultL7RateLimitCount,
		l7RateLimitWindow:          defaultL7RateLimitWindowSeconds * time.Second,
		l4ConnRateLimitEnabled:     defaultL4ConnRateLimitEnabled,
		l4ConnRateLimitCount:       defaultL4ConnRateLimitCount,
		l4ConnRateLimitWindow:      defaultL4ConnRateLimitWindowSeconds * time.Second,
		l4XDPBlocklistLogicEnabled: defaultL4XDPBlocklistLogicEnabled,
		xdpGlobalEnabled:           defaultXDPGlobalEnabled,
	}
}

// Update methods for thread-safe config updates from poller
func (s *Service) UpdateIPBlocklist(newBlocklist map[string]struct{}) {
	s.configMutex.Lock()
	s.ipBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Info("IP blocklist updated (for L4/L7 Go logic)", "count", len(s.ipBlocklist))
}
func (s *Service) UpdateUABlocklist(newBlocklist map[string]struct{}) {
	s.configMutex.Lock()
	s.userAgentBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Info("User-Agent blocklist updated", "count", len(s.userAgentBlocklist))
}
func (s *Service) UpdateL7RateLimitConfig(config RateLimitConfig) {
	s.configMutex.Lock()
	s.l7RateLimitEnabled = config.Enabled
	s.l7RateLimitCount = config.Limit
	s.l7RateLimitWindow = config.Window
	s.configMutex.Unlock()
	s.logger.Info("L7 HTTP rate limit config updated", "enabled", config.Enabled, "limit", config.Limit, "window", config.Window)
}
func (s *Service) UpdateL4ConnRateLimitConfig(config RateLimitConfig) {
	s.configMutex.Lock()
	s.l4ConnRateLimitEnabled = config.Enabled
	s.l4ConnRateLimitCount = config.Limit
	s.l4ConnRateLimitWindow = config.Window
	s.configMutex.Unlock()
	s.logger.Info("L4 Connection rate limit config updated", "enabled", config.Enabled, "limit", config.Limit, "window", config.Window)
}
func (s *Service) UpdateL4XDPBlocklistLogicEnabled(enabled bool) {
	s.configMutex.Lock()
	s.l4XDPBlocklistLogicEnabled = enabled
	s.configMutex.Unlock()
	s.logger.Info("L4 XDP Blocklist Logic (for L4 gRPC) enabled status updated", "enabled", enabled)
}
func (s *Service) UpdateXDPGlobalEnabled(enabled bool) {
	s.configMutex.Lock()
	s.xdpGlobalEnabled = enabled
	s.configMutex.Unlock()
	s.logger.Info("Global XDP Enabled status updated (for poller's eBPF sync decision)", "enabled", enabled)
}


// GetIPBlocklistSnapshot returns a copy of the current in-memory IP blocklist.
// Used by main.go for initial eBPF map sync.
func (s *Service) GetIPBlocklistSnapshot() map[string]struct{} {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	// Return a copy to avoid race conditions if the caller modifies it,
	// though current usage in main.go is read-only for XDP sync.
	snapshot := make(map[string]struct{}, len(s.ipBlocklist))
	for ip, val := range s.ipBlocklist {
		snapshot[ip] = val
	}
	return snapshot
}

// Getter methods for thread-safe access to config by handlers
func (s *Service) IsIPBlocked(ip string) bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	_, blocked := s.ipBlocklist[ip]
	return blocked
}
func (s *Service) IsUABlocked(ua string) bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	for blockedUA := range s.userAgentBlocklist {
		if strings.Contains(ua, blockedUA) {
			return true
		}
	}
	return false
}
func (s *Service) GetL7RateLimitConfig() (enabled bool, limit int64, window time.Duration) {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	return s.l7RateLimitEnabled, s.l7RateLimitCount, s.l7RateLimitWindow
}
func (s *Service) GetL4ConnRateLimitConfig() (enabled bool, limit int64, window time.Duration) {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	return s.l4ConnRateLimitEnabled, s.l4ConnRateLimitCount, s.l4ConnRateLimitWindow
}

// IsL4XDPBlocklistLogicEnabled is used by the L4 gRPC handler to decide if it should
// perform its own IP blocklist check (as a defense-in-depth if XDP is off or missed something).
func (s *Service) IsL4XDPBlocklistLogicEnabled() bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	return s.l4XDPBlocklistLogicEnabled
}
// IsXDPGlobalEnabled is used by the poller to decide whether to sync to eBPF map.
func (s *Service) IsXDPGlobalEnabled() bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	return s.xdpGlobalEnabled
}


// RateLimitConfig holds parameters for a rate limiter.
type RateLimitConfig struct {
	Enabled bool
	Limit   int64
	Window  time.Duration
}

// Helper function to fetch a list (IPs or UAs) from Consul KV.
// Assumes newline-separated entries for UAs, comma-separated for IPs (consistent with current).
func fetchListFromKV(kv consulKVGetter, key string, logger *slog.Logger, configTypeLabel string, delimiter string) (map[string]struct{}, error) {
	list := make(map[string]struct{})
	kvPair, _, err := kv.Get(key, nil)
	if err != nil {
		logger.Error("Failed to get list from Consul KV", "type", configTypeLabel, "key", key, "error", err)
		consulKVErrorsTotal.Inc()
		return list, fmt.Errorf("fetching %s from %s: %w", configTypeLabel, key, err)
	}

	if kvPair == nil || len(kvPair.Value) == 0 {
		logger.Info("List key not found or empty in Consul KV", "type", configTypeLabel, "key", key)
		return list, nil // Return empty map, not an error
	}

	entries := strings.Split(string(kvPair.Value), delimiter)
	entryCount := 0
	for _, entry := range entries {
		trimmedEntry := strings.TrimSpace(entry)
		if trimmedEntry != "" {
			list[trimmedEntry] = struct{}{}
			entryCount++
		}
	}

	if entryCount > 0 {
		logger.Info("Successfully fetched list from Consul KV", "type", configTypeLabel, "key", key, "count", entryCount)
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	} else {
		logger.Info("List from Consul KV effectively empty after processing", "type", configTypeLabel, "key", key)
		// Still a successful fetch of an empty list
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	}
	return list, nil
}

// Helper function to fetch rate limit parameters from Consul KV.
func fetchRateLimitConfigFromKV(kv consulKVGetter, enabledKey, limitKey, windowKey string, defaults RateLimitConfig, logger *slog.Logger, configTypeLabel string) (RateLimitConfig, error) {
	config := defaults // Start with defaults
	var combinedErr error
	var errs []string // To accumulate multiple error messages

	logAndCombineError := func(newErr error, fieldName string) {
		if newErr != nil {
			errs = append(errs, fmt.Sprintf("%s_for_%s: %s", fieldName, configTypeLabel, newErr.Error()))
			if combinedErr == nil { // Store the first error encountered
				combinedErr = newErr
			}
		}
	}

	// Fetch Enabled Flag
	kvPairEnabled, _, err := kv.Get(enabledKey, nil)
	if err != nil {
		logger.Error("Failed to get RL enabled flag from Consul", "type", configTypeLabel, "key", enabledKey, "error", err)
		logAndCombineError(err, "enabled_flag_fetch")
	} else if kvPairEnabled != nil && len(kvPairEnabled.Value) > 0 {
		parsedBool, errConv := strconv.ParseBool(string(kvPairEnabled.Value))
		if errConv != nil {
			logger.Error("Failed to parse RL enabled flag, using default.", "type", configTypeLabel, "key", enabledKey, "value", string(kvPairEnabled.Value), "default", defaults.Enabled, "error", errConv)
			logAndCombineError(errConv, "enabled_flag_parse")
		} else {
			config.Enabled = parsedBool
		}
	} else {
		logger.Info("RL enabled key not found or empty, using default.", "type", configTypeLabel, "key", enabledKey, "default", defaults.Enabled)
	}

	// Fetch Limit Count
	kvPairLimit, _, err := kv.Get(limitKey, nil)
	if err != nil {
		logger.Error("Failed to get RL count from Consul", "type", configTypeLabel, "key", limitKey, "error", err)
		logAndCombineError(err, "limit_fetch")
	} else if kvPairLimit != nil && len(kvPairLimit.Value) > 0 {
		parsedInt, errConv := strconv.ParseInt(string(kvPairLimit.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			finalErrConv := errConv
			if errConv == nil { // if parsedInt <= 0
				finalErrConv = fmt.Errorf("parsed limit %d is not positive", parsedInt)
			}
			logger.Error("Failed to parse RL count or value is not positive, using default.", "type", configTypeLabel, "key", limitKey, "value", string(kvPairLimit.Value), "default", defaults.Limit, "error", finalErrConv)
			logAndCombineError(finalErrConv, "limit_parse")
		} else {
			config.Limit = parsedInt
		}
	} else {
		logger.Info("RL count key not found or empty, using default.", "type", configTypeLabel, "key", limitKey, "default", defaults.Limit)
	}

	// Fetch Window Seconds
	kvPairWindow, _, err := kv.Get(windowKey, nil)
	if err != nil {
		logger.Error("Failed to get RL window from Consul", "type", configTypeLabel, "key", windowKey, "error", err)
		logAndCombineError(err, "window_fetch")
	} else if kvPairWindow != nil && len(kvPairWindow.Value) > 0 {
		parsedInt, errConv := strconv.ParseInt(string(kvPairWindow.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			finalErrConv := errConv
			if errConv == nil { // if parsedInt <= 0
				finalErrConv = fmt.Errorf("parsed window %d is not positive", parsedInt)
			}
			logger.Error("Failed to parse RL window or value is not positive, using default.", "type", configTypeLabel, "key", windowKey, "value", string(kvPairWindow.Value), "default", int64(defaults.Window/time.Second), "error", finalErrConv)
			logAndCombineError(finalErrConv, "window_parse")
		} else {
			config.Window = time.Duration(parsedInt) * time.Second
		}
	} else {
		logger.Info("RL window key not found or empty, using default.", "type", configTypeLabel, "key", windowKey, "default", int64(defaults.Window/time.Second))
	}

	if combinedErr != nil {
		consulKVErrorsTotal.Inc()
		if len(errs) > 1 { // If multiple fields had errors, create a combined error message.
			combinedErr = fmt.Errorf("multiple errors occurred while fetching %s config from Consul: %s", configTypeLabel, strings.Join(errs, "; "))
		}
	} else if (kvPairEnabled != nil && len(kvPairEnabled.Value) > 0) ||
		(kvPairLimit != nil && len(kvPairLimit.Value) > 0) ||
		(kvPairWindow != nil && len(kvPairWindow.Value) > 0) {
		// Only increment config reloads if at least one relevant KV key was present and fetched (even if it parsed to default later)
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	}

	logger.Info("Fetched RL config details", "type", configTypeLabel, "enabled", config.Enabled, "limit", config.Limit, "window_seconds", config.Window.Seconds())
	return config, combinedErr
}

// Helper function to fetch a boolean flag from Consul KV.
func fetchBoolFromKV(kv consulKVGetter, key string, defaultValue bool, logger *slog.Logger, configTypeLabel string) (bool, error) {
	val := defaultValue
	var finalErr error
	kvPair, _, err := kv.Get(key, nil)
	if err != nil {
		logger.Error("Failed to get bool flag from Consul KV", "type", configTypeLabel, "key", key, "error", err)
		consulKVErrorsTotal.Inc()
		finalErr = fmt.Errorf("fetching %s for key %s: %w", configTypeLabel, key, err)
	} else if kvPair == nil || len(kvPair.Value) == 0 {
		logger.Info("Bool flag key not found or empty in Consul KV, using default.", "type", configTypeLabel, "key", key, "default", defaultValue)
	} else {
		parsedBool, errConv := strconv.ParseBool(string(kvPair.Value))
		if errConv != nil {
			logger.Error("Failed to parse bool flag from Consul KV, using default.", "type", configTypeLabel, "key", key, "value", string(kvPair.Value), "default", defaultValue, "error", errConv)
			consulKVErrorsTotal.Inc()
			finalErr = fmt.Errorf("parsing %s for key %s: %w", configTypeLabel, key, errConv)
		} else {
			val = parsedBool
		}
	}
	if finalErr == nil && (kvPair != nil && len(kvPair.Value) > 0) {
		// Only increment if KV key was present and successfully parsed
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	}
	logger.Info("Fetched bool flag", "type", configTypeLabel, "key", key, "value_loaded", val, "default_was", defaultValue)
	return val, finalErr
}


// FetchAllConfigsFromConsul fetches all dynamic configurations from Consul KV.
func FetchAllConfigsFromConsul(kv consulKVGetter, logger *slog.Logger) (
	ipBlocklist map[string]struct{},
	uaBlocklist map[string]struct{},
	l7RLConfig RateLimitConfig,
	l4ConnRLConfig RateLimitConfig,
	l4XDPBlocklistLogicEnabled bool,
	xdpGlobalEnabledFlag bool,
	combinedError error,
) {
	var errs []string
	logAndAccumulateError := func(newErr error, configName string) {
		if newErr != nil {
			errs = append(errs, fmt.Sprintf("error_fetching_%s: %v", configName, newErr))
		}
	}

	ipBlocklist, ipErr := fetchListFromKV(kv, ipBlocklistKVKey, logger, "ip_blocklist", ",")
	logAndAccumulateError(ipErr, "ip_blocklist")

	uaBlocklist, uaErr := fetchListFromKV(kv, uaBlocklistKVKey, logger, "ua_blocklist", "\n")
	logAndAccumulateError(uaErr, "ua_blocklist")

	defaultL7RL := RateLimitConfig{Enabled: defaultL7RateLimitEnabled, Limit: defaultL7RateLimitCount, Window: time.Duration(defaultL7RateLimitWindowSeconds) * time.Second}
	l7RLConfig, l7Err := fetchRateLimitConfigFromKV(kv, l7RateLimitEnabledKey, l7RateLimitLimitPerWindowKey, l7RateLimitWindowSecondsKey, defaultL7RL, logger, "l7_http_rate_limit")
	logAndAccumulateError(l7Err, "l7_http_rate_limit")

	defaultL4ConnRL := RateLimitConfig{Enabled: defaultL4ConnRateLimitEnabled, Limit: defaultL4ConnRateLimitCount, Window: time.Duration(defaultL4ConnRateLimitWindowSeconds) * time.Second}
	l4ConnRLConfig, l4ConnErr := fetchRateLimitConfigFromKV(kv, l4ConnRateLimitEnabledKey, l4ConnRateLimitLimitPerWindowKey, l4ConnRateLimitWindowSecondsKey, defaultL4ConnRL, logger, "l4_conn_rate_limit")
	logAndAccumulateError(l4ConnErr, "l4_conn_rate_limit")

	l4XDPBlocklistLogicEnabled, l4XDPLGErr := fetchBoolFromKV(kv, l4XDPBlocklistLogicEnabledKey, defaultL4XDPBlocklistLogicEnabled, logger, "l4_xdp_blocklist_logic_enabled")
	logAndAccumulateError(l4XDPLGErr, "l4_xdp_blocklist_logic_enabled")

	xdpGlobalEnabledFlag, xdpGlobalErr := fetchBoolFromKV(kv, xdpGlobalEnabledKey, defaultXDPGlobalEnabled, logger, "xdp_global_enabled")
	logAndAccumulateError(xdpGlobalErr, "xdp_global_enabled")

	if len(errs) > 0 {
		combinedError = errors.New("one or more errors occurred while fetching configurations from Consul: " + strings.Join(errs, "; "))
	}
	return
}


// PollConsulKV periodically fetches configuration from Consul KV and updates the service.
// It also calls the XDPMapSyncer to update the eBPF map if XDP is globally enabled.
func PollConsulKV(
	ctx context.Context, // Application context for graceful shutdown
	s *Service,
	consulKVClient consulKVGetter,
	interval time.Duration,
	logger *slog.Logger,
	xdpSyncer XDPMapSyncer, // Use the interface type here
	wg *sync.WaitGroup,
	quitSignal <-chan struct{}, // Separate quit signal for the poller
) {
	defer wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Perform an initial fetch and update immediately
	updateConfigs := func(isInitial bool) {
		logCtx := "Polling Consul KV for all configurations..."; if isInitial { logCtx = "Consul KV Poller: Performing initial configuration fetch..." }
		logger.Debug(logCtx)

		ipList, uaList, l7RLCfg, l4ConnRLCfg, l4XDPLgcEnabled, xdpGlobEnabled, fetchErr :=
			FetchAllConfigsFromConsul(consulKVClient, logger)

		if fetchErr != nil {
			logger.Error("Error(s) during Consul KV fetch, current service config remains unchanged for this cycle.", "error", fetchErr, "is_initial_fetch", isInitial)
		} else {
			logger.Info("Successfully fetched all configurations from Consul KV", "is_initial_fetch", isInitial)
			// Update service state atomically or with appropriate locking
			s.UpdateIPBlocklist(ipList)
			s.UpdateUABlocklist(uaList)
			s.UpdateL7RateLimitConfig(l7RLCfg)
			s.UpdateL4ConnRateLimitConfig(l4ConnRLCfg)
			s.UpdateL4XDPBlocklistLogicEnabled(l4XDPLgcEnabled)
			s.UpdateXDPGlobalEnabled(xdpGlobEnabled) // This updates s.xdpGlobalEnabled
		}

		// XDP Sync decision based on the *just updated* s.xdpGlobalEnabled
		// and the ipList *that was successfully fetched (or empty if fetch failed)*
		if xdpSyncer != nil {
			currentXDPGlobalEnabled := s.IsXDPGlobalEnabled() // Read thread-safely
			currentIPBlocklistForXDP := s.GetIPBlocklistSnapshot() // Get current snapshot for XDP

			if currentXDPGlobalEnabled {
				logger.Debug("XDP global is enabled (via Consul KV) and XDP syncer (controller) is provided: Synchronizing IP blocklist to eBPF map.", "ip_list_count_for_sync", len(currentIPBlocklistForXDP))
				if err := xdpSyncer.SyncIPBlocklistToMap(currentIPBlocklistForXDP); err != nil {
					logger.Error("Failed to sync IP blocklist to eBPF map", "source", "poller", "error", err)
					EbpfMapSyncTotal.WithLabelValues("failure").Inc()
				} else {
					logger.Info("Successfully synced IP blocklist to eBPF map from poller.")
					EbpfMapSyncTotal.WithLabelValues("success").Inc()
				}
			} else {
				logger.Info("XDP global is disabled (via Consul KV) or no IPs to sync, clearing eBPF map (from poller).")
				// Sync an empty map to clear it
				if err := xdpSyncer.SyncIPBlocklistToMap(make(map[string]struct{})); err != nil {
					logger.Error("Failed to clear eBPF map when XDP globally disabled or IP list empty", "error", err)
					EbpfMapSyncTotal.WithLabelValues("clear_failure").Inc()
				} else {
					logger.Info("Successfully ensured eBPF map is cleared (or reflects empty list) as XDP is globally disabled or IP list empty.")
					EbpfMapSyncTotal.WithLabelValues("clear_success").Inc()
				}
			}
		} else {
			logger.Debug("XDP syncer (controller) is nil, skipping eBPF map sync from poller.")
			EbpfMapSyncTotal.WithLabelValues("skipped_nil_controller").Inc()
		}
	}

	updateConfigs(true) // Initial fetch

	logger.Info("Consul KV poller started", "interval", interval)
	for {
		select {
		case <-ctx.Done(): // Check application context first
			logger.Info("Consul KV poller stopping due to application context cancellation.")
			return
		case <-quitSignal: // Then check poller-specific quit signal
			logger.Info("Consul KV poller stopping due to quit signal.")
			return
		case <-ticker.C:
			updateConfigs(false)
		}
	}
}


// HTTPAuthzServer implements the L7 HTTP ext_authz handler logic.
type HTTPAuthzServer struct {
	pb.UnimplementedAuthorizationServer // For forward compatibility with gRPC Check
	logger                              *slog.Logger
	coreService                         *Service
}

// NewHTTPAuthzServer creates a new L7 HTTP authorization handler.
func NewHTTPAuthzServer(logger *slog.Logger, coreService *Service) *HTTPAuthzServer {
	return &HTTPAuthzServer{
		logger:      logger.With("handler", "http_l7_ext_authz"),
		coreService: coreService,
	}
}

// HandleAuthzRequest is the HTTP handler for Envoy L7 ext_authz.
func (h *HTTPAuthzServer) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	// Generate a unique request ID if not provided by Envoy (though Envoy usually adds x-request-id)
	reqIDArr, ok := r.Header["X-Request-Id"]
	reqID := ""
	if ok && len(reqIDArr) > 0 {
		reqID = reqIDArr[0]
	} else {
		// Fallback if X-Request-Id is missing
		b := make([]byte, 8)
		_, _ = rand.Read(b) // Best effort, ignore error for logging ID
		reqID = hex.EncodeToString(b)
	}

	logger := h.logger.With("request_id", reqID)
	clientIP := getClientIP(r)
	userAgent := r.UserAgent() // Standard Go way to get User-Agent
	requestPath := r.URL.Path
	logAttrs := []any{
		slog.String("method", r.Method),
		slog.String("path", requestPath),
		slog.String("client_ip", clientIP),
		slog.String("user_agent", userAgent),
	}
	logger.Debug("Received L7 HTTP authorization request", logAttrs...)

	if h.coreService.IsIPBlocked(clientIP) {
		logger.Warn("L7 Request denied: IP on blocklist", logAttrs...)
		httpRequestsTotal.WithLabelValues("denied", "ip_blocklist").Inc()
		w.Header().Set("X-Authz-Decision", "Deny-IPBlock") // Custom header for observability
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Access Denied: IP blocked.")
		return
	}

	if userAgent != "" && h.coreService.IsUABlocked(userAgent) {
		logger.Warn("L7 Request denied: User-Agent on blocklist", logAttrs...)
		httpRequestsTotal.WithLabelValues("denied", "ua_blocklist").Inc()
		w.Header().Set("X-Authz-Decision", "Deny-UABlock")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Access Denied: Client blocked.")
		return
	}

	// L7 HTTP Request Rate Limiting
	rlEnabled, rlLimit, rlWindow := h.coreService.GetL7RateLimitConfig()
	if rlEnabled && clientIP != "" {
		if h.coreService.redisClient == nil {
			logger.Error("L7 Rate limiting enabled but Redis client is nil! Allowing request.", logAttrs...)
		} else {
			allow, remaining, err := h.coreService.CheckAndIncrementL7RateLimit(clientIP)
			if err != nil {
				logger.Error("Error during L7 rate limit check, failing open (allowing request)", append(logAttrs, slog.String("error", err.Error()))...)
			} else if !allow {
				logger.Warn("L7 Request denied: Rate limit exceeded", append(logAttrs, slog.Int64("limit", rlLimit), slog.Duration("window", rlWindow))...)
				httpRequestsTotal.WithLabelValues("denied", "l7_rate_limit").Inc()
				w.Header().Set("X-Authz-Decision", "Deny-RateLimit")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rlWindow.Seconds()))) // Inform client
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintln(w, "Rate limit exceeded.")
				return
			}
			logger.Debug("L7 Rate limit check passed", append(logAttrs, slog.Int64("remaining_in_window", remaining))...)
		}
	}

	httpRequestsTotal.WithLabelValues("allowed", "none").Inc()
	logger.Info("L7 Request allowed", logAttrs...)
	w.Header().Set("X-Authz-Decision", "Allow")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}


// Check method for L7 gRPC ext_authz (implements pb.AuthorizationServer)
func (h *HTTPAuthzServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	var clientIP, userAgent, path, method string
	httpAttrs := req.GetAttributes().GetRequest().GetHttp()

	if httpAttrs != nil {
		path = httpAttrs.GetPath()
		method = httpAttrs.GetMethod()
		if xff, ok := httpAttrs.GetHeaders()["x-forwarded-for"]; ok {
			if ips := strings.Split(xff, ","); len(ips) > 0 {
				clientIP = strings.TrimSpace(ips[0])
			}
		}
		if ua, ok := httpAttrs.GetHeaders()["user-agent"]; ok {
			userAgent = ua
		}
	}
	// Fallback for client IP if not in XFF
	if clientIP == "" && req.GetAttributes().GetSource() != nil &&
		req.GetAttributes().GetSource().GetAddress() != nil &&
		req.GetAttributes().GetSource().GetAddress().GetSocketAddress() != nil {
		clientIP = req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress()
	}

	if clientIP == "" {
		h.logger.Warn("L7 gRPC Check: Could not extract client IP, denying request")
		httpRequestsTotal.WithLabelValues("denied","missing_source_ip_grpc").Inc()
		return &pb.CheckResponse{
			Status: status.New(codes.PermissionDenied, "Source IP missing for L7 gRPC Check").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{
				DeniedResponse: &pb.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   "Access Denied: Source IP missing.",
				},
			},
		}, nil
	}
	
	logger := h.logger.With("client_ip", clientIP, "path", path, "method", method, "handler", "grpc_l7_ext_authz")
	logger.Debug("Received L7 gRPC authorization request")

	if h.coreService.IsIPBlocked(clientIP) {
		logger.Warn("L7 gRPC Check: Denied - IP on blocklist")
		httpRequestsTotal.WithLabelValues("denied","ip_blocklist_grpc").Inc()
		return &pb.CheckResponse{
			Status: status.New(codes.PermissionDenied, "IP Blocked").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{
				DeniedResponse: &pb.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   "Access Denied: IP Blocked.",
				},
			},
		}, nil
	}

	if userAgent != "" && h.coreService.IsUABlocked(userAgent) {
		logger.Warn("L7 gRPC Check: Denied - User-Agent on blocklist", "user_agent", userAgent)
		httpRequestsTotal.WithLabelValues("denied","ua_blocklist_grpc").Inc()
		return &pb.CheckResponse{
			Status: status.New(codes.PermissionDenied, "User-Agent Blocked").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{
				DeniedResponse: &pb.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   "Access Denied: User-Agent Blocked.",
				},
			},
		}, nil
	}
	
	rlEnabled, rlLimit, rlWindow := h.coreService.GetL7RateLimitConfig()
	if rlEnabled {
		if h.coreService.redisClient == nil {
			logger.Error("L7 gRPC Check: Rate limiting enabled but Redis client is nil! Allowing request.")
		} else {
			allow, remaining, err := h.coreService.CheckAndIncrementL7RateLimit(clientIP)
			if err != nil {
				logger.Error("L7 gRPC Check: Error during L7 rate limit check, failing open (allowing request)", "error", err)
			} else if !allow {
				logger.Warn("L7 gRPC Check: Denied - Rate limit exceeded", "limit", rlLimit, "window_seconds", rlWindow.Seconds(), "remaining", remaining)
				httpRequestsTotal.WithLabelValues("denied","l7_rate_limit_grpc").Inc()
				return &pb.CheckResponse{
					Status: status.New(codes.ResourceExhausted, "Rate Limit Exceeded").Proto(),
					HttpResponse: &pb.CheckResponse_DeniedResponse{
						DeniedResponse: &pb.DeniedHttpResponse{
							Status: &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
							Body:   "Access Denied: Rate Limit Exceeded.",
						},
					},
				}, nil
			}
			logger.Debug("L7 gRPC Rate limit check passed", slog.Int64("remaining_in_window", remaining))
		}
	}


	logger.Info("L7 gRPC Check: Allowed")
	httpRequestsTotal.WithLabelValues("allowed","none_grpc").Inc()
	return &pb.CheckResponse{
		Status: status.New(codes.OK, "OK").Proto(),
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{
			},
		},
	}, nil
}


// Helper to get client IP from HTTP request, considering common proxy headers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first, as it's the most common standard
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if net.ParseIP(clientIP) != nil { // Validate it's an IP
				return clientIP
			}
		}
	}
	// Check X-Real-IP as a fallback
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil { // Validate
			return xri
		}
	}
	// Fallback to r.RemoteAddr if other headers are not present or invalid
	// r.RemoteAddr might be an IP:port string, so try to split
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if net.ParseIP(host) != nil { // Validate
			return host
		}
	}
	// If r.RemoteAddr was just an IP (no port, SplitHostPort fails)
	if net.ParseIP(r.RemoteAddr) != nil { // Validate
		return r.RemoteAddr
	}
	return "unknown" // Could not determine a valid client IP
}

// CheckAndIncrementL7RateLimit checks and increments the L7 HTTP request rate limit for a given ID (client IP).
// Returns true if allowed, false if denied. Also returns remaining allowance or 0.
func (s *Service) CheckAndIncrementL7RateLimit(id string) (bool /*allowed*/, int64 /*remaining*/, error) {
	s.configMutex.RLock()
	enabled := s.l7RateLimitEnabled
	limit := s.l7RateLimitCount
	window := s.l7RateLimitWindow
	s.configMutex.RUnlock()

	if !enabled {
		return true, 0, nil
	}
	if s.redisClient == nil {
		s.logger.Warn("Redis client is nil for L7 rate limiting, allowing request.", "id", id)
		return true, 0, nil // Fail open if Redis is misconfigured
	}

	ctx := context.Background() // Or use request context if available and appropriate
	key := fmt.Sprintf("ratelimit:l7_http:%s", id)
	var currentCount int64

	pipe := s.redisClient.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	// Set expiry only if it's the first increment in the window, or use TTL if supported by Redis version for INCR+EXPIRE
	// For simplicity here, always set EXPIRE. Redis handles it efficiently.
	expireCmd := pipe.Expire(ctx, key, window)

	_, execErr := pipe.Exec(ctx)
	if execErr != nil {
		s.logger.Error("Redis L7 RL pipeline execution error", "key", key, "error", execErr)
		redisErrorsTotal.Inc()
		return true, 0, execErr // Fail open on Redis error
	}

	currentCount = incrCmd.Val() // Get result after pipeline Exec
	_ = expireCmd.Val()          // Check error if needed, but usually not critical for EXPIRE

	s.logger.Debug("L7 HTTP Rate limit check performed", "id", id, "key", key, "current_count", currentCount, "limit", limit, "window", window)
	if currentCount > limit {
		s.logger.Warn("L7 HTTP Rate limit EXCEEDED", "id", id, "current_count", currentCount, "limit", limit)
		return false, 0, nil
	}
	return true, limit - currentCount, nil
}

// CheckAndIncrementL4ConnRateLimit checks and increments the L4 TCP connection rate limit.
func (s *Service) CheckAndIncrementL4ConnRateLimit(id string) (bool /*allowed*/, int64 /*remaining*/, error) {
	s.configMutex.RLock()
	enabled := s.l4ConnRateLimitEnabled
	limit := s.l4ConnRateLimitCount
	window := s.l4ConnRateLimitWindow
	s.configMutex.RUnlock()

	if !enabled {
		return true, 0, nil
	}
	if s.redisClient == nil {
		s.logger.Warn("Redis client is nil for L4 Connection rate limiting, allowing connection.", "id", id)
		return true, 0, nil
	}

	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:l4_conn:%s", id)
	var currentCount int64

	pipe := s.redisClient.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	expireCmd := pipe.Expire(ctx, key, window)

	_, execErr := pipe.Exec(ctx)
	if execErr != nil {
		s.logger.Error("Redis L4 Connection RL pipeline execution error", "key", key, "error", execErr)
		redisErrorsTotal.Inc()
		return true, 0, execErr // Fail open
	}
	currentCount = incrCmd.Val()
	_ = expireCmd.Val()

	s.logger.Debug("L4 Connection Rate limit check performed", "id", id, "key", key, "current_count", currentCount, "limit", limit, "window", window)
	if currentCount > limit {
		s.logger.Warn("L4 Connection Rate limit EXCEEDED", "id", id, "current_count", currentCount, "limit", limit)
		l4ConnectionsRateLimitedTotal.Inc() // Specific metric for L4 RL denials
		return false, 0, nil
	}
	return true, limit - currentCount, nil
}
