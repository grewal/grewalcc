package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

const (
	ipBlocklistKVKey                  = "config/security/ip_blocklist"
	uaBlocklistKVKey                  = "config/security/ua_blocklist"
	rateLimitEnabledKey               = "config/security/ratelimit/enabled"
	rateLimitLimitPerWindowKey        = "config/security/ratelimit/limit_per_window"
	rateLimitWindowSecondsKey         = "config/security/ratelimit/window_seconds"
	l4ConnRateLimitEnabledKey         = "config/security/l4_conn_ratelimit/enabled"
	l4ConnRateLimitLimitPerWindowKey  = "config/security/l4_conn_ratelimit/limit_per_window"
	l4ConnRateLimitWindowSecondsKey   = "config/security/l4_conn_ratelimit/window_seconds"
)

const (
	defaultRateLimitEnabled             = false
	defaultRateLimitCount               = 60
	defaultRateLimitWindowSeconds       = 60
	defaultL4ConnRateLimitEnabled       = false
	defaultL4ConnRateLimitCount         = 20 
	defaultL4ConnRateLimitWindowSeconds = 10 
)

var (
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authz",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of authorization requests processed.",
		},
		[]string{"decision", "path"},
	)
	redisErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "authz",
			Subsystem: "dependencies",
			Name:      "redis_errors_total",
			Help:      "Total number of errors encountered while interacting with Redis.",
		},
	)
	consulKVErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "authz",
			Subsystem: "dependencies",
			Name:      "consul_kv_errors_total",
			Help:      "Total number of errors encountered while fetching from Consul KV.",
		},
	)
	configReloadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "authz",
			Subsystem: "config",
			Name:      "reloads_total",
			Help:      "Total number of successful configuration reloads from Consul KV.",
		},
		[]string{"type"},
	)
)

type consulKV interface {
	Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
}

type redisClientInterface interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
	Pipeline() redis.Pipeliner
}

type Service struct {
	logger                     *slog.Logger
	consulKV                   consulKV
	redisClient                redisClientInterface
	ipBlocklist                map[string]struct{}
	userAgentBlocklist         map[string]struct{}
	configMutex                sync.RWMutex
	rateLimitEnabled           bool
	rateLimitCount             int64
	rateLimitWindow            time.Duration
	l4ConnRateLimitEnabled     bool
	l4ConnRateLimitCount       int64
	l4ConnRateLimitWindow      time.Duration
}

func NewService(logger *slog.Logger, kv consulKV, rdb redisClientInterface) *Service {
	return &Service{
		logger:                          logger.With("component", "authz_service"),
		consulKV:                        kv,
		redisClient:                     rdb,
		ipBlocklist:                     make(map[string]struct{}),
		userAgentBlocklist:              make(map[string]struct{}),
		rateLimitEnabled:                defaultRateLimitEnabled,
		rateLimitCount:                  defaultRateLimitCount,
		rateLimitWindow:                 defaultRateLimitWindowSeconds * time.Second,
		l4ConnRateLimitEnabled:          defaultL4ConnRateLimitEnabled,
		l4ConnRateLimitCount:            defaultL4ConnRateLimitCount,
		l4ConnRateLimitWindow:           defaultL4ConnRateLimitWindowSeconds * time.Second,
	}
}

func (s *Service) FetchAndUpdateRateLimitConfig() error {
	var fetchedEnabled bool = defaultRateLimitEnabled
	var fetchedCount int64 = defaultRateLimitCount
	var fetchedWindowSecs int64 = defaultRateLimitWindowSeconds
	var finalErr error
	s.logger.Debug("Fetching L7 HTTP rate limit config from Consul KV...")

	kvPairEnabled, _, err := s.consulKV.Get(rateLimitEnabledKey, nil)
	if err != nil {
		s.logger.Error("Failed to get L7 rate limit enabled flag from Consul", "key", rateLimitEnabledKey, "error", err)
		finalErr = fmt.Errorf("failed to fetch L7 enabled flag: %w", err)
	} else if kvPairEnabled == nil || len(kvPairEnabled.Value) == 0 {
		s.logger.Info("L7 rate limit enabled key not found or empty, using default.", "key", rateLimitEnabledKey, "default", defaultRateLimitEnabled)
	} else {
		parsedBool, errConv := strconv.ParseBool(string(kvPairEnabled.Value))
		if errConv != nil {
			s.logger.Error("Failed to parse L7 rate limit enabled flag, using default.", "key", rateLimitEnabledKey, "value", string(kvPairEnabled.Value), "default", defaultRateLimitEnabled, "error", errConv)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse L7 enabled flag: %w", errConv) }
		} else { fetchedEnabled = parsedBool }
	}

	kvPairLimit, _, err := s.consulKV.Get(rateLimitLimitPerWindowKey, nil)
	if err != nil {
		s.logger.Error("Failed to get L7 rate limit count from Consul", "key", rateLimitLimitPerWindowKey, "error", err)
		if finalErr == nil { finalErr = fmt.Errorf("failed to fetch L7 limit count: %w", err) }
	} else if kvPairLimit == nil || len(kvPairLimit.Value) == 0 {
		s.logger.Info("L7 rate limit count key not found or empty, using default.", "key", rateLimitLimitPerWindowKey, "default", defaultRateLimitCount)
	} else {
		parsedInt, errConv := strconv.ParseInt(string(kvPairLimit.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			errMsg := "Failed to parse L7 rate limit count or value <= 0, using default."
			if errConv == nil { errConv = fmt.Errorf("parsed L7 limit %d is not positive", parsedInt) }
			s.logger.Error(errMsg, "key", rateLimitLimitPerWindowKey, "value", string(kvPairLimit.Value), "default", defaultRateLimitCount, "error", errConv)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse L7 limit count: %w", errConv) }
		} else { fetchedCount = parsedInt }
	}

	kvPairWindow, _, err := s.consulKV.Get(rateLimitWindowSecondsKey, nil)
	if err != nil {
		s.logger.Error("Failed to get L7 rate limit window from Consul", "key", rateLimitWindowSecondsKey, "error", err)
		if finalErr == nil { finalErr = fmt.Errorf("failed to fetch L7 window seconds: %w", err) }
	} else if kvPairWindow == nil || len(kvPairWindow.Value) == 0 {
		s.logger.Info("L7 rate limit window key not found or empty, using default.", "key", rateLimitWindowSecondsKey, "default", defaultRateLimitWindowSeconds)
	} else {
		parsedInt, errConv := strconv.ParseInt(string(kvPairWindow.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			errMsg := "Failed to parse L7 rate limit window or value <= 0, using default."
			if errConv == nil { errConv = fmt.Errorf("parsed L7 window %d is not positive", parsedInt) }
			s.logger.Error(errMsg, "key", rateLimitWindowSecondsKey, "value", string(kvPairWindow.Value), "default", defaultRateLimitWindowSeconds, "error", errConv)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse L7 window seconds: %w", errConv) }
		} else { fetchedWindowSecs = parsedInt }
	}

	s.configMutex.Lock()
	s.rateLimitEnabled = fetchedEnabled
	s.rateLimitCount = fetchedCount
	s.rateLimitWindow = time.Duration(fetchedWindowSecs) * time.Second
	s.configMutex.Unlock()

	if finalErr != nil { consulKVErrorsTotal.Inc()
	} else { configReloadsTotal.WithLabelValues("l7_http_rate_limit_config").Inc() }
	s.logger.Info("Updated L7 HTTP rate limit configuration", "source", "Consul KV", "enabled", fetchedEnabled, "limit", fetchedCount, "window", s.rateLimitWindow)
	return finalErr
}

func (s *Service) FetchAndUpdateL4ConnRateLimitConfig() error {
	var fetchedEnabled bool = defaultL4ConnRateLimitEnabled
	var fetchedCount int64 = defaultL4ConnRateLimitCount
	var fetchedWindowSecs int64 = defaultL4ConnRateLimitWindowSeconds
	var finalErr error
	s.logger.Debug("Fetching L4 connection rate limit config from Consul KV...")

	kvPairEnabled, _, err := s.consulKV.Get(l4ConnRateLimitEnabledKey, nil)
	if err != nil {
		s.logger.Error("Failed to get L4 conn rate limit enabled flag from Consul", "key", l4ConnRateLimitEnabledKey, "error", err)
		finalErr = fmt.Errorf("failed to fetch L4 enabled flag: %w", err)
	} else if kvPairEnabled == nil || len(kvPairEnabled.Value) == 0 {
		s.logger.Info("L4 conn rate limit enabled key not found or empty, using default.", "key", l4ConnRateLimitEnabledKey, "default", defaultL4ConnRateLimitEnabled)
	} else {
		parsedBool, errConv := strconv.ParseBool(string(kvPairEnabled.Value))
		if errConv != nil {
			s.logger.Error("Failed to parse L4 conn rate limit enabled flag, using default.", "key", l4ConnRateLimitEnabledKey, "value", string(kvPairEnabled.Value), "default", defaultL4ConnRateLimitEnabled, "error", errConv)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse L4 enabled flag: %w", errConv) }
		} else { fetchedEnabled = parsedBool }
	}

	kvPairLimit, _, err := s.consulKV.Get(l4ConnRateLimitLimitPerWindowKey, nil)
	if err != nil {
		s.logger.Error("Failed to get L4 conn rate limit count from Consul", "key", l4ConnRateLimitLimitPerWindowKey, "error", err)
		if finalErr == nil { finalErr = fmt.Errorf("failed to fetch L4 limit count: %w", err) }
	} else if kvPairLimit == nil || len(kvPairLimit.Value) == 0 {
		s.logger.Info("L4 conn rate limit count key not found or empty, using default.", "key", l4ConnRateLimitLimitPerWindowKey, "default", defaultL4ConnRateLimitCount)
	} else {
		parsedInt, errConv := strconv.ParseInt(string(kvPairLimit.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			errMsg := "Failed to parse L4 conn rate limit count or value <= 0, using default."
			if errConv == nil { errConv = fmt.Errorf("parsed L4 limit %d is not positive", parsedInt) }
			s.logger.Error(errMsg, "key", l4ConnRateLimitLimitPerWindowKey, "value", string(kvPairLimit.Value), "default", defaultL4ConnRateLimitCount, "error", errConv)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse L4 limit count: %w", errConv) }
		} else { fetchedCount = parsedInt }
	}

	kvPairWindow, _, err := s.consulKV.Get(l4ConnRateLimitWindowSecondsKey, nil)
	if err != nil {
		s.logger.Error("Failed to get L4 conn rate limit window from Consul", "key", l4ConnRateLimitWindowSecondsKey, "error", err)
		if finalErr == nil { finalErr = fmt.Errorf("failed to fetch L4 window seconds: %w", err) }
	} else if kvPairWindow == nil || len(kvPairWindow.Value) == 0 {
		s.logger.Info("L4 conn rate limit window key not found or empty, using default.", "key", l4ConnRateLimitWindowSecondsKey, "default", defaultL4ConnRateLimitWindowSeconds)
	} else {
		parsedInt, errConv := strconv.ParseInt(string(kvPairWindow.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			errMsg := "Failed to parse L4 conn rate limit window or value <= 0, using default."
			if errConv == nil { errConv = fmt.Errorf("parsed L4 window %d is not positive", parsedInt) }
			s.logger.Error(errMsg, "key", l4ConnRateLimitWindowSecondsKey, "value", string(kvPairWindow.Value), "default", defaultL4ConnRateLimitWindowSeconds, "error", errConv)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse L4 window seconds: %w", errConv) }
		} else { fetchedWindowSecs = parsedInt }
	}

	s.configMutex.Lock()
	s.l4ConnRateLimitEnabled = fetchedEnabled
	s.l4ConnRateLimitCount = fetchedCount
	s.l4ConnRateLimitWindow = time.Duration(fetchedWindowSecs) * time.Second
	s.configMutex.Unlock()

	if finalErr != nil { consulKVErrorsTotal.Inc()
	} else { configReloadsTotal.WithLabelValues("l4_conn_rate_limit_config").Inc() }
	s.logger.Info("Updated L4 connection rate limit configuration", "source", "Consul KV", "enabled", fetchedEnabled, "limit", fetchedCount, "window", s.l4ConnRateLimitWindow)
	return finalErr
}

func (s *Service) FetchAndUpdateIPBlocklist() error {
	kvPair, _, err := s.consulKV.Get(ipBlocklistKVKey, nil)
	if err != nil {
		consulKVErrorsTotal.Inc()
		return fmt.Errorf("failed to get ip_blocklist from consul: %w", err)
	}
	if kvPair == nil || len(kvPair.Value) == 0 {
		s.logger.Info("IP blocklist key not found or empty in Consul KV.", "key", ipBlocklistKVKey)
		s.configMutex.Lock(); s.ipBlocklist = make(map[string]struct{}); s.configMutex.Unlock()
		configReloadsTotal.WithLabelValues("ip_blocklist").Inc()
		return nil
	}
	ips := strings.Split(string(kvPair.Value), ","); newBlocklist := make(map[string]struct{}, len(ips)); ipCount := 0
	for _, ip := range ips {
		trimmedIP := strings.TrimSpace(ip)
		if trimmedIP != "" { newBlocklist[trimmedIP] = struct{}{}; ipCount++ }
	}
	s.configMutex.Lock(); s.ipBlocklist = newBlocklist; s.configMutex.Unlock()
	s.logger.Debug("Updated IP blocklist", "source", "Consul KV", "parsed_ips", ipCount)
	configReloadsTotal.WithLabelValues("ip_blocklist").Inc()
	return nil
}

func (s *Service) FetchAndUpdateUABlocklist() error {
	kvPair, _, err := s.consulKV.Get(uaBlocklistKVKey, nil)
	if err != nil {
		consulKVErrorsTotal.Inc()
		return fmt.Errorf("failed to get ua_blocklist from consul: %w", err)
	}
	if kvPair == nil || len(kvPair.Value) == 0 {
		s.logger.Info("User-Agent blocklist key not found or empty in Consul KV.", "key", uaBlocklistKVKey)
		s.configMutex.Lock(); s.userAgentBlocklist = make(map[string]struct{}); s.configMutex.Unlock()
		configReloadsTotal.WithLabelValues("ua_blocklist").Inc()
		return nil
	}
	userAgents := strings.Split(string(kvPair.Value), "\n"); newBlocklist := make(map[string]struct{}, len(userAgents)); uaCount := 0
	for _, ua := range userAgents {
		trimmedUA := strings.TrimSpace(ua)
		if trimmedUA != "" { newBlocklist[trimmedUA] = struct{}{}; uaCount++ }
	}
	s.configMutex.Lock(); s.userAgentBlocklist = newBlocklist; s.configMutex.Unlock()
	s.logger.Debug("Updated User-Agent blocklist", "source", "Consul KV", "parsed_uas", uaCount)
	configReloadsTotal.WithLabelValues("ua_blocklist").Inc()
	return nil
}

func (s *Service) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context(); xff := r.Header.Get("X-Forwarded-For"); clientIP := ""
	if xff != "" { if ips := strings.Split(xff, ","); len(ips) > 0 { clientIP = strings.TrimSpace(ips[0]) } }
	userAgent := r.Header.Get("User-Agent"); requestPath := r.URL.Path
	logAttrs := []any{ slog.String("method", r.Method), slog.String("path", requestPath), slog.String("client_ip", clientIP), slog.String("user_agent", userAgent) }
	s.logger.Debug("Received L7 authz request", logAttrs...)

	s.configMutex.RLock()
	isEnabled := s.rateLimitEnabled; limit := s.rateLimitCount; window := s.rateLimitWindow
	if clientIP != "" { if _, blocked := s.ipBlocklist[clientIP]; blocked {
		s.configMutex.RUnlock(); requestsTotal.WithLabelValues("denied_ip_block", requestPath).Inc()
		s.logger.Warn("L7 Request denied", append(logAttrs, slog.String("reason", "ip_blocklist"))...)
		w.Header().Set("X-Authz-Decision", "Deny-IPBlock"); w.WriteHeader(http.StatusForbidden); fmt.Fprintln(w, "Access Denied: IP blocked.")
		return
	}}
	if userAgent != "" { if _, blocked := s.userAgentBlocklist[userAgent]; blocked {
		s.configMutex.RUnlock(); requestsTotal.WithLabelValues("denied_ua_block", requestPath).Inc()
		s.logger.Warn("L7 Request denied", append(logAttrs, slog.String("reason", "ua_blocklist"))...)
		w.Header().Set("X-Authz-Decision", "Deny-UABlock"); w.WriteHeader(http.StatusForbidden); fmt.Fprintln(w, "Access Denied: Client blocked.")
		return
	}}
	s.configMutex.RUnlock()

	if isEnabled && clientIP != "" {
		if s.redisClient == nil { s.logger.Error("L7 Rate limiting enabled but Redis client is nil!", logAttrs...)
		} else {
			redisKey := "l7_http_rl:" + clientIP; var currentCount int64 = 0
			pipe := s.redisClient.Pipeline(); incrCmd := pipe.Incr(ctx, redisKey); pipe.Expire(ctx, redisKey, window)
			_, execErr := pipe.Exec(ctx)
			if execErr != nil {
				redisErrorsTotal.Inc(); s.logger.Error("L7 Redis pipeline failed for rate limit check", append(logAttrs, slog.String("key", redisKey), slog.String("error", execErr.Error()))...)
			} else {
				countResult, incrErr := incrCmd.Result()
				if incrErr != nil {
					redisErrorsTotal.Inc(); s.logger.Error("L7 Redis INCR failed in pipeline", append(logAttrs, slog.String("key", redisKey), slog.String("error", incrErr.Error()))...)
				} else {
					currentCount = countResult
					logAttrsForRL := append(logAttrs, slog.Int64("rl_count", currentCount), slog.Int64("rl_limit", limit))
					if currentCount > limit {
						requestsTotal.WithLabelValues("denied_rate_limit", requestPath).Inc()
						s.logger.Warn("L7 Request denied", append(logAttrsForRL, slog.String("reason", "rate_limit"))...)
						w.Header().Set("X-Authz-Decision", "Deny-RateLimit"); w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds()))); w.WriteHeader(http.StatusTooManyRequests); fmt.Fprintln(w, "Rate limit exceeded.")
						return
					}
					s.logger.Debug("L7 Rate limit check passed", logAttrsForRL...)
				}
			}
		}
	}
	requestsTotal.WithLabelValues("allowed", requestPath).Inc()
	s.logger.Info("L7 Request allowed", logAttrs...)
	w.Header().Set("X-Authz-Decision", "Allow"); w.WriteHeader(http.StatusOK); fmt.Fprintln(w, "OK")
}
