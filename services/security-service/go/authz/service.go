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
	"github.com/redis/go-redis/v9"
)

const (
	ipBlocklistKVKey           = "config/security/ip_blocklist"
	uaBlocklistKVKey           = "config/security/ua_blocklist"
	rateLimitEnabledKey        = "config/security/ratelimit/enabled"
	rateLimitLimitPerWindowKey = "config/security/ratelimit/limit_per_window"
	rateLimitWindowSecondsKey  = "config/security/ratelimit/window_seconds"
)

const (
	defaultRateLimitEnabled       = false
	defaultRateLimitCount         = 60
	defaultRateLimitWindowSeconds = 60
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
	logger             *slog.Logger
	consulKV           consulKV
	redisClient        redisClientInterface
	ipBlocklist        map[string]struct{}
	userAgentBlocklist map[string]struct{}
	configMutex        sync.RWMutex
	rateLimitEnabled   bool
	rateLimitCount     int64
	rateLimitWindow    time.Duration
}

func NewService(logger *slog.Logger, kv consulKV, rdb redisClientInterface) *Service {
	return &Service{
		logger:             logger.With("component", "authz_service"),
		consulKV:           kv,
		redisClient:        rdb,
		ipBlocklist:        make(map[string]struct{}),
		userAgentBlocklist: make(map[string]struct{}),
		rateLimitEnabled:   defaultRateLimitEnabled,
		rateLimitCount:     defaultRateLimitCount,
		rateLimitWindow:    defaultRateLimitWindowSeconds * time.Second,
	}
}

func (s *Service) FetchAndUpdateRateLimitConfig() error {
	var fetchedEnabled bool = defaultRateLimitEnabled
	var fetchedCount int64 = defaultRateLimitCount
	var fetchedWindowSecs int64 = defaultRateLimitWindowSeconds
	var finalErr error

	s.logger.Debug("Fetching rate limit config from Consul KV...")

	kvPairEnabled, _, err := s.consulKV.Get(rateLimitEnabledKey, nil)
	if err != nil {
		s.logger.Error("Failed to get rate limit enabled flag from Consul", "key", rateLimitEnabledKey, "error", err)
		finalErr = fmt.Errorf("failed to fetch enabled flag: %w", err)
	} else if kvPairEnabled == nil || len(kvPairEnabled.Value) == 0 {
		s.logger.Info("Rate limit enabled key not found or empty, using default.", "key", rateLimitEnabledKey, "default", defaultRateLimitEnabled)
	} else {
		parsedBool, err := strconv.ParseBool(string(kvPairEnabled.Value))
		if err != nil {
			s.logger.Error("Failed to parse rate limit enabled flag from Consul, using default.", "key", rateLimitEnabledKey, "value", string(kvPairEnabled.Value), "default", defaultRateLimitEnabled, "error", err)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse enabled flag: %w", err) }
		} else {
			fetchedEnabled = parsedBool
		}
	}

	kvPairLimit, _, err := s.consulKV.Get(rateLimitLimitPerWindowKey, nil)
	if err != nil {
		s.logger.Error("Failed to get rate limit count from Consul", "key", rateLimitLimitPerWindowKey, "error", err)
		if finalErr == nil { finalErr = fmt.Errorf("failed to fetch limit count: %w", err) }
	} else if kvPairLimit == nil || len(kvPairLimit.Value) == 0 {
		s.logger.Info("Rate limit count key not found or empty, using default.", "key", rateLimitLimitPerWindowKey, "default", defaultRateLimitCount)
	} else {
		parsedInt, err := strconv.ParseInt(string(kvPairLimit.Value), 10, 64)
		if err != nil || parsedInt <= 0 {
			errMsg := "Failed to parse rate limit count from Consul or value <= 0, using default."
			if err == nil { err = fmt.Errorf("parsed limit %d is not positive", parsedInt) }
			s.logger.Error(errMsg, "key", rateLimitLimitPerWindowKey, "value", string(kvPairLimit.Value), "default", defaultRateLimitCount, "error", err)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse limit count: %w", err) }
		} else {
			fetchedCount = parsedInt
		}
	}

	kvPairWindow, _, err := s.consulKV.Get(rateLimitWindowSecondsKey, nil)
	if err != nil {
		s.logger.Error("Failed to get rate limit window from Consul", "key", rateLimitWindowSecondsKey, "error", err)
		if finalErr == nil { finalErr = fmt.Errorf("failed to fetch window seconds: %w", err) }
	} else if kvPairWindow == nil || len(kvPairWindow.Value) == 0 {
		s.logger.Info("Rate limit window key not found or empty, using default.", "key", rateLimitWindowSecondsKey, "default", defaultRateLimitWindowSeconds)
	} else {
		parsedInt, err := strconv.ParseInt(string(kvPairWindow.Value), 10, 64)
		if err != nil || parsedInt <= 0 {
			errMsg := "Failed to parse rate limit window from Consul or value <= 0, using default."
			if err == nil { err = fmt.Errorf("parsed window %d is not positive", parsedInt) }
			s.logger.Error(errMsg, "key", rateLimitWindowSecondsKey, "value", string(kvPairWindow.Value), "default", defaultRateLimitWindowSeconds, "error", err)
			if finalErr == nil { finalErr = fmt.Errorf("failed to parse window seconds: %w", err) }
		} else {
			fetchedWindowSecs = parsedInt
		}
	}

	s.configMutex.Lock()
	s.rateLimitEnabled = fetchedEnabled
	s.rateLimitCount = fetchedCount
	s.rateLimitWindow = time.Duration(fetchedWindowSecs) * time.Second
	s.configMutex.Unlock()

	s.logger.Info("Updated rate limit configuration",
		"source", "Consul KV",
		"enabled", fetchedEnabled,
		"limit", fetchedCount,
		"window", s.rateLimitWindow,
	)

	return finalErr
}

func (s *Service) FetchAndUpdateIPBlocklist() error {
	kvPair, _, err := s.consulKV.Get(ipBlocklistKVKey, nil)
	if err != nil { return fmt.Errorf("failed to get ip_blocklist from consul: %w", err) }
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
		if trimmedIP != "" { newBlocklist[trimmedIP] = struct{}{}; ipCount++ }
	}
	s.configMutex.Lock()
	s.ipBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Debug("Updated IP blocklist", "source", "Consul KV", "parsed_ips", ipCount)
	return nil
}

func (s *Service) FetchAndUpdateUABlocklist() error {
	kvPair, _, err := s.consulKV.Get(uaBlocklistKVKey, nil)
	if err != nil { return fmt.Errorf("failed to get ua_blocklist from consul: %w", err) }
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
		if trimmedUA != "" { newBlocklist[trimmedUA] = struct{}{}; uaCount++ }
	}
	s.configMutex.Lock()
	s.userAgentBlocklist = newBlocklist
	s.configMutex.Unlock()
	s.logger.Debug("Updated User-Agent blocklist", "source", "Consul KV", "parsed_uas", uaCount)
	return nil
}

func (s *Service) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	xff := r.Header.Get("X-Forwarded-For")
	clientIP := ""
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 { clientIP = strings.TrimSpace(ips[0]) }
	}
	userAgent := r.Header.Get("User-Agent")

	logAttrs := []any{
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("client_ip", clientIP),
		slog.String("user_agent", userAgent),
	}

	s.logger.Debug("Received authz request", logAttrs...)

	// Read lock needed for blocklists AND rate limit config
	s.configMutex.RLock()
	// Read rate limit config needed later *before* releasing lock if possible
	isEnabled := s.rateLimitEnabled
	limit := s.rateLimitCount
	window := s.rateLimitWindow

	// 1. Check IP Blocklist
	if clientIP != "" {
		if _, blocked := s.ipBlocklist[clientIP]; blocked {
			s.configMutex.RUnlock() // Release lock before writing response
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
			s.configMutex.RUnlock() // Release lock before writing response
			s.logger.Warn("Request denied", append(logAttrs, slog.String("reason", "ua_blocklist"))...)
			w.Header().Set("X-Authz-Decision", "Deny-UABlock")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Access Denied: Client blocked.")
			return
		}
	}

	// Config values (isEnabled, limit, window) already read under RLock

	if isEnabled && clientIP != "" {
		s.configMutex.RUnlock() // Release RLock before potentially slow Redis call

		redisKey := "ratelimit:" + clientIP
		var currentCount int64 = 0 // Initialize count

		// Use pipeline for INCR + EXPIRE
		pipe := s.redisClient.Pipeline()
		incrCmd := pipe.Incr(ctx, redisKey)
		pipe.Expire(ctx, redisKey, window) // Set expiry every time for simplicity
		_, execErr := pipe.Exec(ctx)

		if execErr != nil {
			// Log Redis error but allow the request (fail open for rate limiting part)
			s.logger.Error("Redis pipeline failed for rate limit check", append(logAttrs, slog.String("key", redisKey), slog.String("error", execErr.Error()))...)
			// Do not return; proceed to allow
		} else {
			// Pipeline executed, now get the result of INCR
			countResult, incrErr := incrCmd.Result()
			if incrErr != nil {
				// Log error getting INCR result but allow request
				s.logger.Error("Redis INCR command failed within pipeline", append(logAttrs, slog.String("key", redisKey), slog.String("error", incrErr.Error()))...)
				// Do not return; proceed to allow
			} else {
				// Successfully got the count after incrementing
				currentCount = countResult
				logAttrs = append(logAttrs, slog.Int64("rl_count", currentCount), slog.Int64("rl_limit", limit)) // Add context for logging

				if currentCount > limit {
					// Rate limit exceeded
					s.logger.Warn("Request denied", append(logAttrs, slog.String("reason", "rate_limit"))...)
					w.Header().Set("X-Authz-Decision", "Deny-RateLimit")
					w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds()))) // Optional: Inform client
					w.WriteHeader(http.StatusTooManyRequests)                             // 429
					fmt.Fprintln(w, "Rate limit exceeded.")
					return // DENY the request
				}
				// Rate limit check passed
				s.logger.Debug("Rate limit check passed", logAttrs...)
			}
		}
	} else {
		// Rate limiting disabled or no client IP, release lock if not already done
		s.configMutex.RUnlock()
	}

	// Allow if no checks failed and rate limit (if enabled) passed or failed open
	s.logger.Info("Request allowed", logAttrs...)
	w.Header().Set("X-Authz-Decision", "Allow")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
