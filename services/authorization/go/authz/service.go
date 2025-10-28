// FILE: services/authorization/go/authz/service.go
package authz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "grewal.cc/services/authorization/go/pkg/genproto/envoy/service/auth/v3"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// XDPMapSyncer defines the interface required by the poller to sync the eBPF map.
type XDPMapSyncer interface {
	SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error
	IsInitialized() bool
}

const (
	ipBlocklistKVKey                 = "config/security/ip_blocklist"
	uaBlocklistKVKey                 = "config/security/ua_blocklist"
	l7RateLimitEnabledKey            = "config/security/ratelimit/enabled"
	l7RateLimitLimitPerWindowKey     = "config/security/ratelimit/limit_per_window"
	l7RateLimitWindowSecondsKey      = "config/security/ratelimit/window_seconds"
	l4ConnRateLimitEnabledKey        = "config/security/l4_conn_ratelimit/enabled"
	l4ConnRateLimitLimitPerWindowKey = "config/security/l4_conn_ratelimit/limit_per_window"
	l4ConnRateLimitWindowSecondsKey  = "config/security/l4_conn_ratelimit/window_seconds"
	l4XDPBlocklistLogicEnabledKey    = "config/security/l4_xdp_blocklist_logic/enabled"
	xdpGlobalEnabledKey              = "config/security/xdp/enabled"
)

const (
	defaultL7RateLimitEnabled           = false
	defaultL7RateLimitCount             = 100
	defaultL7RateLimitWindowSeconds     = 60
	defaultL4ConnRateLimitEnabled       = false
	defaultL4ConnRateLimitCount         = 50
	defaultL4ConnRateLimitWindowSeconds   = 10
	defaultL4XDPBlocklistLogicEnabled   = true
	defaultXDPGlobalEnabled             = true
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
		[]string{"status"},
	)
)

type consulKVGetter interface {
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
	l4XDPBlocklistLogicEnabled bool
	xdpGlobalEnabled           bool
}

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

func (s *Service) GetIPBlocklistSnapshot() map[string]struct{} {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	snapshot := make(map[string]struct{}, len(s.ipBlocklist))
	for ip, val := range s.ipBlocklist {
		snapshot[ip] = val
	}
	return snapshot
}

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

func (s *Service) IsL4XDPBlocklistLogicEnabled() bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	return s.l4XDPBlocklistLogicEnabled
}

func (s *Service) IsXDPGlobalEnabled() bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	return s.xdpGlobalEnabled
}

type RateLimitConfig struct {
	Enabled bool
	Limit   int64
	Window  time.Duration
}

func fetchListFromKV(kv consulKVGetter, key string, logger *slog.Logger, configTypeLabel string, delimiter string) (map[string]struct{}, error) {
	list := make(map[string]struct{})
	kvPair, _, err := kv.Get(key, nil)
	if err != nil {
		consulKVErrorsTotal.Inc()
		return list, fmt.Errorf("fetching %s from %s: %w", configTypeLabel, key, err)
	}

	if kvPair == nil || len(kvPair.Value) == 0 {
		return list, nil
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
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	}
	return list, nil
}

func fetchRateLimitConfigFromKV(kv consulKVGetter, enabledKey, limitKey, windowKey string, defaults RateLimitConfig, logger *slog.Logger, configTypeLabel string) (RateLimitConfig, error) {
	config := defaults
	var combinedErr error
	var errs []string

	logAndCombineError := func(newErr error, fieldName string) {
		if newErr != nil {
			errs = append(errs, fmt.Sprintf("%s_for_%s: %s", fieldName, configTypeLabel, newErr.Error()))
			if combinedErr == nil {
				combinedErr = newErr
			}
		}
	}

	kvPairEnabled, _, err := kv.Get(enabledKey, nil)
	if err != nil {
		logAndCombineError(err, "enabled_flag_fetch")
	} else if kvPairEnabled != nil && len(kvPairEnabled.Value) > 0 {
		parsedBool, errConv := strconv.ParseBool(string(kvPairEnabled.Value))
		if errConv != nil {
			logAndCombineError(errConv, "enabled_flag_parse")
		} else {
			config.Enabled = parsedBool
		}
	}

	kvPairLimit, _, err := kv.Get(limitKey, nil)
	if err != nil {
		logAndCombineError(err, "limit_fetch")
	} else if kvPairLimit != nil && len(kvPairLimit.Value) > 0 {
		parsedInt, errConv := strconv.ParseInt(string(kvPairLimit.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			finalErrConv := errConv
			if errConv == nil {
				finalErrConv = fmt.Errorf("parsed limit %d is not positive", parsedInt)
			}
			logAndCombineError(finalErrConv, "limit_parse")
		} else {
			config.Limit = parsedInt
		}
	}

	kvPairWindow, _, err := kv.Get(windowKey, nil)
	if err != nil {
		logAndCombineError(err, "window_fetch")
	} else if kvPairWindow != nil && len(kvPairWindow.Value) > 0 {
		parsedInt, errConv := strconv.ParseInt(string(kvPairWindow.Value), 10, 64)
		if errConv != nil || parsedInt <= 0 {
			finalErrConv := errConv
			if errConv == nil {
				finalErrConv = fmt.Errorf("parsed window %d is not positive", parsedInt)
			}
			logAndCombineError(finalErrConv, "window_parse")
		} else {
			config.Window = time.Duration(parsedInt) * time.Second
		}
	}

	if combinedErr != nil {
		consulKVErrorsTotal.Inc()
		if len(errs) > 1 {
			combinedErr = fmt.Errorf("multiple errors occurred while fetching %s config from Consul: %s", configTypeLabel, strings.Join(errs, "; "))
		}
	} else if (kvPairEnabled != nil && len(kvPairEnabled.Value) > 0) ||
		(kvPairLimit != nil && len(kvPairLimit.Value) > 0) ||
		(kvPairWindow != nil && len(kvPairWindow.Value) > 0) {
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	}

	return config, combinedErr
}

func fetchBoolFromKV(kv consulKVGetter, key string, defaultValue bool, logger *slog.Logger, configTypeLabel string) (bool, error) {
	val := defaultValue
	var finalErr error
	kvPair, _, err := kv.Get(key, nil)
	if err != nil {
		consulKVErrorsTotal.Inc()
		finalErr = fmt.Errorf("fetching %s for key %s: %w", configTypeLabel, key, err)
	} else if kvPair != nil && len(kvPair.Value) > 0 {
		parsedBool, errConv := strconv.ParseBool(string(kvPair.Value))
		if errConv != nil {
			consulKVErrorsTotal.Inc()
			finalErr = fmt.Errorf("parsing %s for key %s: %w", configTypeLabel, key, errConv)
		} else {
			val = parsedBool
		}
	}

	if finalErr == nil && (kvPair != nil && len(kvPair.Value) > 0) {
		configReloadsTotal.WithLabelValues(configTypeLabel).Inc()
	}
	return val, finalErr
}

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

func PollConsulKV(
	ctx context.Context,
	s *Service,
	consulKVClient consulKVGetter,
	interval time.Duration,
	logger *slog.Logger,
	xdpSyncer XDPMapSyncer,
	wg *sync.WaitGroup,
	quitSignal <-chan struct{},
) {
	defer wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	updateConfigs := func(isInitial bool) {
		ipList, uaList, l7RLCfg, l4ConnRLCfg, l4XDPLgcEnabled, xdpGlobEnabled, fetchErr :=
			FetchAllConfigsFromConsul(consulKVClient, logger)

		if fetchErr != nil {
			logger.Error("Error(s) during Consul KV fetch, service config remains unchanged.", "error", fetchErr)
		} else {
			s.UpdateIPBlocklist(ipList)
			s.UpdateUABlocklist(uaList)
			s.UpdateL7RateLimitConfig(l7RLCfg)
			s.UpdateL4ConnRateLimitConfig(l4ConnRLCfg)
			s.UpdateL4XDPBlocklistLogicEnabled(l4XDPLgcEnabled)
			s.UpdateXDPGlobalEnabled(xdpGlobEnabled)
		}

		if xdpSyncer != nil && xdpSyncer.IsInitialized() {
			if s.IsXDPGlobalEnabled() {
				if err := xdpSyncer.SyncIPBlocklistToMap(s.GetIPBlocklistSnapshot()); err != nil {
					logger.Error("Failed to sync IP blocklist to eBPF map", "error", err)
					EbpfMapSyncTotal.WithLabelValues("failure").Inc()
				} else {
					EbpfMapSyncTotal.WithLabelValues("success").Inc()
				}
			} else {
				if err := xdpSyncer.SyncIPBlocklistToMap(make(map[string]struct{})); err != nil {
					logger.Error("Failed to clear eBPF map when XDP disabled via KV", "error", err)
					EbpfMapSyncTotal.WithLabelValues("clear_failure").Inc()
				} else {
					EbpfMapSyncTotal.WithLabelValues("clear_success").Inc()
				}
			}
		} else {
			logger.Warn("Skipping XDP map sync because controller is nil or failed to initialize.")
			EbpfMapSyncTotal.WithLabelValues("skipped_uninitialized").Inc()
		}
	}

	updateConfigs(true)

	logger.Info("Consul KV poller started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			logger.Info("Consul KV poller stopping due to application context cancellation.")
			return
		case <-quitSignal:
			logger.Info("Consul KV poller stopping due to quit signal.")
			return
		case <-ticker.C:
			updateConfigs(false)
		}
	}
}

type HTTPAuthzServer struct {
	pb.UnimplementedAuthorizationServer
	logger      *slog.Logger
	coreService *Service
}

func NewHTTPAuthzServer(logger *slog.Logger, coreService *Service) *HTTPAuthzServer {
	return &HTTPAuthzServer{
		logger:      logger.With("handler", "http_l7_ext_authz"),
		coreService: coreService,
	}
}

func (h *HTTPAuthzServer) HandleAuthzRequest(w http.ResponseWriter, r *http.Request) {
	reqIDArr, ok := r.Header["X-Request-Id"]
	reqID := ""
	if ok && len(reqIDArr) > 0 {
		reqID = reqIDArr[0]
	} else {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		reqID = hex.EncodeToString(b)
	}

	logger := h.logger.With("request_id", reqID)
	clientIP := getClientIP(r)
	userAgent := r.UserAgent()
	requestPath := r.URL.Path
	logAttrs := []any{
		slog.String("method", r.Method),
		slog.String("path", requestPath),
		slog.String("client_ip", clientIP),
		slog.String("user_agent", userAgent),
	}

	if h.coreService.IsIPBlocked(clientIP) {
		logger.Warn("L7 Request denied: IP on blocklist", logAttrs...)
		httpRequestsTotal.WithLabelValues("denied", "ip_blocklist").Inc()
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if userAgent != "" && h.coreService.IsUABlocked(userAgent) {
		logger.Warn("L7 Request denied: User-Agent on blocklist", logAttrs...)
		httpRequestsTotal.WithLabelValues("denied", "ua_blocklist").Inc()
		w.WriteHeader(http.StatusForbidden)
		return
	}

	rlEnabled, rlLimit, rlWindow := h.coreService.GetL7RateLimitConfig()
	if rlEnabled && clientIP != "" {
		if h.coreService.redisClient == nil {
			logger.Error("L7 Rate limiting enabled but Redis client is nil! Allowing request.", logAttrs...)
		} else {
			allow, _, err := h.coreService.CheckAndIncrementL7RateLimit(clientIP)
			if err != nil {
				logger.Error("Error during L7 rate limit check, failing open (allowing request)", append(logAttrs, slog.String("error", err.Error()))...)
			} else if !allow {
				logger.Warn("L7 Request denied: Rate limit exceeded", append(logAttrs, slog.Int64("limit", rlLimit), slog.Duration("window", rlWindow))...)
				httpRequestsTotal.WithLabelValues("denied", "l7_rate_limit").Inc()
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rlWindow.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		}
	}

	httpRequestsTotal.WithLabelValues("allowed", "none").Inc()
	logger.Info("L7 Request allowed", logAttrs...)
	w.WriteHeader(http.StatusOK)
}

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
	if clientIP == "" && req.GetAttributes().GetSource() != nil &&
		req.GetAttributes().GetSource().GetAddress() != nil &&
		req.GetAttributes().GetSource().GetAddress().GetSocketAddress() != nil {
		clientIP = req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress()
	}

	if clientIP == "" {
		httpRequestsTotal.WithLabelValues("denied", "missing_source_ip_grpc").Inc()
		return &pb.CheckResponse{
			Status: status.New(codes.PermissionDenied, "Source IP missing").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			}},
		}, nil
	}

	logger := h.logger.With("client_ip", clientIP, "path", path, "method", method, "handler", "grpc_l7_ext_authz")

	if h.coreService.IsIPBlocked(clientIP) {
		logger.Warn("L7 gRPC Check: Denied - IP on blocklist")
		httpRequestsTotal.WithLabelValues("denied", "ip_blocklist_grpc").Inc()
		return &pb.CheckResponse{
			Status: status.New(codes.PermissionDenied, "IP Blocked").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			}},
		}, nil
	}

	if userAgent != "" && h.coreService.IsUABlocked(userAgent) {
		logger.Warn("L7 gRPC Check: Denied - User-Agent on blocklist")
		httpRequestsTotal.WithLabelValues("denied", "ua_blocklist_grpc").Inc()
		return &pb.CheckResponse{
			Status: status.New(codes.PermissionDenied, "User-Agent Blocked").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			}},
		}, nil
	}

	rlEnabled, _, _ := h.coreService.GetL7RateLimitConfig()
	if rlEnabled {
		if h.coreService.redisClient == nil {
			logger.Error("L7 gRPC Check: Rate limiting enabled but Redis client is nil! Allowing request.")
		} else {
			allow, _, err := h.coreService.CheckAndIncrementL7RateLimit(clientIP)
			if err != nil {
				logger.Error("L7 gRPC Check: Error during L7 rate limit check, failing open (allowing request)", "error", err)
			} else if !allow {
				httpRequestsTotal.WithLabelValues("denied", "l7_rate_limit_grpc").Inc()
				return &pb.CheckResponse{
					Status: status.New(codes.ResourceExhausted, "Rate Limit Exceeded").Proto(),
					HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
					}},
				}, nil
			}
		}
	}

	httpRequestsTotal.WithLabelValues("allowed", "none_grpc").Inc()
	return &pb.CheckResponse{
		Status: status.New(codes.OK, "OK").Proto(),
		HttpResponse: &pb.CheckResponse_OkResponse{OkResponse: &pb.OkHttpResponse{}},
	}, nil
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if net.ParseIP(host) != nil {
			return host
		}
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}
	return "unknown"
}

func (s *Service) CheckAndIncrementL7RateLimit(id string) (bool, int64, error) {
	s.configMutex.RLock()
	enabled := s.l7RateLimitEnabled
	limit := s.l7RateLimitCount
	window := s.l7RateLimitWindow
	s.configMutex.RUnlock()

	if !enabled {
		return true, 0, nil
	}
	if s.redisClient == nil {
		return true, 0, nil
	}

	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:l7_http:%s", id)
	var currentCount int64

	pipe := s.redisClient.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	_ = pipe.Expire(ctx, key, window)

	_, execErr := pipe.Exec(ctx)
	if execErr != nil {
		redisErrorsTotal.Inc()
		return true, 0, execErr
	}

	currentCount = incrCmd.Val()
	if currentCount > limit {
		return false, 0, nil
	}
	return true, limit - currentCount, nil
}

func (s *Service) CheckAndIncrementL4ConnRateLimit(id string) (bool, int64, error) {
	s.configMutex.RLock()
	enabled := s.l4ConnRateLimitEnabled
	limit := s.l4ConnRateLimitCount
	window := s.l4ConnRateLimitWindow
	s.configMutex.RUnlock()

	if !enabled {
		return true, 0, nil
	}
	if s.redisClient == nil {
		return true, 0, nil
	}

	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:l4_conn:%s", id)
	var currentCount int64

	pipe := s.redisClient.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	_ = pipe.Expire(ctx, key, window)

	_, execErr := pipe.Exec(ctx)
	if execErr != nil {
		redisErrorsTotal.Inc()
		return true, 0, execErr
	}
	currentCount = incrCmd.Val()
	if currentCount > limit {
		l4ConnectionsRateLimitedTotal.Inc()
		return false, 0, nil
	}
	return true, limit - currentCount, nil
}
