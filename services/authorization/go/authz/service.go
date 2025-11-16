// FILE: services/authorization/go/authz/service.go
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	pb "grewal.cc/services/authorization/go/pkg/genproto/envoy/service/auth/v3"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// XDPMapSyncer defines the interface for syncing the static blocklist to the kernel.
type XDPMapSyncer interface {
	SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error
}

// BanHammer defines the interface for dynamically banning IPs at the kernel level.
type BanHammer interface {
	AddDynamicBan(ipStr string, duration time.Duration) error
}

// XDPStatsReader defines the interface for reading performance counters from the kernel.
type XDPStatsReader interface {
	ReadStats() (interface{}, error)
}

// FirewallManagerInterface combines the capabilities needed from the firewall manager.
type FirewallManagerInterface interface {
	XDPMapSyncer
	BanHammer
	XDPStatsReader
}

// FirewallAdapter adapts the concrete kernel.FirewallManager to our interface.
type FirewallAdapter struct {
	Manager interface {
		SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error
		AddDynamicBan(ipStr string, duration time.Duration) error
		ReadStats() (interface{}, error)
	}
}

func (a *FirewallAdapter) SyncIPBlocklistToMap(currentIPsFromConsul map[string]struct{}) error {
	return a.Manager.SyncIPBlocklistToMap(currentIPsFromConsul)
}

func (a *FirewallAdapter) AddDynamicBan(ipStr string, duration time.Duration) error {
	return a.Manager.AddDynamicBan(ipStr, duration)
}

func (a *FirewallAdapter) ReadStats() (interface{}, error) {
	return a.Manager.ReadStats()
}

const (
	ipBlocklistKVKey = "config/security/ip_blocklist"
	l7RateLimit      = 100 // requests per minute
)

type consulKVGetter interface {
	Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
}

type valkeyRateLimiter interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}

// Service holds the core application state and business logic.
type Service struct {
	logger      *slog.Logger
	kvClient    consulKVGetter
	valkey      valkeyRateLimiter
	firewall    FirewallManagerInterface
	ipBlocklist map[string]struct{}
	configMutex sync.RWMutex
}

// NewService creates a new core authorization service with XDP firewall.
func NewService(logger *slog.Logger, kv consulKVGetter, valkey valkeyRateLimiter, firewall FirewallManagerInterface) *Service {
	return &Service{
		logger:      logger.With("component", "authz_service"),
		kvClient:    kv,
		valkey:      valkey,
		firewall:    firewall,
		ipBlocklist: make(map[string]struct{}),
	}
}

// NewServiceWithoutFirewall creates a Service instance without XDP firewall support.
// This is used when running in environments where eBPF/XDP cannot be loaded.
func NewServiceWithoutFirewall(logger *slog.Logger, kv consulKVGetter, valkey valkeyRateLimiter) *Service {
	return &Service{
		logger:      logger.With("component", "authz_service"),
		kvClient:    kv,
		valkey:      valkey,
		firewall:    nil, // No firewall manager
		ipBlocklist: make(map[string]struct{}),
	}
}

// UpdateIPBlocklist is called by the background task to refresh the in-memory cache.
func (s *Service) UpdateIPBlocklist(newBlocklist map[string]struct{}) {
	s.configMutex.Lock()
	defer s.configMutex.Unlock()
	s.ipBlocklist = newBlocklist
}

// IsIPBlocked checks the in-memory cache. This provides L7 defense-in-depth.
func (s *Service) IsIPBlocked(ip string) bool {
	s.configMutex.RLock()
	defer s.configMutex.RUnlock()
	_, blocked := s.ipBlocklist[ip]
	return blocked
}

// AuthzServer implements the Envoy ext_authz gRPC interface.
type AuthzServer struct {
	pb.UnimplementedAuthorizationServer
	logger      *slog.Logger
	coreService *Service
}

// NewAuthzServer creates a new gRPC server handler.
func NewAuthzServer(logger *slog.Logger, coreService *Service) *AuthzServer {
	return &AuthzServer{
		logger:      logger.With("component", "grpc_authz_server"),
		coreService: coreService,
	}
}

// Check is the main entrypoint for authorization requests from Envoy.
func (s *AuthzServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	var clientIP string
	if source := req.GetAttributes().GetSource(); source != nil && source.GetAddress() != nil && source.GetAddress().GetSocketAddress() != nil {
		clientIP = source.GetAddress().GetSocketAddress().GetAddress()
	}

	if clientIP == "" {
		s.logger.Warn("Authorization check received with no source IP")
		return DeniedResponse(codes.PermissionDenied, "Source IP missing"), nil
	}

	// Layer 1: Check against static blocklist
	if s.coreService.IsIPBlocked(clientIP) {
		s.logger.Warn("L7 Check: Denied - IP on static blocklist", "client_ip", clientIP)
		return DeniedResponse(codes.PermissionDenied, "IP Blocked"), nil
	}

	// Layer 2: L7 Rate Limiting
	limitExceeded, err := s.coreService.checkL7RateLimit(clientIP)
	if err != nil {
		s.logger.Error("Rate limit check failed, failing open", "error", err, "client_ip", clientIP)
	}
	if limitExceeded {
		s.logger.Warn("L7 Check: Rate limit exceeded, activating Ban Hammer!", "client_ip", clientIP, "limit", l7RateLimit)

		// Trigger the Ban Hammer only if firewall is available
		if s.coreService.firewall != nil {
			if banErr := s.coreService.firewall.AddDynamicBan(clientIP, 5*time.Minute); banErr != nil {
				s.logger.Error("Failed to apply dynamic ban", "error", banErr, "client_ip", clientIP)
			}
		} else {
			s.logger.Warn("XDP firewall not available, cannot apply kernel-level ban", "client_ip", clientIP)
		}

		return &pb.CheckResponse{
			Status: status.New(codes.ResourceExhausted, "Rate limit exceeded").Proto(),
			HttpResponse: &pb.CheckResponse_DeniedResponse{
				DeniedResponse: &pb.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
				},
			},
		}, nil
	}

	return AllowedResponse(), nil
}

// checkL7RateLimit implements an accurate sliding-window rate limit using Valkey.
func (s *Service) checkL7RateLimit(id string) (bool, error) {
	now := time.Now().Unix()
	minute := now / 60
	key := fmt.Sprintf("ratelimit:l7:%s:%d", id, minute)

	count, err := s.valkey.Incr(context.Background(), key).Result()
	if err != nil {
		return false, err
	}

	if count == 1 {
		s.valkey.Expire(context.Background(), key, 2*time.Minute)
	}

	return count > l7RateLimit, nil
}

func AllowedResponse() *pb.CheckResponse {
	return &pb.CheckResponse{
		Status:       status.New(codes.OK, "OK").Proto(),
		HttpResponse: &pb.CheckResponse_OkResponse{OkResponse: &pb.OkHttpResponse{}},
	}
}

func DeniedResponse(code codes.Code, message string) *pb.CheckResponse {
	return &pb.CheckResponse{
		Status: status.New(code, message).Proto(),
		HttpResponse: &pb.CheckResponse_DeniedResponse{
			DeniedResponse: &pb.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			},
		},
	}
}

// RunBackgroundTasks is the main goroutine for periodic work.
func RunBackgroundTasks(
	ctx context.Context,
	s *Service,
	interval time.Duration,
	logger *slog.Logger,
	wg *sync.WaitGroup,
	quitSignal <-chan struct{},
) {
	defer wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	updateAndSync := func() {
		kvPair, _, err := s.kvClient.Get(ipBlocklistKVKey, nil)
		if err != nil {
			logger.Error("Error fetching IP blocklist from Consul", "error", err, "key", ipBlocklistKVKey)
			return
		}

		// Parse CSV-formatted IP list
		ipList := make(map[string]struct{})
		if kvPair != nil && len(kvPair.Value) > 0 {
			for _, entry := range strings.Split(string(kvPair.Value), ",") {
				if trimmed := strings.TrimSpace(entry); trimmed != "" {
					ipList[trimmed] = struct{}{}
				}
			}
		}

		// Update L7 in-memory cache
		s.UpdateIPBlocklist(ipList)

		// Sync to kernel only if firewall is available
		if s.firewall != nil {
			if xdpSyncer, ok := s.firewall.(XDPMapSyncer); ok {
				if err := xdpSyncer.SyncIPBlocklistToMap(ipList); err != nil {
					logger.Error("Failed to sync IP blocklist to eBPF map", "error", err)
				}
			}
		}
	}

	logStats := func() {
		if s.firewall != nil {
			if statsReader, ok := s.firewall.(XDPStatsReader); ok {
				stats, err := statsReader.ReadStats()
				if err != nil {
					logger.Error("Failed to read XDP stats", "error", err)
				} else {
					logger.Info("XDP Kernel Stats", "stats", stats)
				}
			}
		}
	}

	// Initial run on startup
	updateAndSync()
	logStats()

	// Periodic execution
	for {
		select {
		case <-ctx.Done():
			logger.Info("Background tasks stopping due to context cancellation")
			return
		case <-quitSignal:
			logger.Info("Background tasks stopping due to quit signal")
			return
		case <-ticker.C:
			updateAndSync()
			logStats()
		}
	}
}
