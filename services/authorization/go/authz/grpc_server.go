// FILE: services/authorization/go/authz/grpc_server.go
package authz

import (
	"context"
	"log/slog"

	pb "grewal.cc/services/authorization/go/pkg/genproto/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type NetworkAuthzServer struct {
	pb.UnimplementedAuthorizationServer
	coreService *Service
	logger      *slog.Logger
}

func NewNetworkAuthzServer(coreSvc *Service, logger *slog.Logger) *NetworkAuthzServer {
	return &NetworkAuthzServer{
		coreService: coreSvc,
		logger:      logger.With("component", "network_authz_grpc_server"),
	}
}

func (s *NetworkAuthzServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	var clientIP string
	if source := req.GetAttributes().GetSource(); source != nil {
		if sourceAddr := source.GetAddress().GetSocketAddress(); sourceAddr != nil {
			clientIP = sourceAddr.GetAddress()
		}
	}

	s.logger.Info("L4 Check: Received connection attempt", "seen_source_ip", clientIP)

	// L4 IP Blocklist Check
	if clientIP != "" {
		if s.coreService.IsIPBlocked(clientIP) {
			s.logger.Warn("L4 ext_authz: Denying TCP connection", "reason", "ip_blocklist", "client_ip", clientIP)
			return &pb.CheckResponse{
				Status: status.New(codes.PermissionDenied, "IP Address is on the blocklist").Proto(),
			}, nil
		}
	}

	// L4 TCP Connection Rate Limiting Logic
	if clientIP != "" {
		allow, _, err := s.coreService.CheckAndIncrementL4ConnRateLimit(clientIP)
		if err != nil {
			s.logger.Error("L4 Redis check failed, allowing connection to prevent outage", "error", err, "client_ip", clientIP)
		} else if !allow {
			s.logger.Warn("L4 ext_authz: Denying TCP connection due to L4 connection rate limit", "reason", "rate_limit", "client_ip", clientIP)
			return &pb.CheckResponse{
				Status: status.New(codes.ResourceExhausted, "L4 connection rate limit exceeded").Proto(),
			}, nil
		}
	}

	s.logger.Info("L4 ext_authz: Allowing TCP connection", "reason", "passed_all_l4_checks", "client_ip", clientIP)

	// For an L4 network filter, ONLY return the Status.
	return &pb.CheckResponse{
		Status: status.New(codes.OK, "OK").Proto(),
	}, nil
}
