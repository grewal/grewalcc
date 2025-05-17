package authz

import (
	"context"
	"log/slog"
	"reflect"

	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
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
	var clientIP, destIP string
	var clientPort, destPort uint32
	var connectionID, transportProtocol, requestedServerName string

	attributes := req.GetAttributes()
	if attributes == nil {
		s.logger.Warn("L4 ext_authz: Received CheckRequest with nil Attributes, denying connection")
		return &pb.CheckResponse{HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{}}}, nil
	}

	if source := attributes.GetSource(); source != nil {
		if sourceAddr := source.GetAddress().GetSocketAddress(); sourceAddr != nil {
			clientIP = sourceAddr.GetAddress()
			clientPort = sourceAddr.GetPortValue()
		}
	}
	if destination := attributes.GetDestination(); destination != nil {
		if destAddr := destination.GetAddress().GetSocketAddress(); destAddr != nil {
			destIP = destAddr.GetAddress()
			destPort = destAddr.GetPortValue()
		}
	}

	logAttrs := []interface{}{
		slog.String("source_ip_peer", clientIP),
		slog.Uint64("source_port_peer", uint64(clientPort)),
		slog.String("destination_ip_peer", destIP),
		slog.Uint64("destination_port_peer", uint64(destPort)),
	}

	envoyCoreMeta := attributes.GetMetadataContext()
	if envoyCoreMeta != nil {
		s.logger.Debug("L4 ext_authz: Raw MetadataContext type received", "type", reflect.TypeOf(envoyCoreMeta).String())
		var dataStruct *structpb.Struct
		if fm := envoyCoreMeta.GetFilterMetadata(); fm != nil {
			if specificExtAuthzData, ok := fm["envoy.filters.network.ext_authz"]; ok && specificExtAuthzData != nil {
				dataStruct = specificExtAuthzData
			} else if genericExtAuthzData, ok := fm["ext_authz"]; ok && genericExtAuthzData != nil {
				dataStruct = genericExtAuthzData
			}
		}
		if dataStruct != nil {
			if fields := dataStruct.GetFields(); fields != nil {
				if val, ok := fields["connection_id"]; ok { connectionID = val.GetStringValue() }
				if val, ok := fields["transport_protocol"]; ok { transportProtocol = val.GetStringValue() }
				if val, ok := fields["requested_server_name"]; ok { requestedServerName = val.GetStringValue() }
			}
		}
	}
	logAttrs = append(logAttrs, slog.String("connection_id", connectionID),
		slog.String("transport_protocol", transportProtocol),
		slog.String("requested_server_name", requestedServerName))

	// L4 IP Blocklist Check
	if clientIP != "" {
		s.coreService.configMutex.RLock()
		_, ipIsBlocked := s.coreService.ipBlocklist[clientIP]
		s.coreService.configMutex.RUnlock()
		if ipIsBlocked {
			finalLogAttrs := append(logAttrs, slog.String("l4_decision", "deny"), slog.String("l4_reason", "ip_blocklist"))
			s.logger.Warn("L4 ext_authz: Denying TCP connection", finalLogAttrs...)
			return &pb.CheckResponse{HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{}}}, nil
		}
	} else {
		s.logger.Warn("L4 ext_authz: ClientIP is empty, cannot perform IP block check. Allowing.", logAttrs...)
	}

	// L4 TCP Connection Rate Limiting Logic
	s.coreService.configMutex.RLock()
	isL4RLEnabled := s.coreService.l4ConnRateLimitEnabled
	l4RLLimit := s.coreService.l4ConnRateLimitCount
	l4RLWindow := s.coreService.l4ConnRateLimitWindow
	s.coreService.configMutex.RUnlock()

	if isL4RLEnabled && clientIP != "" {
		if s.coreService.redisClient == nil {
			s.logger.Error("L4 Connection Rate Limiting enabled but Redis client is nil! Allowing connection.", logAttrs...)
		} else {
			redisKeyL4 := "l4_conn_rl:" + clientIP
			var currentL4Count int64

			pipe := s.coreService.redisClient.Pipeline()
			incrCmd := pipe.Incr(ctx, redisKeyL4)
			pipe.Expire(ctx, redisKeyL4, l4RLWindow)
			_, execErr := pipe.Exec(ctx)

			if execErr != nil {
				s.coreService.logger.Error("L4 Redis pipeline failed for connection rate limit", append(logAttrs, slog.String("key", redisKeyL4), slog.String("error", execErr.Error()))...)
			} else {
				countResult, incrErr := incrCmd.Result()
				if incrErr != nil {
					s.coreService.logger.Error("L4 Redis INCR failed in pipeline for connection rate limit", append(logAttrs, slog.String("key", redisKeyL4), slog.String("error", incrErr.Error()))...)
				} else {
					currentL4Count = countResult
					logAttrs = append(logAttrs, slog.Int64("l4_conn_rl_count", currentL4Count), slog.Int64("l4_conn_rl_limit", l4RLLimit))
					if currentL4Count > l4RLLimit {
						finalLogAttrs := append(logAttrs, slog.String("l4_decision", "deny"), slog.String("l4_reason", "rate_limit"))
						s.logger.Warn("L4 ext_authz: Denying TCP connection due to L4 connection rate limit", finalLogAttrs...)
						return &pb.CheckResponse{
							HttpResponse: &pb.CheckResponse_DeniedResponse{DeniedResponse: &pb.DeniedHttpResponse{}},
						}, nil
					}
					s.logger.Debug("L4 Connection rate limit check passed", logAttrs...)
				}
			}
		}
	}

	finalLogAttrs := append(logAttrs, slog.String("l4_decision", "allow"), slog.String("l4_reason", "passed_all_l4_checks"))
	s.logger.Info("L4 ext_authz: Allowing TCP connection", finalLogAttrs...)
	return &pb.CheckResponse{
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{},
		},
	}, nil
}
