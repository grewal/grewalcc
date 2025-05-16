package authz

import (
	"context"
	"log/slog"

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

	if clientIP != "" {
		s.coreService.configMutex.RLock()
		_, ipIsBlocked := s.coreService.ipBlocklist[clientIP]
		s.coreService.configMutex.RUnlock()

		if ipIsBlocked {
			// L4 Deny due to IP blocklist
			finalLogAttrs := append(logAttrs, slog.String("l4_decision", "deny"), slog.String("l4_reason", "ip_blocklist"))
			s.logger.Warn("L4 ext_authz: Denying TCP connection", finalLogAttrs...)
			// Increment L4 specific Prometheus counter for IP block deny here later
			return &pb.CheckResponse{
				HttpResponse: &pb.CheckResponse_DeniedResponse{
					DeniedResponse: &pb.DeniedHttpResponse{},
				},
			}, nil
		}
	} else {
		s.logger.Warn("L4 ext_authz: ClientIP is empty, cannot perform IP block check. Allowing connection.", logAttrs...)
	}

	// If not blocked by IP, proceed to other L4 checks (like rate limiting - to be added) or allow
	// For now, if not IP-blocked, it's allowed by L4.
	finalLogAttrs := append(logAttrs, slog.String("l4_decision", "allow"), slog.String("l4_reason", "passed_ip_check"))
	s.logger.Info("L4 ext_authz: Allowing TCP connection", finalLogAttrs...)
	// Increment L4 specific Prometheus counter for allow here later
	return &pb.CheckResponse{
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{},
		},
	}, nil
}
