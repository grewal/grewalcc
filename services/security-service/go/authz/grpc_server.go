package authz

import (
	"context"
	"log/slog"

	pb "grewal.cc/services/security-service/go/pkg/genproto/envoy/service/auth/v3"
)

// NetworkAuthzServer implements the envoy.service.auth.v3.AuthorizationServer interface
// for network (L4) external authorization checks.
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

// Check implements the gRPC Check method for L4 external authorization
// logs request details and always allows the connection
func (s *NetworkAuthzServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	var clientIP string
	var clientPort uint32
	var destIP string
	var destPort uint32
	var connectionID, transportProtocol, requestedServerName string

	if source := req.GetAttributes().GetSource(); source != nil {
		if sourceAddr := source.GetAddress().GetSocketAddress(); sourceAddr != nil {
			clientIP = sourceAddr.GetAddress()
			clientPort = sourceAddr.GetPortValue()
		}
	}
	if destination := req.GetAttributes().GetDestination(); destination != nil {
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

	if metaCtx := req.GetAttributes().GetMetadataContext(); metaCtx != nil {
		if fields := metaCtx.GetFields(); fields != nil {
			if sourceAddressVal, ok := fields["source.address"]; ok {
				logAttrs = append(logAttrs, slog.String("source_address_meta", sourceAddressVal.GetStringValue()))
			}
			if sourcePortVal, ok := fields["source.port"]; ok {
				// NumberValue could be float64, ensure appropriate logging/casting if using directly
				logAttrs = append(logAttrs, slog.Any("source_port_meta", sourcePortVal.GetNumberValue()))
			}
			if destAddressVal, ok := fields["destination.address"]; ok {
				logAttrs = append(logAttrs, slog.String("destination_address_meta", destAddressVal.GetStringValue()))
			}
			if destPortVal, ok := fields["destination.port"]; ok {
				logAttrs = append(logAttrs, slog.Any("destination_port_meta", destPortVal.GetNumberValue()))
			}
			if connIDVal, ok := fields["connection_id"]; ok {
				connectionID = connIDVal.GetStringValue() // Stored if needed for logic
				logAttrs = append(logAttrs, slog.String("connection_id_meta", connectionID))
			}
			if transportProtoVal, ok := fields["transport_protocol"]; ok {
				transportProtocol = transportProtoVal.GetStringValue() // Stored if needed for logic
				logAttrs = append(logAttrs, slog.String("transport_protocol_meta", transportProtocol))
			}
			if sniVal, ok := fields["requested_server_name"]; ok {
				requestedServerName = sniVal.GetStringValue() // Stored if needed for logic
				logAttrs = append(logAttrs, slog.String("requested_server_name_meta", requestedServerName))
			}
		}
	}

	s.logger.Info("L4 ext_authz: Received CheckRequest, allowing by default", logAttrs...)

	return &pb.CheckResponse{
		HttpResponse: &pb.CheckResponse_OkResponse{
			OkResponse: &pb.OkHttpResponse{},
		},
	}, nil
}
