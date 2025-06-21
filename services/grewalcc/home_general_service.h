#ifndef HOME_GENERAL_SERVICE_H
#define HOME_GENERAL_SERVICE_H

#include "home_general.grpc.pb.h" // Includes the gRPC service definition
#include <grpcpp/grpcpp.h>      // Includes gRPC++ headers

namespace grewal {

std::string getSubdomain(const std::string& host);

class HomeGeneralServiceImpl final : public HomeGeneral::Service {
public:
    grpc::Status GetHomeGeneral(grpc::ServerContext* context,
                               const HomeGeneralRequest* request,
                               HomeGeneralResponse* response) override;
};

void RunGrpcServer(); // Declaration of the server startup function

} // namespace grewal

#endif
