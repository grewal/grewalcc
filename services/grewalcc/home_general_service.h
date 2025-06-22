// File: services/grewalcc/home_general_service.h (Corrected)
#ifndef HOME_GENERAL_SERVICE_H
#define HOME_GENERAL_SERVICE_H

#include "home_general.grpc.pb.h"
#include <grpcpp/grpcpp.h>

namespace grewal {

class HomeGeneralServiceImpl final : public HomeGeneral::Service {
public:
    grpc::Status GetHomeGeneral(grpc::ServerContext* context,
                               const GeneralRequest* request,
                               GeneralResponse* response) override;
};

void RunGrpcServer();

} // namespace grewal

#endif // HOME_GENERAL_SERVICE_H
