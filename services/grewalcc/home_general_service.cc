// File: services/grewalcc/home_general_service.cc
#include "home_general_service.h"
#include <iostream>
#include <memory>
#include <string>
#include <map>
#include <grpcpp/health_check_service_interface.h>

namespace grewal {

grpc::Status HomeGeneralServiceImpl::GetHomeGeneral(
    grpc::ServerContext* context,
    const GeneralRequest* request,
    GeneralResponse* response) {

    (void)request;

    // Extract Headers from gRPC Metadata
    std::string remote_ip = "Unknown";
    std::string user_agent = "Unknown";

    const auto& metadata = context->client_metadata();

    auto xff_iter = metadata.find("x-forwarded-for");
    if (xff_iter != metadata.end()) {
        remote_ip = std::string(xff_iter->second.data(), xff_iter->second.length());
    }

    auto ua_iter = metadata.find("user-agent");
    if (ua_iter != metadata.end()) {
        user_agent = std::string(ua_iter->second.data(), ua_iter->second.length());
    }

    // Populate the Response Message
    response->set_remote_ip(remote_ip);
    response->set_user_agent(user_agent);

    std::cout << "GetHomeGeneral: Processed request for IP="
              << remote_ip << ", UA=" << user_agent << std::endl;

    return grpc::Status::OK;
}

void RunGrpcServer() {
    std::string server_address("0.0.0.0:50051");
    grewal::HomeGeneralServiceImpl service;

    grpc::EnableDefaultHealthCheckService(true);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    if (server == nullptr) {
        std::cerr << "!!! ERROR: Failed to start gRPC server on " << server_address << std::endl;
        return;
    }
    std::cout << "Grewalcc data-service listening on " << server_address << std::endl;
    server->Wait();
}

} // namespace grewal
