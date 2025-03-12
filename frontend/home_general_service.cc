#include "home_general_service.h"
#include "../security/security.h" // Adjust path if needed
#include <ctemplate/template.h>
#include <grpcpp/grpcpp.h> // Include gRPC++ headers here as well

namespace grewal {

grpc::Status HomeGeneralServiceImpl::GetHomeGeneral(grpc::ServerContext* context,
                                                  const HomeGeneralRequest* request,
                                                  HomeGeneralResponse* response) {
    ctemplate::TemplateDictionary dict("home_general");
    dict.SetValue("HTTP_HOST", request->http_host());
    dict.SetValue("REMOTE_IP", request->remote_ip());
    dict.SetValue("USER_AGENT", request->user_agent());

    grewal::Security security; // Assuming Security is also in the grewal namespace
    if (security.isInternal(request->remote_ip().c_str())) {
        dict.ShowSection("INTERNAL");
    }

    std::string output;
    ctemplate::ExpandTemplate("templates/home_general.tpl",
                              ctemplate::DO_NOT_STRIP, &dict, &output);

    response->set_html_output(output);
    return grpc::Status::OK;
}

void RunGrpcServer() {
    std::string server_address("0.0.0.0:50051"); // Or your desired address/port
    grewal::HomeGeneralServiceImpl service;

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials()); // Use SECURE credentials in production!
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait(); // This blocks until the server shuts down
}

} // namespace grewal
