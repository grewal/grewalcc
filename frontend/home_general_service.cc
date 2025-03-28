#include "home_general_service.h"
#include "home_general.grpc.pb.h"
// Assuming security.h is correctly included relative to build system includes
#include "../security/security.h" 
#include <ctemplate/template.h>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <string>
#include <map> // For metadata

namespace grewal {

grpc::Status HomeGeneralServiceImpl::GetHomeGeneral(grpc::ServerContext* context,
                                                 const HomeGeneralRequest* request,
                                                 HomeGeneralResponse* response) {
    // --- Log Entry ---
    std::cout << "=== GetHomeGeneral START ===" << std::endl;

    // --- Log Data Received in Request Payload (Potentially Incorrect Source) ---
    std::cout << "[Payload Data]" << std::endl;
    std::cout << "  Payload http_host: " << request->http_host() << std::endl;
    std::cout << "  Payload remote_ip: " << request->remote_ip() << std::endl;
    std::cout << "  Payload user_agent: " << request->user_agent() << std::endl;

    // --- Log Data from gRPC Context & Metadata (Correct Source) ---
    std::cout << "[Context/Metadata]" << std::endl;
    std::string peer_ip = context->peer(); // Get direct peer IP (will be Envoy's IP: 127.0.0.1)
    std::cout << "  context->peer(): " << peer_ip << std::endl;

    // Extract headers from metadata (X-Forwarded-For, User-Agent, Host/:authority)
    std::string actual_remote_ip = peer_ip; // Default to peer IP
    std::string actual_user_agent = "Unknown";
    std::string actual_host = "Unknown";

    const std::multimap<grpc::string_ref, grpc::string_ref>& metadata = context->client_metadata();
    for (auto iter = metadata.begin(); iter != metadata.end(); ++iter) {
        std::string key(iter->first.data(), iter->first.length());
        std::string value(iter->second.data(), iter->second.length());
        std::cout << "  Metadata: " << key << " = " << value << std::endl;

        // Look for X-Forwarded-For (Nginx should add this)
        if (key == "x-forwarded-for") {
            // Take the first IP in the list if multiple exist
            size_t comma_pos = value.find(',');
            actual_remote_ip = (comma_pos == std::string::npos) ? value : value.substr(0, comma_pos);
        }
        // Look for User-Agent
        else if (key == "user-agent") {
            actual_user_agent = value;
        }
        // Look for Host or :authority (gRPC uses :authority)
        else if (key == "host" || key == ":authority") {
             actual_host = value;
             // Optionally strip port if present
             size_t colon_pos = actual_host.find(':');
             if (colon_pos != std::string::npos) {
                 actual_host = actual_host.substr(0, colon_pos);
             }
        }
    }
    std::cout << "  Derived Actual Remote IP: " << actual_remote_ip << std::endl;
    std::cout << "  Derived Actual User Agent: " << actual_user_agent << std::endl;
    std::cout << "  Derived Actual Host: " << actual_host << std::endl;

    // --- Prepare Data for Template (Using CORRECTED Sources) ---
    std::cout << "[Template Data Prep]" << std::endl;
    ctemplate::TemplateDictionary dict("home_general");

    // **USE THE DERIVED VALUES, NOT THE PAYLOAD VALUES**
    dict.SetValue("HTTP_HOST", actual_host);
    dict.SetValue("REMOTE_IP", actual_remote_ip);
    dict.SetValue("USER_AGENT", actual_user_agent);

    // Derive subdomain from the *actual* host
    grewal::Security security;
    //std::string sub_domain = actual_host;
    //dict.SetValue("SUB_DOMAIN", actual_host);
    //std::cout << "  Template HTTP_HOST: " << actual_host << std::endl;
    //std::cout << "  Template REMOTE_IP: " << actual_remote_ip << std::endl;
    //std::cout << "  Template USER_AGENT: " << actual_user_agent << std::endl;

    // Check internal status using the *actual* remote IP
    bool is_internal = security.isInternal(actual_remote_ip.c_str());
    if (is_internal) {
        std::cout << "  Showing INTERNAL section." << std::endl;
        dict.ShowSection("INTERNAL");
    } else {
         std::cout << "  NOT showing INTERNAL section." << std::endl;
    }


    // --- Expand Template ---
    std::cout << "[Template Expansion]" << std::endl;
    std::string output_html;
    // CRITICAL: templates directory must be relative to execution path.
    bool expand_ok = ctemplate::ExpandTemplate("templates/home_general.tpl",
                                          ctemplate::DO_NOT_STRIP, &dict, &output_html);

    if (!expand_ok) {
         std::cerr << "  ERROR: Failed to expand template 'templates/home_general.tpl'" << std::endl;
         // Return an internal error to the client
         return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to render template");
    }
    std::cout << "  Template expanded successfully." << std::endl;


    // --- Prepare and Log Response ---
    response->set_html_output(output_html);

    std::cout << "[Response Sending]" << std::endl;
    std::cout << "  Response HTML size: " << output_html.length() << std::endl;
    std::cout << "  Response HTML snippet (first 100): "
              << output_html.substr(0, 100) << (output_html.length() > 100 ? "..." : "")
              << std::endl;

    // --- Log Exit ---
    std::cout << "=== GetHomeGeneral END (Success) ===" << std::endl;
    return grpc::Status::OK;
}

// RunGrpcServer function remains the same... make sure it includes the cout line:
void RunGrpcServer() {
    std::string server_address("0.0.0.0:50051");
    grewal::HomeGeneralServiceImpl service;

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // ** TODO: Add Reflection Service Registration Here (Optional but Recommended Later) **
    // grpc::reflection::InitProtoReflectionServerBuilderPlugin(); // #include <grpcpp/ext/proto_server_reflection_plugin.h>
    // builder.RegisterService(&service); // Register your service *after* reflection init
    builder.RegisterService(&service); // Register service

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    if (server == nullptr) {
         std::cerr << "!!! ERROR: Failed to start gRPC server on " << server_address << std::endl;
         return; // Or exit, handle error
    }
    std::cout << "Grewal GRPC server listening on " << server_address << std::endl;
    server->Wait();
    std::cout << "Grewal GRPC server shutting down." << std::endl; // Added shutdown message
}

} // namespace grewal
