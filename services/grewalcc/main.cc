#include <iostream>
#include "home_general_service.h" // Include the gRPC service implementation

int main(int argc, char *argv[]) {
    grewal::RunGrpcServer(); // ONLY start the gRPC server
    return 0;
}
