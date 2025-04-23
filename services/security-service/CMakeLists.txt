cmake_minimum_required(VERSION 3.16)

project(security-service VERSION 0.1.0 LANGUAGES CXX)

# Find the Protobuf package provided by vcpkg
find_package(Protobuf CONFIG REQUIRED)

# Find the gRPC package provided by vcpkg
find_package(gRPC CONFIG REQUIRED)

add_executable(security-service src/main.cc)

# Link our executable against Protobuf and gRPC libraries
target_link_libraries(security-service PRIVATE
    protobuf::libprotobuf
    gRPC::grpc++
)
