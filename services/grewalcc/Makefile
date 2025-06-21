# File: services/grewalcc/Makefile
BINARY_NAME = grewalcc
CXX = g++
BASE_CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread

# --- Protobuf Generation ---
PROTO_SRC = home_general.proto
PROTOC = $(shell which protoc)
GRPC_PLUGIN = /usr/bin/grpc_cpp_plugin

# --- Dependencies via pkg-config ---
PKG_CFG_LIBS = grpc++ protobuf
CXXFLAGS = $(BASE_CXXFLAGS) $(shell pkg-config --cflags $(PKG_CFG_LIBS))
LDFLAGS = $(shell pkg-config --libs $(PKG_CFG_LIBS))

# --- Generated Files ---
PROTO_GENERATED = home_general.pb.cc home_general.grpc.pb.cc
PROTO_HEADERS = home_general.pb.h home_general.grpc.pb.h

# --- Source Files ---
CXX_SOURCES = \
    main.cc \
    home_general_service.cc \
    $(PROTO_GENERATED)

OBJECTS = $(CXX_SOURCES:.cc=.o)

.PHONY: all clean protos

all: $(BINARY_NAME)

# Generate protobuf files
$(PROTO_GENERATED) $(PROTO_HEADERS): $(PROTO_SRC)
	@echo "--- Generating Protobuf/gRPC C++ files ---"
	$(PROTOC) --grpc_out=. --cpp_out=. --plugin=protoc-gen-grpc=$(GRPC_PLUGIN) $(PROTO_SRC)

# Legacy protos target for manual generation
protos: $(PROTO_GENERATED)

# Binary depends on all objects
$(BINARY_NAME): $(OBJECTS)
	@echo "--- Linking binary: $(BINARY_NAME) ---"
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

# Object files depend on their source files
%.o: %.cc
	@echo "--- Compiling $< ---"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Protobuf object files also depend on generated headers
home_general.pb.o: home_general.pb.cc $(PROTO_HEADERS)
home_general.grpc.pb.o: home_general.grpc.pb.cc $(PROTO_HEADERS)

# Service file depends on generated headers
home_general_service.o: home_general_service.cc $(PROTO_HEADERS)

# Main file also depends on generated headers (since it includes home_general_service.h)
main.o: main.cc $(PROTO_HEADERS)

clean:
	rm -f $(BINARY_NAME) $(OBJECTS) $(PROTO_GENERATED) $(PROTO_HEADERS)
