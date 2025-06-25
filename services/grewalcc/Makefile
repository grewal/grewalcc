# File: services/grewalcc/Makefile

BINARY_NAME = grewalcc
CXX = g++
BASE_CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread
PKG_CFG_LIBS = grpc++ protobuf
CXXFLAGS = $(BASE_CXXFLAGS) $(shell pkg-config --cflags $(PKG_CFG_LIBS))
LDFLAGS = $(shell pkg-config --libs $(PKG_CFG_LIBS))

PROTO_PATH = protos
PROTO_SRC = $(PROTO_PATH)/home_general.proto
GRPC_CPP_PLUGIN_PATH = /usr/bin/grpc_cpp_plugin

PROTO_GENERATED_CC = home_general.pb.cc home_general.grpc.pb.cc
PROTO_HEADERS = home_general.pb.h home_general.grpc.pb.h

CXX_SOURCES = main.cc home_general_service.cc $(PROTO_GENERATED_CC)
OBJECTS = $(CXX_SOURCES:.cc=.o)

.PHONY: all clean protos-cpp

all: $(BINARY_NAME)

protos-cpp: $(PROTO_HEADERS)

$(PROTO_GENERATED_CC) $(PROTO_HEADERS): $(PROTO_SRC)
	@echo "--- Generating Protobuf/gRPC C++ files from $(PROTO_SRC) ---"
	protoc --proto_path=$(PROTO_PATH) \
	       --cpp_out=. \
	       --grpc_out=. \
	       --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) \
	       $(PROTO_SRC)

$(BINARY_NAME): protos-cpp $(OBJECTS)
	@echo "--- Linking binary: $(BINARY_NAME) ---"
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.cc
	@echo "--- Compiling $< ---"
	$(CXX) $(CXXFLAGS) -c $< -o $@

home_general.pb.o: home_general.pb.cc
home_general.grpc.pb.o: home_general.grpc.pb.cc
home_general_service.o: home_general_service.cc
main.o: main.cc

clean:
	rm -f $(BINARY_NAME) $(OBJECTS) $(PROTO_GENERATED_CC) $(PROTO_HEADERS)

