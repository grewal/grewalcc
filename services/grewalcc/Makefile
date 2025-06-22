# File: services/grewalcc/Makefile
BINARY_NAME = grewalcc
CXX = g++
BASE_CXXFLAGS = -std=c++17 -Wall -Wextra -g -pthread

# --- Protobuf C++ Generation ---
PROTO_SRC = home_general.proto
PROTOC = $(shell which protoc)
GRPC_CPP_PLUGIN = /usr/bin/grpc_cpp_plugin

# --- Protobuf JavaScript Generation ---
PROTOC_GEN_JS_PLUGIN = ./node_modules/.bin/protoc-gen-js
PROTOC_GEN_GRPC_JS_PLUGIN = ./node_modules/.bin/grpc_tools_node_protoc_plugin
JS_OUT_DIR = .

# --- Dependencies via pkg-config ---
PKG_CFG_LIBS = grpc++ protobuf
CXXFLAGS = $(BASE_CXXFLAGS) $(shell pkg-config --cflags $(PKG_CFG_LIBS))
LDFLAGS = $(shell pkg-config --libs $(PKG_CFG_LIBS))

# --- Generated Files ---
PROTO_GENERATED_CC = home_general.pb.cc home_general.grpc.pb.cc
PROTO_HEADERS = home_general.pb.h home_general.grpc.pb.h
PROTO_GENERATED_JS = home_general_pb.js home_general_grpc_pb.js

# --- Source Files ---
CXX_SOURCES = \
    main.cc \
    home_general_service.cc \
    $(PROTO_GENERATED_CC)

OBJECTS = $(CXX_SOURCES:.cc=.o)

.PHONY: all clean protos-cpp protos-js all-protos npm-install

all: $(BINARY_NAME)

# --- TARGETS ---

npm-install: package.json
	@echo "--- Installing local Node.js dependencies for code generation ---"
	npm install

protos-cpp: $(PROTO_GENERATED_CC)

$(PROTO_GENERATED_CC) $(PROTO_HEADERS): $(PROTO_SRC)
	@echo "--- Generating Protobuf/gRPC C++ files ---"
	$(PROTOC) --grpc_out=. --cpp_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $(PROTO_SRC)

protos-js: npm-install $(PROTO_GENERATED_JS)

$(PROTO_GENERATED_JS): $(PROTO_SRC)
	@echo "--- Generating Protobuf/gRPC JavaScript files using local toolchain ---"
	@if [ ! -f "$(PROTOC_GEN_GRPC_JS_PLUGIN)" ]; then \
		echo "ERROR: grpc_tools_node_protoc_plugin not found. Did you run 'npm install --save-dev grpc-tools protobufjs'?"; \
		exit 1; \
	fi
	$(PROTOC) \
		--plugin=protoc-gen-js=$(PROTOC_GEN_JS_PLUGIN) \
		--js_out=import_style=commonjs,binary:$(JS_OUT_DIR) \
		$(PROTO_SRC)
	$(PROTOC) \
		--plugin=protoc-gen-grpc=$(PROTOC_GEN_GRPC_JS_PLUGIN) \
		--grpc_out=grpc_js:$(JS_OUT_DIR) \
		$(PROTO_SRC)

all-protos: protos-cpp protos-js

$(BINARY_NAME): protos-cpp $(OBJECTS)
	@echo "--- Linking binary: $(BINARY_NAME) ---"
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.cc
	@echo "--- Compiling $< ---"
	$(CXX) $(CXXFLAGS) -c $< -o $@

home_general.pb.o: home_general.pb.cc $(PROTO_HEADERS)
home_general.grpc.pb.o: home_general.grpc.pb.cc $(PROTO_HEADERS)
home_general_service.o: home_general_service.cc $(PROTO_HEADERS)
main.o: main.cc $(PROTO_HEADERS)

clean:
	rm -f $(BINARY_NAME) $(OBJECTS) $(PROTO_GENERATED_CC) $(PROTO_HEADERS) $(PROTO_GENERATED_JS)
