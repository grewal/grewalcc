# Author: Yadwinder Grewal
# Copyright: 2025 Grewal, Inc.

BINARY_NAME = grewal

CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17

# --- Protobuf Generation ---
PROTO_SRC = home_general.proto
PROTO_GEN_HDR = home_general.pb.h home_general.grpc.pb.h
PROTO_GEN_CC = home_general.pb.cc home_general.grpc.pb.cc
PROTOC = protoc
GRPC_PLUGIN = $(shell which grpc_cpp_plugin)

# List of packages needed for include paths
PKG_CFG_INCLUDE_LIBS = \
	grpc++ \
	grpc \
	protobuf \
	re2 \
	gflags \
	libctemplate_nothreads \
	libglog \
	absl_base \
	absl_flags \
	absl_strings \
	openssl \
	liblzma

INCLUDE_DIRS := $(shell pkg-config --cflags-only-I $(PKG_CFG_INCLUDE_LIBS)) \
	.
INCLUDE_PATH = $(patsubst %,-I%,$(INCLUDE_DIRS))

# List of packages needed for static linking flags
PKG_CFG_STATIC_LIBS = \
	grpc++ \
	grpc \
	protobuf \
	re2 \
	gflags \
	libctemplate_nothreads \
	libglog \
	absl_base \
	absl_flags \
	absl_strings \
	openssl \
	zlib \
	liblzma \
	libcares

RAW_STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(PKG_CFG_STATIC_LIBS))
STATIC_PKG_LDFLAGS := $(filter-out -lunwind, $(RAW_STATIC_PKG_LDFLAGS))

LDFLAGS = \
	-no-pie \
	-static-libgcc \
	-static-libstdc++ \
	-L/usr/lib/x86_64-linux-gnu \
	-Wl,-Bstatic \
	$(STATIC_PKG_LDFLAGS) \
	-Wl,-Bdynamic \
	-lpthread \
	-ldl

# List sources - includes the generated .cc files
CXX_SOURCES = \
	main.cc \
	../security/security.cc \
	../db/mysql_util.cc \
	$(PROTO_GEN_CC) \
	home_general_service.cc

CXX_OBJECTS = $(CXX_SOURCES:.cc=.o)
OBJECTS = $(CXX_OBJECTS)

# --- Test Related Definitions ---
TEST_BINARY = security_test
TEST_SOURCES = ../security/security_test.cc
# Assuming security.o is the only dependency needed besides the test source itself
TEST_DEPS_OBJECTS = ../security/security.o
TEST_MAIN_OBJECT = $(TEST_SOURCES:.cc=.o)

GTEST_STATIC_LIBS = gtest_main gtest
RAW_TEST_STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(GTEST_STATIC_LIBS))
TEST_STATIC_PKG_LDFLAGS := $(filter-out -lunwind, $(RAW_TEST_STATIC_PKG_LDFLAGS))

TEST_LDFLAGS = \
	-no-pie \
	-static-libgcc \
	-static-libstdc++ \
	-L/usr/lib/x86_64-linux-gnu \
	-Wl,-Bstatic \
	$(STATIC_PKG_LDFLAGS) \
	$(TEST_STATIC_PKG_LDFLAGS) \
	-Wl,-Bdynamic \
	-lpthread \
	-ldl

RM = rm -rf

.PHONY: all clean test install protos

# Default target
all: $(BINARY_NAME)

# --- Target to generate protobuf files ---
# Ensure this target explicitly lists the files it creates
protos: $(PROTO_SRC)
	@echo "--- Generating Protobuf/gRPC C++ files from $(PROTO_SRC) ---"
	@if [ -z "$(GRPC_PLUGIN)" ]; then \
	echo "ERROR: grpc_cpp_plugin not found. Is protobuf-compiler-grpc installed?"; \
	exit 1; \
	fi
	$(PROTOC) --grpc_out=. --cpp_out=. --plugin=protoc-gen-grpc=$(GRPC_PLUGIN) $(PROTO_SRC)
	@echo "--- Generated: $(PROTO_GEN_CC) $(PROTO_GEN_HDR) ---"

# --- Main binary target ---
# Depends on 'protos' first, then the object files.
$(BINARY_NAME): protos $(OBJECTS)
	@echo "--- Linking main binary ($@) ---"
	# *** CORRECTED: Use $(OBJECTS) directly, not $^ ***
	$(CXX) $(CXXFLAGS) $(OBJECTS) $(LDFLAGS) -o $@
	@echo "--- Binary '$@' linked. Use 'ldd $@' to check dynamic dependencies ---"

# --- Generic compile rule for .cc to .o ---
# This rule should handle all .cc files unless overridden by a specific rule below
%.o: %.cc
	@echo "--- Compiling $< (Generic Rule) ---"
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

# --- Specific rules for files in other directories ---
../security/security.o: ../security/security.cc ../security/security.h
	@echo "--- Compiling $< (Specific Rule) ---"
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

../db/mysql_util.o: ../db/mysql_util.cc ../db/mysql_util.h
	@echo "--- Compiling $< (Specific Rule) ---"
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

# --- Explicit dependencies for objects on headers (especially generated) ---
# These tell 'make' when an object needs recompiling because a header changed.
# The generic %.o: %.cc rule is still used for *how* to compile them.
main.o: main.cc $(PROTO_GEN_HDR) home_general_service.h
home_general_service.o: home_general_service.cc $(PROTO_GEN_HDR) home_general_service.h
home_general.pb.o: home_general.pb.cc home_general.pb.h
home_general.grpc.pb.o: home_general.grpc.pb.cc home_general.grpc.pb.h $(PROTO_GEN_HDR)
../security/security.o: ../security/security.h # Add dependency on its own header
../db/mysql_util.o: ../db/mysql_util.h     # Add dependency on its own header

# --- Test target ---
test: $(TEST_BINARY)
	./$(TEST_BINARY)

$(TEST_BINARY): $(TEST_MAIN_OBJECT) $(TEST_DEPS_OBJECTS)
	@echo "--- Linking test binary ($@) ---"
	$(CXX) $(CXXFLAGS) $^ $(TEST_LDFLAGS) -o $@ # $^ is okay here (main obj + dep obj)
	@echo "--- Binary '$@' linked. Use 'ldd $@' to check dynamic dependencies ---"

# Test main object needs its source and potentially headers it includes
$(TEST_MAIN_OBJECT): $(TEST_SOURCES) ../security/security.h
	@echo "--- Compiling $< (Test Main Rule) ---"
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

# --- Clean target ---
# Now also removes generated proto files
clean:
	$(RM) $(BINARY_NAME) $(OBJECTS) $(TEST_BINARY) $(TEST_MAIN_OBJECT) *.d $(PROTO_GEN_CC) $(PROTO_GEN_HDR) ../security/security.o ../db/mysql_util.o $(TEST_MAIN_OBJECT) # Be thorough

# --- Install target (remains manual indicator) ---
install: $(BINARY_NAME)
	@echo "Install target is for manual testing/setup only."
	@echo "Production deployment uses CI/CD."
