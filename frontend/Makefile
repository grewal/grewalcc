# Makefile rules:
# - Lines that are commands executed for a target MUST start with a TAB.
# - Variable assignments, directives ($(info)), conditionals (ifeq/else/endif) MUST start at column 1 (NO TAB).

# Author: Yadwinder Grewal
# Copyright: 2025 Grewal, Inc.

BINARY_NAME = grewal

CXX = g++
# Base CXXFLAGS - Starts at column 1
BASE_CXXFLAGS = -Wall -Wextra -g -std=c++17 -pthread -DNOMINMAX

# --- Protobuf Generation ---
# Variable assignments - Start at column 1
PROTO_SRC = home_general.proto
PROTO_GEN_HDR = home_general.pb.h home_general.grpc.pb.h
PROTO_GEN_CC = home_general.pb.cc home_general.grpc.pb.cc

# Dynamically find protoc and the gRPC plugin using 'which' during variable assignment
PROTOC_PATH := $(shell which protoc)
GRPC_PLUGIN_PATH := $(shell which grpc_cpp_plugin)

# $(info) directives - Start at column 1
$(info --- Found protoc at: $(PROTOC_PATH) ---)
$(info --- Found grpc_cpp_plugin at: $(GRPC_PLUGIN_PATH) ---)

# Conditional directives (ifeq/endif) - Start at column 1
# $(error) directive - Starts at column 1 (but is part of the conditional)
ifeq ($(PROTOC_PATH),)
$(error ERROR: protoc not found in PATH via 'which' during make variable assignment. Is protobuf-compiler installed correctly?)
endif
ifeq ($(GRPC_PLUGIN_PATH),)
$(error ERROR: grpc_cpp_plugin not found in PATH via 'which' during make variable assignment. Is protobuf-compiler-grpc installed correctly?)
endif

# Variables used in the rule - Start at column 1
PROTOC = $(PROTOC_PATH)
GRPC_PLUGIN = $(GRPC_PLUGIN_PATH)

# Variable assignment - Starts at column 1
PKG_CFG_COMPILE_LIBS = \
        grpc++ \
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

# Variable assignment using function/shell - Starts at column 1
PKG_CONFIG_CXXFLAGS := $(foreach lib,$(PKG_CFG_COMPILE_LIBS),$(shell pkg-config --cflags $(lib)))

# $(info) directive - Starts at column 1
$(info --- Calculated PKG_CONFIG_CXXFLAGS ---)
$(info $(PKG_CONFIG_CXXFLAGS))
$(info ------------------------------------)

# Variable assignment - Starts at column 1
CXXFLAGS := $(BASE_CXXFLAGS) $(PKG_CONFIG_CXXFLAGS) -I/usr/include -I.
# $(info) directive - Starts at column 1
$(info --- Final CXXFLAGS to be used ---)
$(info $(CXXFLAGS))
$(info ---------------------------------)

# Variable assignment - Starts at column 1
PKG_CFG_STATIC_LIBS = \
        grpc++ \
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
        libcares \
        mariadb

# Variable assignment - Starts at column 1
RAW_STATIC_PKG_LDFLAGS := $(foreach lib,$(PKG_CFG_STATIC_LIBS),$(shell pkg-config --static --libs $(lib) 2>/dev/null))
STATIC_PKG_LDFLAGS := $(filter-out -lunwind, $(RAW_STATIC_PKG_LDFLAGS))

# $(info) directives - Start at column 1
$(info --- Calculated RAW_STATIC_PKG_LDFLAGS ---)
$(info $(RAW_STATIC_PKG_LDFLAGS))
$(info --- Calculated STATIC_PKG_LDFLAGS (filtered) ---)
$(info $(STATIC_PKG_LDFLAGS))
$(info ---------------------------------------------)

# Variable assignment - Starts at column 1
LDFLAGS := \
        -no-pie \
        -static-libgcc \
        -static-libstdc++ \
        -L/usr/lib/x86_64-linux-gnu \
        -Wl,-Bstatic \
	-lgrpc++ \
        $(STATIC_PKG_LDFLAGS) \
        -Wl,-Bdynamic \
        -lpthread \
        -ldl \
        -lmariadb

# $(info) directive - Starts at column 1
$(info --- Final LDFLAGS to be used ---)
$(info $(LDFLAGS))
$(info --------------------------------)

# Variable assignments - Start at column 1
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
TEST_DEPS_OBJECTS = ../security/security.o
TEST_MAIN_OBJECT = $(TEST_SOURCES:.cc=.o)

GTEST_STATIC_LIBS = gtest_main gtest
RAW_TEST_STATIC_PKG_LDFLAGS := $(foreach lib,$(GTEST_STATIC_LIBS),$(shell pkg-config --static --libs $(lib) 2>/dev/null))
TEST_STATIC_PKG_LDFLAGS := $(filter-out -lunwind, $(RAW_TEST_STATIC_PKG_LDFLAGS))

TEST_LDFLAGS := \
        -no-pie \
        -static-libgcc \
        -static-libstdc++ \
        -L/usr/lib/x86_64-linux-gnu \
        -Wl,-Bstatic \
        $(STATIC_PKG_LDFLAGS) \
        $(TEST_STATIC_PKG_LDFLAGS) \
        -Wl,-Bdynamic \
        -lpthread \
        -ldl \
        -lmariadb

RM = rm -rf

# Target definition - Starts at column 1
.PHONY: all clean test install protos

# Target definition - Starts at column 1
all: $(BINARY_NAME)

# --- Target to generate protobuf files ---
# Target definition - Starts at column 1
protos: $(PROTO_SRC)
# Recipe commands - MUST start with a TAB
	@echo "--- Generating Protobuf/gRPC C++ files from $(PROTO_SRC) ---"
	@echo "  Using protoc: $(PROTOC)"
	@echo "  Using plugin: $(GRPC_PLUGIN)"
	@echo "  Verifying plugin existence with 'ls':"
	@ls -l $(GRPC_PLUGIN) || (echo "!!! ls check failed for $(GRPC_PLUGIN) !!!"; exit 1)
	@echo "  Executing protoc command:"
	$(PROTOC) --grpc_out=. --cpp_out=. --plugin=protoc-gen-grpc=$(GRPC_PLUGIN) $(PROTO_SRC)
	@echo "--- Generated: $(PROTO_GEN_CC) $(PROTO_GEN_HDR) ---"

# --- Main binary target ---
# Target definition - Starts at column 1
$(BINARY_NAME): protos $(OBJECTS)
# Recipe command - MUST start with a TAB
	@echo "--- Linking main binary ($@) ---"
# Conditional directives - Start at column 1
ifeq ($(V),1)
# Recipe command (inside ifeq) - MUST start with a TAB
	$(CXX) $(CXXFLAGS) $(OBJECTS) $(LDFLAGS) -o $@
# Conditional directive - Starts at column 1
else
# Recipe command (inside else) - MUST start with a TAB
	@$(CXX) $(CXXFLAGS) $(OBJECTS) $(LDFLAGS) -o $@
# Conditional directive - Starts at column 1
endif
# Recipe command - MUST start with a TAB
	@echo "--- Binary '$@' linked. Use 'make V=1' for verbose link command. Use 'ldd $@' to check dynamic dependencies ---"

# --- Generic compile rule for .cc to .o ---
# Target definition - Starts at column 1
%.o: %.cc
# Recipe command - MUST start with a TAB
	@echo "--- Compiling $< (Generic Rule) ---"
# Conditional directives - Start at column 1
ifeq ($(V),1)
# Recipe command (inside ifeq) - MUST start with a TAB
	$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
else
# Recipe command (inside else) - MUST start with a TAB
	@$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
endif

# --- Specific rules for files in other directories ---
# Target definition - Starts at column 1
../security/security.o: ../security/security.cc ../security/security.h
# Recipe command - MUST start with a TAB
	@echo "--- Compiling $< (Specific Rule) ---"
# Conditional directives - Start at column 1
ifeq ($(V),1)
# Recipe command (inside ifeq) - MUST start with a TAB
	$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
else
# Recipe command (inside else) - MUST start with a TAB
	@$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
endif

# Target definition - Starts at column 1
../db/mysql_util.o: ../db/mysql_util.cc ../db/mysql_util.h
# Recipe command - MUST start with a TAB
	@echo "--- Compiling $< (Specific Rule) ---"
# Conditional directives - Start at column 1
ifeq ($(V),1)
# Recipe command (inside ifeq) - MUST start with a TAB
	$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
else
# Recipe command (inside else) - MUST start with a TAB
	@$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
endif

# --- Explicit dependencies for objects on headers (especially generated) ---
# These are dependency lines, part of target definitions - Start at column 1
main.o: main.cc home_general.pb.h home_general.grpc.pb.h home_general_service.h
home_general_service.o: home_general_service.cc home_general.pb.h home_general.grpc.pb.h home_general_service.h
home_general.pb.o: home_general.pb.cc home_general.pb.h
home_general.grpc.pb.o: home_general.grpc.pb.cc home_general.grpc.pb.h
../security/security.o: ../security/security.h
../db/mysql_util.o: ../db/mysql_util.h

# --- Test target ---
# Target definition - Starts at column 1
test: $(TEST_BINARY)
# Recipe command - MUST start with a TAB
	./$(TEST_BINARY)

# Target definition - Starts at column 1
$(TEST_BINARY): $(TEST_MAIN_OBJECT) $(TEST_DEPS_OBJECTS)
# Recipe command - MUST start with a TAB
	@echo "--- Linking test binary ($@) ---"
# Conditional directives - Start at column 1
ifeq ($(V),1)
# Recipe command (inside ifeq) - MUST start with a TAB
	$(CXX) $(CXXFLAGS) $^ $(TEST_LDFLAGS) -o $@
# Conditional directive - Starts at column 1
else
# Recipe command (inside else) - MUST start with a TAB
	@$(CXX) $(CXXFLAGS) $^ $(TEST_LDFLAGS) -o $@
# Conditional directive - Starts at column 1
endif
# Recipe command - MUST start with a TAB
	@echo "--- Binary '$@' linked. Use 'make V=1' for verbose link command. Use 'ldd $@' to check dynamic dependencies ---"

# Target definition - Starts at column 1
$(TEST_MAIN_OBJECT): $(TEST_SOURCES) ../security/security.h
# Recipe command - MUST start with a TAB
	@echo "--- Compiling $< (Test Main Rule) ---"
# Conditional directives - Start at column 1
ifeq ($(V),1)
# Recipe command (inside ifeq) - MUST start with a TAB
	$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
else
# Recipe command (inside else) - MUST start with a TAB
	@$(CXX) $(CXXFLAGS) -c $< -o $@
# Conditional directive - Starts at column 1
endif

# --- Clean target ---
# Target definition - Starts at column 1
clean:
# Recipe command - MUST start with a TAB
	$(RM) $(BINARY_NAME) $(OBJECTS) $(TEST_BINARY) $(TEST_MAIN_OBJECT) *.d $(PROTO_GEN_CC) $(PROTO_GEN_HDR) ../security/security.o ../db/mysql_util.o

# --- Install target (remains manual indicator) ---
# Target definition - Starts at column 1
install: $(BINARY_NAME)
# Recipe commands - MUST start with a TAB
	@echo "Install target is for manual testing/setup only."
	@echo "Production deployment uses CI/CD."
