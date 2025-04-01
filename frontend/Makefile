# Author: Yadwinder Grewal
# Copyright: 2025 Grewal, Inc.

# --- Configuration ---
BINARY_NAME = grewal
GIT_CLIENT = gcc-gem-a # Informational

# --- Compiler and Flags ---
CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17

# --- Include Paths ---
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

# --- Libraries for Static Linking ---
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
    liblzma

STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(PKG_CFG_STATIC_LIBS))

# --- Linker Flags (LDFLAGS) ---
LDFLAGS = \
    -no-pie \
    -static-libstdc++ \
    -Wl,-Bstatic \
    $(STATIC_PKG_LDFLAGS) \
    -lunwind \
    -Wl,-Bdynamic \
    -lpthread \
    -ldl

# --- Source Files ---
CXX_SOURCES = \
    main.cc \
    ../security/security.cc \
    ../db/mysql_util.cc \
    home_general.pb.cc \
    home_general.grpc.pb.cc \
    home_general_service.cc

CXX_OBJECTS = $(CXX_SOURCES:.cc=.o)
OBJECTS = $(CXX_OBJECTS)

# --- Test Configuration ---
TEST_BINARY = security_test
TEST_SOURCES = ../security/security_test.cc
TEST_DEPS_OBJECTS = ../security/security.o
TEST_MAIN_OBJECT = $(TEST_SOURCES:.cc=.o)

GTEST_STATIC_LIBS = gtest_main gtest
TEST_STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(GTEST_STATIC_LIBS))

TEST_LDFLAGS = \
    $(LDFLAGS) \
    -Wl,-Bstatic \
    $(TEST_STATIC_PKG_LDFLAGS) \
    -Wl,-Bdynamic

# --- Utility Commands ---
RM = rm -rf

# --- Targets ---
.PHONY: all clean test install

all: $(BINARY_NAME)

$(BINARY_NAME): $(OBJECTS)
	@echo "--- Linking main binary ($@) ---"
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@
	@echo "--- Binary '$@' linked. Use 'ldd $@' to check dynamic dependencies ---"

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

../security/security.o: ../security/security.cc ../security/security.h
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

../db/mysql_util.o: ../db/mysql_util.cc # Add header dependency if exists
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

test: $(TEST_BINARY)
	./$(TEST_BINARY)

$(TEST_BINARY): $(TEST_MAIN_OBJECT) $(TEST_DEPS_OBJECTS)
	@echo "--- Linking test binary ($@) ---"
	$(CXX) $(CXXFLAGS) $^ $(TEST_LDFLAGS) -o $@
	@echo "--- Binary '$@' linked. Use 'ldd $@' to check dynamic dependencies ---"

$(TEST_MAIN_OBJECT): $(TEST_SOURCES) ../security/security.h
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

clean:
	$(RM) $(BINARY_NAME) $(OBJECTS) $(TEST_BINARY) $(TEST_MAIN_OBJECT) *.d

install: $(BINARY_NAME)
	@echo "Install target is intended for manual testing/setup."
	@echo "Production deployment uses CI/CD (scp/ssh actions)."
	# sudo killall $(BINARY_NAME) # Use 'systemctl stop' instead via deployment script
	# sudo cp $(BINARY_NAME) /usr/local/bin/ # More standard location than /etc/nginx/sbin
	# sudo chown root:root /usr/local/bin/$(BINARY_NAME)
	# sudo chmod 755 /usr/local/bin/$(BINARY_NAME)
	@echo "Consider copying to /usr/local/bin/ and using systemd unit file."
