# Author: Yadwinder Grewal
# Copyright: 2025 Grewal, Inc.

BINARY_NAME = grewal

CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17

# List of packages needed for include paths (doesn't need c-ares usually)
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

# Get static library flags from pkg-config for the listed packages
# Filter out -lunwind because we use the one from -static-libgcc to avoid conflict
RAW_STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(PKG_CFG_STATIC_LIBS))
STATIC_PKG_LDFLAGS := $(filter-out -lunwind, $(RAW_STATIC_PKG_LDFLAGS))


# Define main linker flags
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

CXX_SOURCES = \
    main.cc \
    ../security/security.cc \
    ../db/mysql_util.cc \
    home_general.pb.cc \
    home_general.grpc.pb.cc \
    home_general_service.cc

CXX_OBJECTS = $(CXX_SOURCES:.cc=.o)
OBJECTS = $(CXX_OBJECTS)

TEST_BINARY = security_test
TEST_SOURCES = ../security/security_test.cc
TEST_DEPS_OBJECTS = ../security/security.o
TEST_MAIN_OBJECT = $(TEST_SOURCES:.cc=.o)

# Define dependencies for tests (might need similar static libs)
GTEST_STATIC_LIBS = gtest_main gtest
RAW_TEST_STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(GTEST_STATIC_LIBS))
# Filter -lunwind from gtest dependencies too, just in case
TEST_STATIC_PKG_LDFLAGS := $(filter-out -lunwind, $(RAW_TEST_STATIC_PKG_LDFLAGS))

# Define linker flags for tests, using filtered static libs
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

../db/mysql_util.o: ../db/mysql_util.cc ../db/mysql_util.h
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
	@echo "Install target is for manual testing/setup only."
	@echo "Production deployment uses CI/CD."
