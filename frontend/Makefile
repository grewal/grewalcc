# Author: Yadwinder Grewal
# Copyright: 2025 Grewal, Inc.

BINARY_NAME = grewal

CXX = g++
CXXFLAGS = -Wall -Wextra -g -std=c++17

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

LDFLAGS = \
    -no-pie \
    -static-libstdc++ \
    -Wl,-Bstatic \
    $(STATIC_PKG_LDFLAGS) \
    -lunwind \
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

GTEST_STATIC_LIBS = gtest_main gtest
TEST_STATIC_PKG_LDFLAGS := $(shell pkg-config --static --libs $(GTEST_STATIC_LIBS))

TEST_LDFLAGS = \
    $(LDFLAGS) \
    -Wl,-Bstatic \
    $(TEST_STATIC_PKG_LDFLAGS) \
    -Wl,-Bdynamic

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

../db/mysql_util.o: ../db/mysql_util.cc
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
