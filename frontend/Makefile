# Author: Yadwinder Grewal
# Copyright: 2024 Grewal, Inc.

# --- Configuration ---

BINARY_NAME = grewal
GIT_CLIENT = gcc-gem-a

# --- Compiler and Flags ---

CC = cc
CXX = g++  # Use clang++ for C++ projects
CXXFLAGS = -Wall -Wextra -g -std=c++17  # Enable warnings, debug info, and C++17

# --- Include Paths ---
# Use pkg-config for gRPC include paths.
INCLUDE_DIRS := $(shell pkg-config --cflags-only-I grpc++) \
		.  # Don't forget the current directory!

INCLUDE_PATH = $(INCLUDE_DIRS)

# --- Library Paths ---
# We *don't* need to list standard library paths explicitly.  The compiler knows them.
# We'll let pkg-config handle the gRPC library paths.

# --- Libraries (Critical Order) ---
# Let pkg-config handle *all* gRPC-related libraries. This is the key change.

# Get ALL linker flags from pkg-config, including -L, -l, and -Wl flags.
GRPC_LDFLAGS := $(shell pkg-config --libs grpc++ grpc protobuf)

# Other libraries (FastCGI, MariaDB, etc.) - order *still* matters!
# REMOVE fcgi++ and fcgi if this is ONLY for the gRPC server
OTHER_LIBS = \
		re2 \
		gflags \
		ctemplate_nothreads \
		ssl \
		crypto \
		pthread \
		gtest

# Combine gRPC linker flags with our other libraries, and add stdc++ LAST.
# REMOVE fcgi++ and fcgi from LDFLAGS if this is ONLY for the gRPC server
LDFLAGS = $(GRPC_LDFLAGS) $(addprefix -l,$(OTHER_LIBS)) -lstdc++

# --- Source Files ---

CXX_SOURCES = \
		main.cc \
		../security/security.cc \
		../db/mysql_util.cc \
		home_general.pb.cc \
		home_general.grpc.pb.cc \
		home_general_service.cc

CXX_OBJECTS = $(CXX_SOURCES:.cc=.o)

C_SOURCES =  # You don't have any C sources, leave this empty
C_OBJECTS = $(C_SOURCES:.c=.o)

OBJECTS = $(CXX_OBJECTS) $(C_OBJECTS)

# --- Test Configuration ---

TEST_BINARY = security_test
TEST_SOURCES = ../security/security_test.cc
TEST_OBJECTS = $(TEST_SOURCES:.cc=.o)

# --- Installation Configuration ---
NGINX_BIN = /etc/nginx/sbin

# --- Utility Commands ---

RM = rm -rf

# --- Targets ---

.PHONY: all clean install test

all: $(BINARY_NAME)

# Build the main executable (use LDFLAGS for *all* linker flags)
$(BINARY_NAME): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

# General rule for compiling .cc files to .o files
%.o: %.cc
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

# General rule for compiling .c files to .o files (if you have any - you don't)
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -c $< -o $@

# --- Test Targets ---

test: $(TEST_BINARY)
	./$(TEST_BINARY)

# Test executable linking (also use LDFLAGS)
$(TEST_BINARY): $(TEST_OBJECTS) ../security/security.o
	$(CXX) $^ $(LDFLAGS) -lgtest -lgtest_main -o $@

$(TEST_OBJECTS): %.o : %.cc ../security/security.h
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

# --- Clean and Install ---

clean:
	$(RM) $(BINARY_NAME) $(OBJECTS) $(TEST_BINARY)

install:
	sudo killall $(BINARY_NAME)  # Be VERY careful with killall!
	sudo cp $(BINARY_NAME) $(NGINX_BIN)
