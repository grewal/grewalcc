# Author: Yadwinder Grewal
# Copyright: 2024 Grewal, Inc.

# Project Configuration
BINARY_NAME = grewal
GIT_CLIENT = gcc-gem-a

# Compiler and Flags
CC = cc
CXX = g++
CFLAGS = -Wall -c -v -g
CXXFLAGS = -Wall -c -v

# Include Paths
INCLUDE_DIRS = \
	/usr/include \
	/usr/local/include \
	/home/monty/src/$(GIT_CLIENT)/third_party/mariadb/connector/include/ \
	/usr/local/include/gtest \
	/usr/local/include/grpc

INCLUDE_PATH = $(addprefix -I,$(INCLUDE_DIRS))

# Library Paths and Libraries
LIBRARY_DIRS = \
	/usr/lib/ \
	/home/monty/src/$(GIT_CLIENT)/third_party/mariadb/connector/lib/mariadb \
	/usr/local/lib

LIBRARY_PATH = $(addprefix -L,$(LIBRARY_DIRS))

LIBRARIES = \
	fcgi \
	fcgi++ \
	mariadbcpp \
	pthread \
	re2 \
	crypto \
	ssl \
	gflags \
	ctemplate_nothreads \
	gtest \
	grpc++ \
	protobuf

LDFLAGS = $(LIBRARY_PATH) $(addprefix -l,$(LIBRARIES))

# Source Files and Objects
CXX_SOURCES = \
	main.cc \
	../security/security.cc \
	../db/mysql_util.cc \
	home_general.pb.cc \
	home_general.grpc.pb.cc

CXX_OBJECTS = $(CXX_SOURCES:.cc=.o)

C_SOURCES =
C_OBJECTS = $(C_SOURCES:.c=.o)

OBJECTS = $(CXX_OBJECTS) $(C_OBJECTS)

# Test Configuration
TEST_BINARY = security_test
TEST_SOURCES = ../security/security_test.cc
TEST_OBJECTS = $(TEST_SOURCES:.cc=.o)

# Installation Configuration
NGINX_BIN = /etc/nginx/sbin

# Utility Commands
RM = rm -rf

# Targets

.PHONY: all clean install test

all: $(BINARY_NAME)

$(BINARY_NAME): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -c $< -o $@

clean:
	$(RM) $(BINARY_NAME) $(OBJECTS) $(TEST_BINARY)

install:
	sudo killall $(BINARY_NAME)
	sudo cp $(BINARY_NAME) $(NGINX_BIN)

test: $(TEST_BINARY)
	./$(TEST_BINARY)

$(TEST_BINARY): $(TEST_OBJECTS) ../security/security.o
	$(CXX) $(TEST_OBJECTS) ../security/security.o $(LDFLAGS) -lgtest -lgtest_main -pthread -o $@

$(TEST_OBJECTS): %.o: %.cc ../security/security.h
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATH) -c $< -o $@
