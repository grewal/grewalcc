# Author: Yadwinder Grewal
# Copyright: 2024 Grewal, Inc.

BINARY_NAME = grewal
CC = cc
CXX = g++
OBJS = main.o security.o mysql_util.o
GIT_CLIENT = gcc-gem-a
CXXFILES = main.cc ../security/security.cc ../db/mysql_util.cc
CFILES = 
INCLUDE_PATH = -I/usr/include -I/usr/local/include -I/home/monty/src/$(GIT_CLIENT)/third_party/mariadb/connector/include/ -I/usr/local/include/gtest
CFLAGS = -Wall -c -v -g
COMPILE_FLAGS = -c -v -Wall
LDFLAGS = -lfcgi -lfcgi++ -L/usr/lib/ -L/home/monty/src/$(GIT_CLIENT)/third_party/mariadb/connector/lib/mariadb -lmariadbcpp -lpthread
GOOGLE_FLAGS = -lre2 -lcrypto -lssl -lgflags -lctemplate_nothreads -lgtest
NGINX_BIN = /etc/nginx/sbin
REMOVE = rm -rf

# Default target to build the binary
$(BINARY_NAME): $(OBJS)
	# Compile the binary
	$(CXX) $(OBJS) $(LDFLAGS) $(GOOGLE_FLAGS) -o $@

# Rule to compile .cc files to .o
%.o: %.cc
	$(CXX) $(COMPILE_FLAGS) $(CXXFILES) $(GOOGLE_FLAGS) $(INCLUDE_PATH) $<

# Rule to compile .c files to .o
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_PATH) $<

# Clean the project
clean:
	$(REMOVE) $(BINARY_NAME)
	$(REMOVE) $(OBJS)
	$(REMOVE) security_test*

# Install the binary to NGINX_BIN
install:
	sudo killall $(BINARY_NAME)
	cp $(BINARY_NAME) $(NGINX_BIN)

# Build and run the tests
test: security_test
	./security_test

# Compile the test binary
security_test: security_test.o security.o
	$(CXX) security_test.o security.o $(GOOGLE_FLAGS) -lgtest -lgtest_main -pthread -o $@

# Rule to compile the security_test.cc into an object file
security_test.o: ../security/security_test.cc ../security/security.h
	$(CXX) $(COMPILE_FLAGS) $(INCLUDE_PATH) $<
