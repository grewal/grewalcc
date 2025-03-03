# Author: Yadwinder Grewal
# Copyright: 2024 Grewal, Inc.

BINARY_NAME = grewal
CC = cc
CXX = g++
OBJS = main.o security.o mysql_util.o
CXXFILES = main.cc ../security/security.cc ../db/mysql_util.cc
CFILES = 
INCLUDE_PATH = -I/usr/local/include -I/home/monty/src/gcc/third_party/mariadb/connector/include/
CFLAGS = -Wall -c -v -g
COMPILE_FLAGS = -c -v -Wall
LDFLAGS = -lfcgi -lfcgi++ -L/home/monty/src/gcc/third_party/mariadb/connector/lib/mariadb -lmariadbcpp
GOOGLE_FLAGS = -lre2 -lpthread -lcrypto -lssl -lgflags
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

# Install the binary to NGINX_BIN
install:
	sudo killall $(BINARY_NAME)
	cp $(BINARY_NAME) $(NGINX_BIN)
