# Author: Yadwinder Grewal
# Copyright: 2024 Grewal, Inc.

BINARY_NAME = grewal
CC = cc
CXX = g++
OBJS = main.o security.o sanitizer.o
CXXFILES = main.cc ../security/security.cc ../security/sanitizer.cc
INCLUDE_PATH = -I/usr/local/include -I/usr/include/mysql
CFLAGS = -Wall -c -v -g
COMPILE_FLAGS = -c -v -std=c++1z -Wall
LDFLAGS = -lfcgi -lfcgi++ -lmysqlclient
GOOGLE_FLAGS = -lre2 -lpthread -lcrypto -lssl
NGINX_BIN = /etc/nginx/sbin
REMOVE = rm -rf

$(BINARY_NAME) : $(OBJS)
	# Compile the binary
	$(CXX) $(OBJS) $(LDFLAGS) $(GOOGLE_FLAGS) -o $(@)

%.o:	%.cc
	$(CXX) $(COMPILE_FLAGS) $(GOOGLE_FLAGS) $(CXXFILES) $(INCLUDE_PATH) $<

%.o:	%.c
	$(CC) $(CFLAGS) $(CFILES) $(INCLUDE_PATH)

clean :
	$(REMOVE) $(BINARY_NAME)
	$(REMOVE) $(OBJS)

install :
	cp $(BINARY_NAME) $(NGINX_BIN)
