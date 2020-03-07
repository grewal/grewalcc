# Author: Yadwinder Grewal
# Copyright: 2020 Grewal, Inc.

BINARY_NAME = grewal 
CXX = g++
OBJS = main.o
CXXFILES = main.cc
INCLUDE_PATH = -I/usr/local/include
COMPILE_FLAGS = -c -v -std=c++1z -Wall
LDFLAGS = -lfcgi -lfcgi++
NGINX_BIN = /etc/nginx/sbin
REMOVE = rm -rf

$(BINARY_NAME) : $(OBJS)
	# Compile the binary
	$(CXX) $(OBJS) $(LDFLAGS) -o $(@)

%.o:	%.cc
	$(CXX) $(COMPILE_FLAGS) $<

clean :
	$(REMOVE) $(BINARY_NAME)
	$(REMOVE) $(OBJS)

install :
	cp $(BINARY_NAME) $(NGINX_BIN)
