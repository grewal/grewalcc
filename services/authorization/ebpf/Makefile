# File: services/security-service/ebpf/Makefile
# VERSION 1.3 - Fixed clang usage and target dependencies

CLANG ?= clang
SOURCE = kernel/xdp_ip_blocker.c

RUNTIME_TARGET = kernel/xdp_ip_blocker.o
B2G_TARGET = kernel/xdp_ip_blocker_b2g.o

# Corrected CFLAGS to point to the actual installed kernel headers directory.
# We get the specific version string using `uname -r` to keep it portable.
# This single path contains the necessary 'linux' and 'uapi/linux' subdirectories.
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS_PATH := /usr/src/linux-headers-$(KERNEL_VERSION)-common/include

BASE_CFLAGS = -O2 -target bpf -Wall \
             -I$(KERNEL_HEADERS_PATH) \
             -I/usr/include/bpf

RUNTIME_CFLAGS = $(BASE_CFLAGS) -g
B2G_CFLAGS = $(BASE_CFLAGS)

.PHONY: all clean runtime b2g

all: runtime b2g

runtime: $(RUNTIME_TARGET)

$(RUNTIME_TARGET): $(SOURCE)
	@echo "  CLANG (runtime) $(SOURCE) -> $@"
	@$(CLANG) $(RUNTIME_CFLAGS) -c $(SOURCE) -o $@

b2g: $(B2G_TARGET)

$(B2G_TARGET): $(SOURCE)
	@echo "  CLANG (bpf2go)  $(SOURCE) -> $@"
	@$(CLANG) $(B2G_CFLAGS) -c $(SOURCE) -o $@

clean:
	@echo "  CLEAN"
	@rm -f $(RUNTIME_TARGET) $(B2G_TARGET)
