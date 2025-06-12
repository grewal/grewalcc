# File: services/security-service/ebpf/Makefile
CLANG ?= clang
SOURCE = kernel/xdp_ip_blocker.c

RUNTIME_TARGET = kernel/xdp_ip_blocker.o
B2G_TARGET = kernel/xdp_ip_blocker_b2g.o

BASE_CFLAGS = -O2 -target bpf -Wall \
             -I/usr/include/x86_64-linux-gnu \
             -I/usr/include

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
