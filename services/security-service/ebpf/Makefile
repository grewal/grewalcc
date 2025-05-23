# File: services/security-service/ebpf/Makefile
CLANG ?= clang
BPF_TARGET_ARCH ?= bpf
TARGET = kernel/xdp_ip_blocker.o
SOURCE = kernel/xdp_ip_blocker.c

CFLAGS = -O2 -g -target $(BPF_TARGET_ARCH) -Wall \
         -I/usr/include/$(shell uname -m)-linux-gnu \
         -I/usr/include \
         -Wno-unused-value -Wno-pointer-sign \
         -Wno-compare-distinct-pointer-types \
         -Wno-address-of-packed-member \
         -Wno-tautological-compare

all: $(TARGET)

$(TARGET): $(SOURCE)
	@echo "  CLANG $(SOURCE) -> $@"
	@$(CLANG) $(CFLAGS) -c $(SOURCE) -o $@

clean:
	@echo "  CLEAN"
	@rm -f $(TARGET)
	@rm -f *.ll *.bc

.PHONY: all clean
