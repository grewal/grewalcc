#!/bin/bash
# File: services/security-service/build_ebpf.sh

set -e  # Exit on any error

echo "=== eBPF Build Script ==="

# Navigate to the eBPF directory
cd "$(dirname "$0")/ebpf"

echo "Step 1: Building runtime eBPF object file (with debug info)..."
make clean
make runtime

echo "Step 2: Verifying runtime object file was created..."
if [[ ! -f "kernel/xdp_ip_blocker.o" ]]; then
    echo "ERROR: Runtime object file not found!"
    exit 1
fi

echo "Step 3: Running bpf2go with C source (no debug info)..."
cd "../go/ebpfctrl"

# Let bpf2go compile the C source itself, but without -g flag and without -type flag
go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang \
    -target bpfel \
    -go-package ebpfctrl \
    xdp_ip_blocker \
    ../../ebpf/kernel/xdp_ip_blocker.c \
    -- \
    -O2 \
    -target bpf \
    -Wall \
    -I/usr/include/$(uname -m)-linux-gnu \
    -I/usr/include \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-address-of-packed-member \
    -Wno-tautological-compare

echo "Step 4: Verifying generated Go file..."
if [[ -f "xdp_ip_blocker_bpfel.go" ]]; then
    echo "SUCCESS: Generated xdp_ip_blocker_bpfel.go"
    echo "File size: $(wc -l < xdp_ip_blocker_bpfel.go) lines"
else
    echo "ERROR: Go file was not generated!"
    exit 1
fi

echo "=== Build Complete ==="
echo "Key files created:"
echo "1. Runtime object: ../../ebpf/kernel/xdp_ip_blocker.o (WITH debug info)"
echo "2. Generated Go code: xdp_ip_blocker_bpfel.go (from compilation WITHOUT debug info)"
echo ""
echo "Code should load the runtime object file for actual execution."
