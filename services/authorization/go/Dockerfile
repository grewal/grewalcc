# FILE: services/authorization/go/Dockerfile
# Production-grade multi-stage Dockerfile for Phoenix authorization service
# This container runs with minimal attack surface and follows security best practices.

# --- Stage 1: Go Builder ---
# Use Go 1.24+ for the latest cilium/ebpf library features and performance improvements.
FROM golang:1.24-alpine AS builder

# Install build-time dependencies for eBPF C compilation.
# clang: C compiler for eBPF programs
# llvm: Required by clang for eBPF target support
# build-base: Provides standard C build tools
# linux-headers: Provides kernel headers for bpf2go
# libbpf-dev: (FIX) Provides the critical <bpf/bpf_helpers.h> and other libbpf headers.
RUN apk add --no-cache \
    build-base \
    clang \
    llvm \
    linux-headers \
    libbpf-dev

WORKDIR /app

# Copy module files first to leverage Docker's layer caching.
# This step is only re-run if go.mod or go.sum changes.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the entire service source code into the builder.
COPY . .

# Compile the eBPF C code and generate the Go wrapper.
# This executes the //go:generate directive in kernel/bpf.go.
RUN go generate ./...

# Build the final, statically-linked Go binary for a minimal container.
# CGO_ENABLED=0: Creates a pure Go binary with no C dependencies.
# -s -w: Linker flags to strip debug symbols and DWARF info, reducing binary size.
# -trimpath: Remove file system paths from the binary for reproducible builds.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o /authz-service .

# --- Stage 2: Final Runtime Image ---
# Use Google's distroless image for minimal attack surface.
# This image contains only the bare essentials to run the Go binary.
FROM gcr.io/distroless/static-debian12:nonroot

# Labels for container metadata (useful for orchestration and auditing)
LABEL maintainer="ygrewal@gmail.com" \
      description="Grewal.cc Security Control Plane" \
      version="2.0-final" \
      security.policy="kernel-first-defense"

# Copy the compiled Go binary from the builder stage.
COPY --from=builder /authz-service /authz-service

# The distroless nonroot image runs as UID 65532 by default.
# No need to explicitly set USER as the base image handles this.

# Expose the gRPC and metrics/health ports.
EXPOSE 9001 9090

# Define the command to run the service.
# Using ENTRYPOINT is a best practice for containers.
ENTRYPOINT ["/authz-service"]

# CMD provides default arguments to the ENTRYPOINT, which can be overridden at runtime.
CMD ["--grpc-addr=:9001", "--http-addr=:9090"]
