# FILE: go/Dockerfile
# Assumes eBPF object and Go bindings are pre-generated and in the repository.

# --- Stage 1: Go Builder ---
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy Go module files and download dependencies
COPY go/go.mod go/go.sum ./
RUN go mod download

# Copy the rest of the Go source code.
COPY go/. ./

# Build the final Go binary. No bpf2go or C compilation needed here.
RUN go build -ldflags="-s -w" -o /authz-service .


# --- Stage 2: Final Runtime Image ---
FROM alpine:latest

RUN apk add --no-cache ca-certificates

# Copy the Go binary from the builder stage
COPY --from=builder /authz-service /usr/local/bin/authz-service

# Copy the pre-compiled eBPF object file
COPY ebpf/kernel/xdp_ip_blocker.o /app/ebpf/kernel/xdp_ip_blocker.o

# Set default environment variables
ENV XDP_GLOBAL_ENABLED=true
ENV XDP_INTERFACE_NAME=ens4

EXPOSE 9001 9002

CMD ["/usr/local/bin/authz-service"]
