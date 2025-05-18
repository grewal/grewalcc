# Stage 1: Build Go binary
FROM golang:1.23-alpine AS builder

ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /app

# Copy from go subdirectory
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/. .
RUN go build -ldflags="-s -w" -o /authz-service .

# Stage 2: Prepare eBPF assets
FROM alpine:latest AS ebpf
WORKDIR /ebpf
COPY ebpf/kernel/xdp_ip_blocker.o /ebpf/

# Stage 3: Final image
FROM alpine:latest
WORKDIR /app

# Copy binaries
COPY --from=builder /authz-service /app/
# Create directory and copy eBPF
RUN mkdir -p /app/ebpf/kernel
COPY --from=ebpf /ebpf/xdp_ip_blocker.o /app/ebpf/kernel/

EXPOSE 9001 9002
ENTRYPOINT ["/app/authz-service"]
