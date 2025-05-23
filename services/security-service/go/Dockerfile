FROM golang:1.23-alpine AS builder

ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /app

COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/. ./
RUN go build -ldflags="-s -w" -o /authz-service .

FROM alpine:latest AS ebpf
WORKDIR /ebpf
COPY ebpf/kernel/xdp_ip_blocker.o /ebpf/xdp_ip_blocker.o

FROM alpine:latest

WORKDIR /app
COPY --from=builder /authz-service /app/authz-service
COPY --from=ebpf /ebpf/xdp_ip_blocker.o /app/ebpf/kernel/xdp_ip_blocker.o

EXPOSE 9001 9002
ENTRYPOINT ["/app/authz-service"]
CMD []
