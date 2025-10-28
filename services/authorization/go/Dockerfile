# FILE: go/Dockerfile

# --- Stage 1: Go Builder ---
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY services/authorization/go/go.mod services/authorization/go/go.sum ./
RUN go mod download

COPY services/authorization/go/ ./

# Build the final Go binary. The 'go:embed' directive will handle the .o file.
RUN go build -ldflags="-s -w" -o /authz-service .


# --- Stage 2: Final Runtime Image ---
FROM alpine:latest

RUN apk add --no-cache ca-certificates

# Copy the Go binary from the builder stage
COPY --from=builder /authz-service /usr/local/bin/authz-service

# Set default environment variables
ENV XDP_GLOBAL_ENABLED=true
ENV XDP_INTERFACE_NAME=ens4

EXPOSE 9001 9002

CMD ["/usr/local/bin/authz-service"]
