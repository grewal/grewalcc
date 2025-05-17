# Dockerfile for the Grewal Security Service (authz)

# --- Stage 1: Build ---
# Use an official Go image with Alpine Linux as the base.
# Specify the Go version matching your go.mod file (adjust if needed).
FROM golang:1.23-alpine AS builder

# Set necessary environment variables for static linking
ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code.
COPY . .

# Build the application statically.
# -ldflags="-s -w" strips debug information and symbols, reducing binary size.
# -o /authz-service specifies the output path for the executable.
RUN go build -ldflags="-s -w" -o /authz-service .

# --- Stage 2: Final Image ---
# Use a minimal Alpine image as the final base.
FROM alpine:latest

# Optional: Install root certificates if your app needs to make HTTPS calls
# RUN apk update && apk add --no-cache ca-certificates

WORKDIR /app

# Copy the compiled executable from the builder stage.
COPY --from=builder /authz-service /app/authz-service

# Optional but recommended: Run as a non-root user
# Create a non-root user and group
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# Switch to the non-root user
# USER appuser

# Expose the port the application listens on (informational).
EXPOSE 9001 9002

# Define the entrypoint for the container.
ENTRYPOINT ["/app/authz-service"]

# Default command (can be overridden). Often empty when using ENTRYPOINT exec form.
CMD []
