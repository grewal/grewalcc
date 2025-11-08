# --- Stage 1: The Builder ---
FROM golang:1.23-alpine AS builder

# Set the working directory inside the container.
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the binary. The key flags are:
# - CGO_ENABLED=0: This creates a truly static binary with no C library dependencies (like glibc or musl).
#                  This is ESSENTIAL for the binary to run in the 'scratch' image.
# -o /xds-adapter: Specifies the output path for the compiled executable.
RUN CGO_ENABLED=0 go build -o /xds-adapter .


# --- Stage 2: The Final Image ---
FROM scratch

# Copy only the compiled binary from the 'builder' stage into our empty image.
COPY --from=builder /xds-adapter /xds-adapter

# We also need the manifest.yaml file for the server to read on startup.
# We copy it from the builder stage as well.
COPY --from=builder /app/manifest.yaml /manifest.yaml

# Document the ports the container will listen on.
EXPOSE 18000
EXPOSE 9090

# Set the entrypoint for the container. This is the command that will be run when the container starts.
# We point it to the manifest file we just copied in.
ENTRYPOINT ["/xds-adapter", "--manifest=/manifest.yaml"]
