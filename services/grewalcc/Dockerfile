# Multi-Stage Dockerfile for the C++ 'grewalcc' gRPC Service
#

# --- Stage 1: The "Builder" ---
FROM debian:12.5-slim AS builder

LABEL stage=builder

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    git \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libprotobuf-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the entire service directory into the builder.
COPY . .

# Run the Makefile to compile the binary & generate protos

RUN make all

# --- Stage 2: The "Runner" ---
FROM debian:12.5-slim AS runner

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y --no-install-recommends \
    libgrpc++1.51 \
    libprotobuf32 \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home appuser
USER appuser
WORKDIR /home/appuser

COPY --from=builder /app/grewalcc /usr/local/bin/grewalcc

# Expose the gRPC port
EXPOSE 50051

CMD ["grewalcc"]
