# File: services/grewalcc/Dockerfile

# --- Stage 1: Builder ---
FROM debian:12.5-slim AS builder

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libgrpc++-dev \
        libprotobuf-dev \
        protobuf-compiler-grpc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Adjusted: copy protos from root-level protos/
COPY protos ./protos

# Adjusted: copy C++ service code from services/grewalcc
COPY services/grewalcc .

RUN make

# --- Stage 2: Minimal runtime ---
FROM debian:12.5-slim AS runner
RUN apt-get update && \
    apt-get install -y --no-install-recommends libgrpc++1.51 libprotobuf32 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/grewalcc .

EXPOSE 50051
CMD ["./grewalcc"]

