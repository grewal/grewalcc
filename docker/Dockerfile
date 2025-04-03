# --- Stage 1: Builder ---
# Use a specific Debian 12 version for reproducibility
FROM debian:12.5 AS builder

LABEL stage=builder

# Install build dependencies and compile gtest
RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y --no-install-recommends \
    # Core build tools
    apt-utils \
    build-essential \
    pkg-config \
    cmake \
    git \
    # gRPC and Protobuf
    libgrpc-dev \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libprotobuf-dev \
    protobuf-compiler \
    # Other direct dependencies from Makefile
    libctemplate-dev \
    libgoogle-glog-dev \
    libabsl-dev \
    libc-ares-dev \
    libssl-dev \
    zlib1g-dev \
    # Added based on Makefile analysis
    libre2-dev \
    libgflags-dev \
    liblzma-dev \
    libmariadb-dev \
    libgtest-dev \
    # Tool needed for dpkg -L diagnostics
    dpkg && \
    \
    # --- Compile gtest ---
    echo "--- Compiling installed googletest source ---" && \
    cd /usr/src/googletest && \
    cmake CMakeLists.txt && \
    make && \
    # Copy the libraries to a standard location
    cp lib/*.a /usr/lib/ && \
    cd / && \
    # --- End gtest compilation ---
    \
    # Clean up apt cache
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/src/googletest

# Set base working directory for COPY
WORKDIR /app

# Copy the application source code into the image
# Assumes 'docker build' is run from the project root (e.g., /home/ygrew/src/gcc-docker)
# Ensure you have a .dockerignore file in that root directory!
COPY . /app/

# Change WORKDIR to where the Makefile is located inside the image
WORKDIR /app/frontend

# Build the application using the Makefile from the current directory (/app/frontend)
# Add diagnostics before make
RUN echo "--- DIAGNOSTICS ---" && \
    echo "PATH=$PATH" && \
    echo "--- which pkg-config ---" && \
    which pkg-config && \
    echo "--- which grpc_cpp_plugin ---" && \
    which grpc_cpp_plugin && \
    echo "--- pkg-config --version ---" && \
    pkg-config --version && \
    echo "---------------------" && \
    echo "--- Setting up pkg-config for grpc++ ---" && \
    ln -sf grpc.pc /usr/lib/x86_64-linux-gnu/pkgconfig/grpc++.pc && \
    echo "--- Verifying symlink ---" && \
    ls -l /usr/lib/x86_64-linux-gnu/pkgconfig/grpc* && \
    export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH} && \
    echo "--- Checking .pc file contents ---" && \
    echo ">>> Content of grpc.pc:" && \
    cat /usr/lib/x86_64-linux-gnu/pkgconfig/grpc.pc && \
    echo ">>> Content of protobuf.pc:" && \
    cat /usr/lib/x86_64-linux-gnu/pkgconfig/protobuf.pc && \
    echo "--- Checking pkg-config output directly ---" && \
    echo ">>> pkg-config --cflags grpc++" && \
    pkg-config --cflags grpc++ && \
    echo ">>> pkg-config --libs grpc++" && \
    pkg-config --libs grpc++ && \
    echo ">>> pkg-config --cflags protobuf" && \
    pkg-config --cflags protobuf && \
    echo ">>> pkg-config --libs protobuf" && \
    pkg-config --libs protobuf && \
    echo "----------------------------------" && \
    echo "--- Verifying libgrpc-dev Contents ---" && \
    echo ">>> Listing ALL files from libgrpc-dev:" && \
    dpkg -L libgrpc-dev || echo "dpkg -L libgrpc-dev command failed." && \
    echo "----------------------------------" && \
    echo "--- Running make clean && make V=1 all ---" && \
    # IMPORTANT: Makefile still has the '-I/usr/include' from previous step for this test run
    # We will change it to the correct path (if found by dpkg -L) in the next step
    make clean && make V=1 all

# --- Stage 2: Final Runtime Image ---
# Use the same base image to ensure GLIBC and core library compatibility
FROM debian:12.5

# Install only RUNTIME dependencies
RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y --no-install-recommends \
    # Runtime libraries identified for Debian 12 (Bookworm)
    libgrpc++1.51 \
    libprotobuf32 \
    libctemplate3 \
    libgoogle-glog0v6 \
    libabsl20220623 \
    libc-ares2 \
    libssl3 \
    zlib1g \
    libre2-dev \
    libgflags2.2 \
    liblzma5 \
    libmariadb3 \
    # Base C/C++ runtime
    libc6 \
    libgcc-s1 \
    libstdc++6 \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set final working directory (optional, '/app' is fine)
WORKDIR /app

# Copy the compiled binary FROM the builder stage's correct location
# The binary will be in /app/frontend/grewal in the builder stage
COPY --from=builder /app/frontend/grewal /app/grewal

# Copy the templates directory from the builder stage
COPY --from=builder /app/frontend/templates /app/templates

# Example: If you had config files relative to frontend:
# COPY --from=builder /app/frontend/config/ /app/config/

# Define the user to run as (optional but good practice to not run as root)
# RUN useradd --system --no-create-home appuser
# USER appuser

# Expose the port the application listens on
EXPOSE 50051

# Define the command to run the application
ENTRYPOINT ["/app/grewal"]
# CMD can provide default arguments if needed
# CMD ["--config", "/app/config/grewal.cfg"]
