#--------------------------------------------------------------------------------------------
# Stage 1: Builder Stage - Compile the Rust application
# Direct build approach.
#--------------------------------------------------------------------------------------------
FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy all necessary application files for a single, direct build
# Source paths are relative to the build context root (services/authentication/)
# Destination paths are relative to WORKDIR (/usr/src/app)
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx/
COPY src ./src/
COPY migrations ./migrations/

# --- DEBUG: List contents of /usr/src/app to verify copies ---
RUN echo ">>> Builder: Contents of /usr/src/app BEFORE build:" && ls -A /usr/src/app && \
    echo ">>> Builder: Contents of /usr/src/app/.sqlx/ (if exists):" && \
    (ls -A /usr/src/app/.sqlx || echo "  .sqlx directory not found in /usr/src/app or is empty") && \
    echo ">>> Builder: Contents of /usr/src/app/src/ (if exists):" && \
    (ls -A /usr/src/app/src || echo "  src directory not found in /usr/src/app or is empty") && \
    echo ">>> Builder: Contents of /usr/src/app/migrations/ (if exists):" && \
    (ls -A /usr/src/app/migrations || echo "  migrations directory not found in /usr/src/app or is empty")

# Perform a SINGLE, direct build of the release binary.
# This will use the .sqlx cache if DATABASE_URL is not set in this build stage.
RUN echo ">>> Builder: Starting cargo build --release --locked --bin authentication..." && \
    cargo build --release --locked --bin authentication && \
    echo ">>> Builder: Listing /usr/src/app/target/release/ after build:" && \
    ls -l /usr/src/app/target/release/ && \
    if [ -f /usr/src/app/target/release/authentication ]; then \
        echo ">>> SUCCESS: 'authentication' BINARY FOUND in target/release/"; \
    else \
        echo ">>> FAILURE: 'authentication' BINARY NOT FOUND in target/release/"; \
        echo ">>> Contents of target/release was:"; \
        ls -l /usr/src/app/target/release/; \
        echo ">>> CHECK: 1. Package name in Cargo.toml (is it 'authentication'?)."; \
        echo ">>> CHECK: 2. Do you have src/main.rs (for a binary)?"; \
        echo ">>> CHECK: 3. If using a custom binary name in Cargo.toml's [[bin]] section, ensure --bin matches."; \
        exit 1; \
    fi

#--------------------------------------------------------------------------------------------
# Stage 2: Runner Stage - Create the final lightweight production image
#--------------------------------------------------------------------------------------------
FROM debian:stable-slim AS runner

ARG APP_USER=appuser
ARG APP_GROUP=appgroup
ARG APP_UID=1001
ARG APP_GID=1001

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g ${APP_GID} ${APP_GROUP} \
 && useradd -r -u ${APP_UID} -g ${APP_GROUP} -s /sbin/nologin -m -d /app ${APP_USER}

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/authentication /usr/local/bin/authentication_service
COPY --from=builder /usr/src/app/migrations ./migrations

RUN chown -R ${APP_USER}:${APP_GROUP} /app \
 && chown ${APP_USER}:${APP_GROUP} /usr/local/bin/authentication_service

USER ${APP_USER}:${APP_GROUP}

EXPOSE 3000

CMD ["authentication_service"]
