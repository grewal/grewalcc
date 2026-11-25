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
# Paths are now relative to the build context root (the project root).
COPY services/authentication_service/Cargo.toml services/authentication_service/Cargo.lock ./
COPY services/authentication_service/.sqlx ./.sqlx/
COPY services/authentication_service/src ./src/
COPY services/authentication_service/migrations ./migrations/
COPY services/authentication_service/redis-scripts ./redis-scripts/

# --- DEBUG: List contents of /usr/src/app to verify copies ---
RUN echo ">>> Builder: Contents of /usr/src/app AFTER copy:" && ls -A /usr/src/app

# Perform a SINGLE, direct build of the release binary.
# This will use the .sqlx cache if DATABASE_URL is not set in this build stage.
RUN echo ">>> Builder: Starting cargo build --release --locked --bin authentication_service..." && \
    cargo build --release --locked --bin authentication_service && \
    echo ">>> Builder: Listing /usr/src/app/target/release/ after build:" && \
    ls -l /usr/src/app/target/release/ && \
    if [ -f /usr/src/app/target/release/authentication_service ]; then \
        echo ">>> SUCCESS: 'authentication_service' BINARY FOUND in target/release/"; \
    else \
        echo ">>> FAILURE: 'authentication_service' BINARY NOT FOUND in target/release/"; \
        echo ">>> Contents of target/release was:"; \
        ls -l /usr/src/app/target/release/; \
        echo ">>> CHECK: 1. Package name in Cargo.toml (is it 'authentication_service'?)."; \
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

COPY --from=builder /usr/src/app/target/release/authentication_service /usr/local/bin/authentication_service
COPY --from=builder /usr/src/app/migrations ./migrations
# Copy Lua script into the final image
COPY --from=builder /usr/src/app/redis-scripts ./redis-scripts

RUN chown -R ${APP_USER}:${APP_GROUP} /app \
 && chown ${APP_USER}:${APP_GROUP} /usr/local/bin/authentication_service

USER ${APP_USER}:${APP_GROUP}

EXPOSE 3000

CMD ["authentication_service"]
