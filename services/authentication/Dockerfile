#--------------------------------------------------------------------------------------------
# Stage 1: Builder Stage - Compile the Rust application
#--------------------------------------------------------------------------------------------
FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir src && \
    echo "fn main(){println!(\"Dummy main for dep caching\");}" > src/main.rs && \
    echo "[package]\nname = \"authentication-dummy-builder\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]" > Cargo.toml

COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked

COPY src ./src
COPY migrations ./migrations 

RUN cargo build --release --locked

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
