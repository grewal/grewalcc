# web/grewal-cc-web/Dockerfile

# --- Stage 1: Artifact Generator ---
FROM rust:1.82-slim AS artifact_generator

WORKDIR /app
# Copy only the Rust source code into this stage
COPY ./web/grewalcc-fluid-simulation ./
# Install wasm-pack for compilation
RUN cargo install wasm-pack
# Build the WASM package. The output will be in /app/pkg
RUN wasm-pack build --target web --out-dir pkg

# --- Stage 2: Next.js Production Builder ---
FROM node:18-alpine AS builder
WORKDIR /app

# Copy package manager files first
COPY ./web/grewal-cc-web/package.json ./web/grewal-cc-web/package-lock.json ./
RUN npm ci

# Copy the entire Next.js app source code
COPY ./web/grewal-cc-web/. .

# Copy the compiled WASM artifacts from the first stage
COPY --from=artifact_generator /app/pkg ./public/simulation

# Run the production build command
RUN npm run build

# --- Stage 3: Final Production Runner ---
FROM node:18-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

# Create a non-root user for security
RUN addgroup --system --gid 1001 nextjs && \
    adduser --system --uid 1001 --ingroup nextjs nextjs

# Copy only the necessary, optimized build artifacts from the builder stage
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
