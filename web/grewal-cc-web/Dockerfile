# --- Stage 1: Builder ---
FROM node:20-alpine AS builder
WORKDIR /app

# Copy package manager files
COPY package.json package-lock.json ./

# Install dependencies (including build tools like Tailwind)
RUN npm ci

# Copy the rest of the application source code,
# which now INCLUDES the pre-generated src/lib/grpc files.
COPY . .

# Run the production build
ENV NODE_ENV=production
RUN npm run build

# --- Stage 2: Production Runner ---
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nextjs && \
    adduser --system --uid 1001 --ingroup nextjs nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
