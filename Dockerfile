# Multi-stage Dockerfile for HookVault
# Produces a single, secure, production-ready container hosting both API and UI.

# -----------------------------------------------------------------------------
# Stage 1: Build the React + Vite frontend
# -----------------------------------------------------------------------------
FROM node:22-bookworm-slim AS web-builder
WORKDIR /app/web

COPY web/package*.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Build the TypeScript backend
# -----------------------------------------------------------------------------
FROM node:22-bookworm-slim AS server-builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build:server

# -----------------------------------------------------------------------------
# Stage 3: Production runner
# -----------------------------------------------------------------------------
FROM node:22-bookworm-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install production dependencies only
COPY package*.json ./
RUN npm ci --omit=dev

# Copy compiled backend and frontend artifacts
COPY --from=server-builder /app/dist ./dist
COPY --from=web-builder /app/web/dist ./web/dist

# Setup persistent volume directory for SQLite database
RUN mkdir -p /app/data && chown -R node:node /app

USER node

EXPOSE 3000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:' + (process.env.PORT || 3000) + '/api/endpoints').then(r => process.exit(r.status === 401 ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "dist/server.js"]
