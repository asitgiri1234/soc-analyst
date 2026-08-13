# Three stages: dependencies, build, runtime. The runtime image carries only
# Next's standalone output and its static assets -- no source, no node_modules
# tree, no package manager.

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# `npm ci` rather than `install`: the lockfile decides, so the image is
# reproducible and a transitive dependency cannot drift between builds.
RUN npm ci


FROM node:22-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

# NEXT_PUBLIC_* values are inlined into the JavaScript bundle at build time, so
# they must be present *here* -- setting them at run time has no effect on an
# already-built bundle. This is also why no secret may ever be a NEXT_PUBLIC_
# variable: it would be baked into a file served to every browser. GROQ_API_KEY
# is backend-only and deliberately absent from this file.
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
ARG NEXT_PUBLIC_API_VERSION=v1
ARG NEXT_PUBLIC_APP_NAME="AI SOC Analyst"
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL \
    NEXT_PUBLIC_API_VERSION=$NEXT_PUBLIC_API_VERSION \
    NEXT_PUBLIC_APP_NAME=$NEXT_PUBLIC_APP_NAME

COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build


FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

# The login page is static and needs no backend, so it answers even when the
# API is down -- which is what a container healthcheck should measure: whether
# *this* process is serving, not whether its dependencies are.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/login || exit 1

CMD ["node", "server.js"]
