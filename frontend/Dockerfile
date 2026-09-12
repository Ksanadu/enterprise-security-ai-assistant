# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Frontend image: Vite build output served by nginx.
#
# The build stage needs Node and the whole dependency tree; the runtime stage
# needs neither. Only `dist/` crosses the stage boundary, so the shipped image
# contains static files and an nginx configuration and nothing else.
# ---------------------------------------------------------------------------

FROM node:22-alpine AS builder

WORKDIR /build

# Lockfile first so the dependency layer is cached across source edits.
COPY package.json package-lock.json ./
RUN npm ci

# tsconfig.node.json makes `tsc -b` type-check vite.config.ts, so the config
# files are build inputs and not merely tooling.
COPY tsconfig.json tsconfig.app.json tsconfig.node.json ./
COPY vite.config.ts index.html ./
COPY src ./src

# `npm run build` runs `tsc -b` before `vite build`, so a type error fails the
# image build instead of shipping broken JavaScript.
RUN npm run build


FROM nginx:1.27-alpine AS runtime

# The stock configuration is replaced wholesale: the default one serves
# /usr/share/nginx/html without the SPA fallback or the security headers.
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/esaa.conf
COPY --from=builder /build/dist /usr/share/nginx/html

# nginx:alpine already ships an unprivileged `nginx` user; the master process
# still needs to bind port 80, so it starts as root and drops privileges for
# every worker.
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
