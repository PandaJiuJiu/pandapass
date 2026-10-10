# PandaPass all-in-one image: server + web UI in a single container.
# This is the only supported Docker deployment mode. s6-overlay supervises
# both nginx (web UI on :8080, proxying /api/) and pandapass-server (:8233)
# under a minimal init.
#
# Multi-stage: the server/cli are built in a Rust builder, the web bundle in a
# node builder, and only the artifacts are copied into the release image.
#
# Build:
#   docker build -f docker/Dockerfile -t ghcr.io/pandajiujiu/pandapass:0.0.1 .
#   docker compose build   # equivalent via docker-compose.yml
#
# Run:
#   docker run -d -p 8080:8080 -p 8233:8233 \
#     -v pandapass-data:/data \
#     -e PANDAPASS_PUBLIC_URL=https://vault.example.com \
#     ghcr.io/pandajiujiu/pandapass:0.0.1

# ── builder: server + cli ────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/rust:1.88-slim AS server-builder
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/pandapass-core/Cargo.toml      crates/pandapass-core/
COPY crates/pandapass-db/Cargo.toml         crates/pandapass-db/
COPY crates/pandapass-server/Cargo.toml    crates/pandapass-server/
COPY crates/pandapass-cli/Cargo.toml       crates/pandapass-cli/

RUN mkdir -p crates/pandapass-core/src crates/pandapass-db/src \
            crates/pandapass-server/src crates/pandapass-cli/src \
 && echo "" > crates/pandapass-core/src/lib.rs \
 && echo "" > crates/pandapass-db/src/lib.rs \
 && echo "fn main() {}" > crates/pandapass-server/src/main.rs \
 && echo "fn main() {}" > crates/pandapass-cli/src/main.rs \
 && cargo build --release --locked 2>/dev/null || true

COPY crates ./crates

RUN find crates -name "*.rs" -exec touch {} + \
 && cargo build --release --locked \
      --bin pandapass-server --bin pandapass-cli

# ── builder: web UI ──────────────────────────────────────────────────────────
FROM node:22-alpine AS web-builder

WORKDIR /app

COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund

COPY web/tsconfig.json web/vite.config.ts web/index.html ./
COPY web/src ./src
COPY web/public ./public

RUN npm run build

# ── runtime ──────────────────────────────────────────────────────────────────
FROM docker.io/library/debian:bookworm-slim

# Non-root user
RUN groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --home-dir /nonexistent \
      --shell /usr/sbin/nologin nonroot

# Install nginx + s6-overlay (lightweight process supervisor).
# sqlite3 is included for in-container backups (see docs/DEPLOY.md).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx sqlite3 xz-utils \
 && rm -rf /var/lib/apt/lists/*

# s6-overlay: noarch config + architecture-specific binaries.
# Downloaded once and checked in under docker/ to keep the build reliable
# even when GitHub is unreachable from the build machine.
COPY docker/s6-overlay-noarch.tar.xz docker/s6-overlay-x86_64.tar.xz /tmp/
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
 && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz \
 && rm /tmp/s6-overlay-noarch.tar.xz /tmp/s6-overlay-x86_64.tar.xz

# Copy server binaries
COPY --from=server-builder /build/target/release/pandapass-server /usr/local/bin/pandapass-server
COPY --from=server-builder /build/target/release/pandapass-cli    /usr/local/bin/pandapass

# Copy web bundle + nginx config
COPY --from=web-builder /app/dist /usr/share/nginx/html
COPY docker/nginx.allinone.conf /etc/nginx/nginx.conf

# Data directory (DB + server age key). This is the vault — back it up.
VOLUME ["/data"]

# Default config (override via docker run -e or compose)
ENV PANDAPASS_LISTEN=0.0.0.0:8233 \
    PANDAPASS_DB_URL=sqlite:///data/pandapass.db?mode=rwc \
    PANDAPASS_SERVER_AGE_IDENTITY_FILE=/data/server-age.key \
    PANDAPASS_PUBLIC_URL=http://localhost:8080 \
    RUST_LOG=info

EXPOSE 8233 8080

# The binary probes its own /api/v1/health endpoint (see `--health-check` in
# crates/pandapass-server/src/main.rs). Works for both docker run and compose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/pandapass-server", "--health-check"]

# ── s6-overlay services ──────────────────────────────────────────────────────
# s6-rc v3 layout (confirmed against the s6-overlay 3.2.0.2 package itself):
#   /etc/s6-overlay/s6-rc.d/
#     user/          bundle (pre-installed, selects services at boot)
#       type         "bundle"
#       contents.d/  EMPTY marker files naming the services to start
#     <service>/     each service is a top-level directory
#       type         "longrun" (has run) or "oneshot" (has up)
#       run          executable script (longrun)
#       up           script (oneshot)
#       dependencies.d/  empty marker files naming dependencies
# The init runs as root (standard s6-overlay pattern); each service drops
# privileges to nonroot with s6-setuidgid.

RUN mkdir -p /etc/s6-overlay/s6-rc.d/user/contents.d \
 && touch /etc/s6-overlay/s6-rc.d/user/contents.d/fix-perms \
        /etc/s6-overlay/s6-rc.d/user/contents.d/pandapass-server \
        /etc/s6-overlay/s6-rc.d/user/contents.d/nginx

# fix-perms: oneshot, fixes ownership of the /data volume at startup.
# Runs as root (the container starts as root), so the chown succeeds.
# s6-rc parses `up` as an execline script (newlines are whitespace), so the
# file must contain a single command path pointing to a real shell script.
RUN mkdir -p /etc/s6-overlay/s6-rc.d/fix-perms \
 && echo 'oneshot' > /etc/s6-overlay/s6-rc.d/fix-perms/type \
 && printf '#!/bin/sh\nchown -R nonroot:nonroot /data\nchmod 700 /data\n' > /usr/local/bin/fix-perms \
 && chmod +x /usr/local/bin/fix-perms \
 && echo '/usr/local/bin/fix-perms' > /etc/s6-overlay/s6-rc.d/fix-perms/up

# pandapass-server: longrun, drops to nonroot.
# `--init` is idempotent: it generates /data/server-age.key on first boot
# (skipping it if present) and then starts the server normally. It runs
# after fix-perms has chown'ed /data to nonroot.
# `with-contenv` loads the container's environment variables from
# /run/s6/container_environment (s6-overlay does NOT pass them to services
# otherwise); without it, PANDAPASS_DB_URL / PANDAPASS_SERVER_AGE_IDENTITY_FILE
# are unset and the server cannot open the database.
# `run` is exec'd directly by s6-supervise, so a #!/bin/sh shebang works.
RUN mkdir -p /etc/s6-overlay/s6-rc.d/pandapass-server/dependencies.d \
 && touch /etc/s6-overlay/s6-rc.d/pandapass-server/dependencies.d/fix-perms \
 && echo 'longrun' > /etc/s6-overlay/s6-rc.d/pandapass-server/type \
 && printf '#!/bin/sh\nexec /command/with-contenv /command/s6-setuidgid nonroot /usr/local/bin/pandapass-server --init\n' > /etc/s6-overlay/s6-rc.d/pandapass-server/run \
 && chmod +x /etc/s6-overlay/s6-rc.d/pandapass-server/run

# nginx: longrun, drops to nonroot. Needs writable pid + temp dirs.
# `daemon off;` is already in nginx.allinone.conf; no -g flag needed.
# `with-contenv` loads the container environment (PATH etc.) for nginx.
RUN mkdir -p /var/cache/nginx /var/lib/nginx \
 && chown -R nonroot:nonroot /var/cache/nginx /var/lib/nginx \
 && mkdir -p /etc/s6-overlay/s6-rc.d/nginx/dependencies.d \
 && touch /etc/s6-overlay/s6-rc.d/nginx/dependencies.d/fix-perms \
 && echo 'longrun' > /etc/s6-overlay/s6-rc.d/nginx/type \
 && printf '#!/bin/sh\nmkdir -p /var/cache/nginx/client_body_temp /var/cache/nginx/proxy_temp /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp /var/cache/nginx/scgi_temp\nchown -R nonroot:nonroot /var/cache/nginx\nexec /command/with-contenv /command/s6-setuidgid nonroot nginx\n' > /etc/s6-overlay/s6-rc.d/nginx/run \
 && chmod +x /etc/s6-overlay/s6-rc.d/nginx/run

# s6-overlay's init becomes PID 1 (root), starts the services, reaps zombies
ENTRYPOINT ["/init"]