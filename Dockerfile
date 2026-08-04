# ================================================================
# Stage 1: Build Frontend Dashboard (Svelte)
# ================================================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

# ================================================================
# Stage 2: Build Backend Controller (Rust)
# ================================================================
FROM rust:slim-bookworm AS backend-builder
WORKDIR /app

# Minimize disk usage: no incremental builds, limit parallel jobs
ENV CARGO_INCREMENTAL=0
ENV CARGO_BUILD_JOBS=2
ENV RUSTFLAGS="-C strip=symbols"

# Install only the build toolchain actually needed to compile the binary and its transitive
# C deps: cmake/g++/make for libz-ng-sys (ONNX/tract chain), pkg-config + libssl-dev for
# openssl-sys headers. `curl` was previously listed but the build never uses it — omitted.
# `build-essential` alone proved flaky here ("failed to find tool c++"), so gcc/g++/make are
# installed explicitly and verified before building.
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev build-essential cmake gcc g++ make && \
    command -v cmake && command -v c++ && \
    rm -rf /var/lib/apt/lists/*

# Copy everything needed for build (single cargo build instead of two)
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto/ ./proto/
COPY xtask/ ./xtask/
COPY src/ ./src/

# Single build pass — avoids doubling disk usage from dummy build caching
# Clean up cargo registry + build artifacts we don't need afterward
RUN cargo build --release && \
    cp target/release/jarswaf /app/jarswaf-bin && \
    rm -rf target /usr/local/cargo/registry /usr/local/cargo/git

# ================================================================
# Stage 3: Final Minimal Runtime Image
# ================================================================
FROM debian:bookworm-slim
WORKDIR /app

# Minimal runtime: only what the binary actually needs. `ldd` on the release binary shows
# it links libc/libm/libgcc_s only — rustls uses `ring` (bundled crypto), so libssl3 is NOT
# required. curl is not used at runtime. ca-certificates IS needed for reqwest/rustls TLS
# root verification (threat-intel pull, webhooks). Everything else is omitted.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled Rust binary
COPY --from=backend-builder /app/jarswaf-bin /app/jarswaf

# Copy Svelte frontend build
COPY --from=frontend-builder /app/dashboard/dist /app/dashboard/dist

# Host the compiled Linux binary for Agent install script
RUN mkdir -p /app/dashboard/dist/bin && \
    cp /app/jarswaf /app/dashboard/dist/bin/jarswaf-agent-Linux-x86_64

EXPOSE 8080

ENV RUST_LOG=info
ENV JARSWAF_PORT=8080

# Run as non-root. The WAF inspects untrusted traffic; PID 1 as root turns any logic flaw
# into host compromise. Serves on 8080 so no NET_BIND_SERVICE cap is needed here.
# The entrypoint runs as root ONLY to chown mounted volumes (logs/certs/db) then drops to
# the jarswaf user via `su` — so named volumes that start root-owned still work.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin jarswaf && \
    mkdir -p /app/logs /app/certs /var/log/jarswaf && \
    chown -R jarswaf:jarswaf /app /app/dashboard/dist /app/logs /app/certs /var/log/jarswaf

COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Container default user is root so the entrypoint can chown mounted volumes; it then drops
# to the unprivileged jarswaf user for the actual server process. This is the standard
# "root entrypoint, non-root app" pattern (PostgreSQL, n8n, etc.) — the long-running process
# never runs as root.
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# CMD runs as jarswaf (set by the entrypoint's `su`); keep the image default user as root
# solely for the chown step.
CMD ["/app/jarswaf", "agent"]
