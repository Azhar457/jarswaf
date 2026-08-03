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

# Install build deps and clean apt cache in same layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Copy everything needed for build (single cargo build instead of two)
COPY Cargo.toml Cargo.lock ./
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

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled Rust binary
COPY --from=backend-builder /app/jarswaf-bin /app/jarswaf

# Copy Svelte frontend build
COPY --from=frontend-builder /app/dashboard/dist /app/dashboard/dist

# Host the compiled Linux binary for Agent install script
RUN mkdir -p /app/dashboard/bin && \
    cp /app/jarswaf /app/dashboard/bin/jarswaf-agent-Linux-x86_64

EXPOSE 8080

ENV RUST_LOG=info
ENV JARSWAF_PORT=8080

# Run as a non-root user. The WAF inspects untrusted traffic; running PID 1 as root
# turns any memory/logic flaw into host/system compromise. `ponytail:` port bindings
# below 1024 would need CAP_NET_BIND_SERVICE — the image serves on 8080 so no extra
# cap is required here.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin jarswaf && \
    mkdir -p /app/logs /app/certs /var/log/jarswaf && \
    chown -R jarswaf:jarswaf /app /var/log/jarswaf

USER jarswaf

CMD ["/app/jarswaf", "agent"]
