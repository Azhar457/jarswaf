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
    cp target/release/aegis-waf /app/aegis-waf-bin && \
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
COPY --from=backend-builder /app/aegis-waf-bin /app/aegis-waf

# Copy Svelte frontend build
COPY --from=frontend-builder /app/dashboard/dist /app/dashboard/dist

# Host the compiled Linux binary for Agent install script
RUN mkdir -p /app/dashboard/dist/bin && \
    cp /app/aegis-waf /app/dashboard/dist/bin/aegis-agent-Linux-x86_64

EXPOSE 8080

ENV RUST_LOG=info
ENV AEGIS_PORT=8080

CMD ["/app/aegis-waf"]
