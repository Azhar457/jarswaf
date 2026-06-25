# Stage 1: Build Frontend Dashboard (Svelte)
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ ./
RUN npm run build

# Stage 2: Build Backend Controller (Rust)
FROM rust:slim-bullseye AS backend-builder
WORKDIR /app
# Install required build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev curl

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml ./xtask/Cargo.toml

# Create dummy source files for dependency caching
RUN mkdir -p src xtask/src && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > xtask/src/main.rs && \
    cargo build --release && \
    rm -rf src xtask/src

# Copy actual source code
COPY src ./src
COPY xtask/src ./xtask/src

# Rebuild actual application code
RUN cargo build --release

# Stage 3: Final Runtime Image
FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates libssl1.1 curl && rm -rf /var/lib/apt/lists/*

# Copy compiled Rust binary
COPY --from=backend-builder /app/target/release/aegis-waf /app/aegis-waf

# Copy Svelte frontend build
COPY --from=frontend-builder /app/dashboard/dist /app/dashboard/dist

# Host the compiled Linux binary for the Agent install script
RUN mkdir -p /app/dashboard/dist/bin && \
    cp /app/aegis-waf /app/dashboard/dist/bin/aegis-agent-Linux-x86_64

# Expose Controller Port
EXPOSE 8080

# Environment setup
ENV RUST_LOG=info
ENV AEGIS_PORT=8080

CMD ["/app/aegis-waf"]
