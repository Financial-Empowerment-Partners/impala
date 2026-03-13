# syntax=docker/dockerfile:1

# =============================================================================
# Multi-architecture Dockerfile for impala-bridge
# Supports both linux/amd64 (x86_64) and linux/arm64 (Graviton)
#
# Build single-arch:  docker build .
# Build multi-arch:   docker buildx build --platform linux/amd64,linux/arm64 .
# =============================================================================

# --- Builder stage ---
# Uses the native platform for the builder when cross-compiling via buildx.
# For arm64 targets on x86 hosts, QEMU emulation handles the Rust compilation.
FROM --platform=$BUILDPLATFORM rust:1.83-slim AS planner

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ src/
COPY migrations/ migrations/

# Compute a recipe of dependencies for caching (cargo-chef pattern without the tool)
# This layer is cached as long as Cargo.toml/Cargo.lock don't change
RUN cargo fetch

FROM rust:1.83-slim AS builder

ARG TARGETARCH

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ src/
COPY migrations/ migrations/

RUN cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser -u 1000 appuser

COPY --from=builder /app/target/release/impala-bridge /usr/local/bin/impala-bridge
COPY migrations/ /app/migrations/

WORKDIR /app

# Run as non-root user
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["impala-bridge"]
