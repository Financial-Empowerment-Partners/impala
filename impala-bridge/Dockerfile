# syntax=docker/dockerfile:1

# =============================================================================
# Multi-architecture Dockerfile for impala-bridge
# Supports both linux/amd64 (x86_64) and linux/arm64 (Graviton)
#
# Build single-arch:  docker build .
# Build multi-arch:   docker buildx build --platform linux/amd64,linux/arm64 .
# =============================================================================

# --- Builder stage ---
# For arm64 targets on x86 hosts, QEMU emulation handles the Rust compilation.
#
# Base images are pinned by multi-arch manifest-list digest (supply-chain
# hardening). To bump: `docker buildx imagetools inspect <image>:<tag>` and copy
# the top-level "Digest". The :tag is kept alongside the digest for readability.
FROM rust:1.96-slim@sha256:26abcef3d79b8d890c4ceb17093154573e1f6479cf6dd7c1450043b8458350f6 AS builder

ARG TARGETARCH

WORKDIR /app
# Unpinned by design: Debian point releases shift package versions and would
# break the build on every release; the digest-pinned base image bounds the drift.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
COPY migrations/ migrations/

RUN cargo build --release --locked

# --- Runtime stage ---
FROM debian:trixie-slim@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e

# Unpinned by design: Debian point releases shift package versions and would
# break the build on every release; the digest-pinned base image bounds the drift.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser -u 1000 appuser

COPY --from=builder /app/target/release/impala-bridge /usr/local/bin/impala-bridge
COPY migrations/ /app/migrations/

WORKDIR /app

# Run as non-root user
USER appuser

EXPOSE 8080

# Readiness, not liveness: /readyz is 200 only when Postgres and Redis both
# answer (src/handlers/health.rs), so anything acting on this check sees a
# container that cannot serve (auth is fail-closed on Redis) rather than one
# that merely has a listener. /health stays 200 with a JSON body even while
# degraded — that shape is a contract for humans, impalactl and openapi.yaml,
# so never probe it. retries=6 (3 min at 30 s) rides out a Multi-AZ RDS /
# ElastiCache failover without a restart storm under Swarm or autoheal;
# docker compose only reports the state. The ECS target groups
# (terraform/) run their own /readyz check with the same philosophy.
HEALTHCHECK --interval=30s --timeout=5s --retries=6 --start-period=60s \
    CMD curl -f http://localhost:8080/readyz || exit 1

CMD ["impala-bridge"]
