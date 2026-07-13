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
FROM rust:1.97-slim@sha256:14c4fe50ea427dc42381a1a09a9a839c1d2346a2e508cd491bf02c659dbc0ed7 AS builder

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
FROM debian:trixie-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8

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

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["impala-bridge"]
