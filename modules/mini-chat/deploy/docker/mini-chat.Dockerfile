# Multi-stage build for hyperspot-server with mini-chat + k8s features
# Stage 1: Builder
FROM rust:1.92-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS builder

# Build arguments
ARG CARGO_FEATURES=mini-chat,static-authn,static-authz,single-tenant,static-credstore,k8s
ARG BUILD_PROFILE=dev

# Install protobuf-compiler for prost-build
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake protobuf-compiler libprotobuf-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./

# Copy all workspace members
COPY apps/hyperspot-server ./apps/hyperspot-server
COPY apps/gts-docs-validator ./apps/gts-docs-validator
COPY libs ./libs
COPY modules ./modules
COPY examples ./examples
COPY config ./config
COPY proto ./proto

# Build the hyperspot-server binary.
# BUILD_PROFILE: "dev" (default, fast compile) or "release" (optimized).
# BuildKit cache mounts persist cargo registry + target dir across builds.
# On linux hosts (same triple as the container), this reuses compiled deps.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    RELEASE_FLAG="" && \
    OUTPUT_DIR="debug" && \
    if [ "$BUILD_PROFILE" = "release" ]; then \
        RELEASE_FLAG="--release"; \
        OUTPUT_DIR="release"; \
    fi && \
    if [ -n "$CARGO_FEATURES" ]; then \
        cargo build $RELEASE_FLAG --bin hyperspot-server --package=hyperspot-server --features "$CARGO_FEATURES"; \
    else \
        cargo build $RELEASE_FLAG --bin hyperspot-server --package=hyperspot-server; \
    fi && \
    cp /build/target/$OUTPUT_DIR/hyperspot-server /tmp/hyperspot-server

# Stage 2: Runtime
FROM debian:13.3-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary from builder stage (via /tmp because target/ is a cache mount)
COPY --from=builder /tmp/hyperspot-server /app/hyperspot-server
# Copy config
COPY --from=builder /build/config /app/config

# Expose mini-chat API port
EXPOSE 8087

RUN useradd -U -u 1000 appuser && \
    chown -R 1000:1000 /app
USER 1000
CMD ["/app/hyperspot-server", "--config", "/app/config/mini-chat.yaml", "run"]
