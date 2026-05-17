# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Build (Rust + dependencies)
# ─────────────────────────────────────────────────────────────────────────────
# clap 4.x may pull clap_lex 1.1+ which requires Rust edition 2024 (1.85+).
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Install build dependencies for Pingora (needs clang + perl for BoringSSL/OpenSSL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    perl \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# ── Dependency cache layer ────────────────────────────────────────────────────
# Copy only the manifest first. This layer is invalidated only when Cargo.toml
# changes, not on every source edit.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release 2>&1 || true \
    && rm -f src/main.rs

# ── Real source ───────────────────────────────────────────────────────────────
# Use trailing slash on both sides to make COPY src/ -> src/ explicit.
COPY src/ ./src/
RUN touch src/main.rs && cargo build --release

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime (minimal Debian slim)
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r sniproxy && useradd -r -g sniproxy -s /usr/sbin/nologin sniproxy

COPY --from=builder /build/target/release/pingora-sniproxy /usr/local/bin/pingora-sniproxy
RUN chmod +x /usr/local/bin/pingora-sniproxy

# Default config directory (mount a volume here)
RUN mkdir -p /etc/sniproxy && chown sniproxy:sniproxy /etc/sniproxy
COPY config/config.yaml /etc/sniproxy/config.yaml

# ── Entrypoint script (handles PROXY env var) ─────────────────────────────────
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports (add every port from config `listens` when using -p mapping)
EXPOSE 80/tcp 443/tcp 8080/tcp 8443/tcp 9090/tcp

# Use non-root (Note: ports 80/443 require NET_BIND_SERVICE or run as root)
# For production, use --cap-add=NET_BIND_SERVICE or bind to 8080/8443
USER root

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# Extra CLI flags only (e.g. --daemon). Do not repeat the binary name here.
CMD []
