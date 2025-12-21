# lazydns Dockerfile
# Multi-stage build for optimal image size

# Stage 1: Builder
FROM rust:1.92-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Stage 2: Runtime
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/lazydns /usr/local/bin/lazydns

# Create configuration directory
RUN mkdir -p /etc/lazydns

# Expose DNS ports
EXPOSE 53/udp 53/tcp

# Expose DoT port
EXPOSE 853/tcp

# Expose DoH port
EXPOSE 443/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD dig @127.0.0.1 -p 53 health.check || exit 1

# Run as non-root user
RUN useradd -r -s /bin/false lazydns
USER lazydns

# Default command
CMD ["lazydns", "--config", "/etc/lazydns/config.yaml"]
