# lazydns Dockerfile
# Multi-stage build: download binary in first stage, use scratch in second stage
# How to run:
#
# Need to map config volume and ports
# 
# docker run -d \
#   --name lazydns \
#   -p 53:53/udp -p 53:53/tcp \
#   -p 853:853/tcp -p 443:443/tcp \
#   -p 784:784/tcp -p 8080:8080/tcp -p 9090:9090/tcp \
#   -e TZ=Asia/Shanghai \
#   -v /path/to/config:/etc/lazydns \
#   lazywalker/lazydns:latest

# Stage 1: Downloader and Preparer
FROM alpine:3.23 AS downloader

# Install curl and other tools for downloading and preparing
RUN apk add --no-cache curl tzdata

# Download latest release binary based on architecture
ARG LAZYDNS_VERSION=v0.2.31
ARG TARGETARCH
RUN set -ex; \
    case "$TARGETARCH" in \
    amd64) ARCH="x86_64" ;; \
    arm64) ARCH="aarch64" ;; \
    arm) ARCH="arm" ;; \
    *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" = "arm" ]; then \
    BINARY_NAME="lazydns-full-${ARCH}-unknown-linux-musleabihf.tar.gz"; \
    else \
    BINARY_NAME="lazydns-full-${ARCH}-unknown-linux-musl.tar.gz"; \
    fi; \
    echo "Downloading ${BINARY_NAME}"; \
    curl -L -o lazydns-full.tar.gz \
    https://github.com/lazywalker/lazydns/releases/download/${LAZYDNS_VERSION}/${BINARY_NAME} \
    && tar -xzf lazydns-full.tar.gz \
    && chmod +x lazydns


# Set timezone (can be overridden at runtime)
ARG TZ=Asia/Shanghai
RUN echo "$TZ" > /etc/timezone

# Prepare application files
ADD config.yaml /app/config.yaml
RUN sed -i 's/5354/53/g' /app/config.yaml || true

# Stage 2: Runtime (scratch - minimal)
FROM scratch

# Copy timezone and zoneinfo from the downloader stage
COPY --from=downloader /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=downloader /etc/timezone /etc/timezone
COPY --from=downloader /app /app

# Copy the binary
COPY --from=downloader /lazydns /lazydns

# Set environment variables
ENV TZ=Asia/Shanghai

# Expose DNS ports
EXPOSE 53/udp 53/tcp

# Expose DoT port
EXPOSE 853/tcp

# Expose DoH port
EXPOSE 443/tcp

# Expose DoQ port
EXPOSE 784/tcp

# Expose HTTP management ports
EXPOSE 8080/tcp
# Expose Prometheus metrics port
EXPOSE 9090/tcp

WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/lazydns", "--version"] || exit 1

# Default command
CMD ["/lazydns", "start", "-d", "/app"]

