# Build stage
FROM rust:1.94-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src
COPY templates ./templates

# Build the application
RUN touch src/main.rs && \
    cargo build --release

# Runtime stage
FROM alpine:3.23

# Install runtime dependencies
RUN apk add --no-cache \
    wireguard-tools \
    nftables \
    iptables \
    ip6tables \
    iproute2 \
    bash

# Create necessary directories
RUN mkdir -p /etc/wireguard /etc/wg-manager

# Copy the binary from builder
COPY --from=builder /app/target/release/wg-manager /usr/local/bin/wg-manager

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set environment variables
ENV WG_USERNAME=admin \
    WG_PASSWORD=admin \
    WG_CONFIG_DIR=/etc/wireguard

# Expose port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/wg-manager"]
