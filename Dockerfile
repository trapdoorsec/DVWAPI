# Build stage
FROM rust:1.86 as builder

WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install CA certificates for HTTPS
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 dvwapi

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/dvwapi /app/dvwapi

# Change ownership
RUN chown -R dvwapi:dvwapi /app

# Switch to non-root user
USER dvwapi

# Expose default port
EXPOSE 7341

# Run the application
ENTRYPOINT ["/app/dvwapi"]
CMD ["--ip", "0.0.0.0", "--port", "7341"]
