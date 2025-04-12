FROM rust:1.86-slim as builder

WORKDIR /usr/src/app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the real source code
COPY . .

# Modify the server binding for container environment
RUN sed -i 's/\[127, 0, 0, 1\]/\[0, 0, 0, 0\]/g' src/main.rs

# Build the application
RUN cargo build --release

# Create a smaller runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/PAMP-auth-service .

# Expose the service port
EXPOSE 3000

# Run the service
CMD ["./PAMP-auth-service"] 