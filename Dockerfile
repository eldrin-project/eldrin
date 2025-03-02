FROM rust:latest as builder

WORKDIR /usr/src/eldrin

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# First, copy files for dependencies
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml ./core/
COPY modules/Cargo.toml ./modules/

# Create empty source files for dependencies
RUN mkdir -p core/src && \
    echo "fn main() {}" > core/src/main.rs && \
    mkdir -p modules/src && \
    echo "fn main() {}" > modules/src/lib.rs

# Build dependencies
ENV SQLX_OFFLINE=true
RUN SQLX_OFFLINE=true cargo build

# Now, copy the real source code
COPY . .

# Build the application in release mode
ENV SQLX_OFFLINE=true
RUN SQLX_OFFLINE=true cargo build --release

FROM rust:latest

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the executable from the builder
COPY --from=builder /usr/src/eldrin/target/release/eldrin-core /app/
COPY --from=builder /usr/src/eldrin/modules/ /app/modules/
COPY --from=builder /usr/src/eldrin/start.sh /app/

# Expose port
EXPOSE 3000

# Command to run the application
CMD ["/app/eldrin-core"]