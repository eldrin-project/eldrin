#!/bin/bash

# Start PostgreSQL database
echo "Starting PostgreSQL database..."
docker compose up -d postgres

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
sleep 5

# Build and run the application
echo "Building and running the Eldrin application..."
cargo run