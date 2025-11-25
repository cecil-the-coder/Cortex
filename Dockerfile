# Multi-stage Dockerfile for Cortex LLM Router
# Build stage - creates a minimal, secure Go binary
FROM golang:1.24-alpine AS builder

# Set build arguments
ARG GO_VERSION=1.24
ARG GIT_SHA
ARG GIT_VERSION
ARG TARGETOS
ARG TARGETARCH

# Install required packages for building
RUN apk add --no-cache git ca-certificates tzdata

# Create a non-root user for building
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /build

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Set build environment variables
ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS:-linux}
ENV GOARCH=${TARGETARCH:-amd64}
ENV GO_VERSION=${GO_VERSION}

# Build the application
RUN go build -a -installsuffix cgo \
    -ldflags="-w -s \
      -X 'main.Version=${GIT_VERSION:-dev}' \
      -X 'main.GitSHA=${GIT_SHA:-unknown}' \
      -X 'main.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')'" \
    -o cortex ./cmd/router

# Production stage - creates a minimal runtime image
FROM alpine:3.20 AS production

# Set labels for metadata
LABEL maintainer="cecil-the-coder"
LABEL description="Cortex - LLM Router with Admin API"
LABEL version="1.0.0"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    && rm -rf /var/cache/apk/*

# Create a non-root user
RUN adduser -D -s /bin/sh -u 1001 appuser

# Create necessary directories
RUN mkdir -p /app/config /app/logs && \
    chown -R appuser:appuser /app

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /build/cortex /app/cortex

# Set permissions
RUN chmod +x /app/cortex && \
    chown appuser:appuser /app/cortex

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080 8081

# Set environment variables
ENV GIN_MODE=release
ENV CONFIG_PATH=/app/config/config.json

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/app/cortex"]
CMD ["-config", "/app/config/config.json"]

# Development stage - includes debugging tools
FROM builder AS development

# Install development tools
RUN apk add --no-cache \
    delve \
    curl \
    vim \
    && rm -rf /var/cache/apk/*

# Switch to working directory
WORKDIR /app

# Copy the binary
COPY --from=builder /build/cortex /app/cortex

# Set development environment
ENV GIN_MODE=debug
ENV CONFIG_PATH=/app/config/config.json

# Expose debugging port
EXPOSE 8080 8081 40000

# Default command for development
ENTRYPOINT ["/app/cortex"]
CMD ["-config", "/app/config/config.json", "-enable-admin", "-admin-host", "0.0.0.0"]