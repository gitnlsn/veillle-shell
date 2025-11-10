# Multi-stage build for Go monitor

FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev \
    libpcap-dev

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags '-extldflags "-static"' \
    -o monitor ./cmd/monitor

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap \
    ca-certificates

# Create non-root user
RUN addgroup -g 1000 nlsn && \
    adduser -D -u 1000 -G nlsn nlsn

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/monitor .

# Can't run as non-root due to packet capture requirements
# Will run as root with capabilities

ENTRYPOINT ["/app/monitor"]
