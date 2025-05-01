FROM golang:1.22-alpine as builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libpcap-dev upx ca-certificates

# Create working directory
WORKDIR /app

# Copy Go module files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -o ppanther -ldflags "-s -w" ./cmd/ppanther

# Compress the binary with UPX
RUN upx -9 ppanther

# Create minimal scratch image
FROM scratch

# Copy CA certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy libpcap.so for packet capture
COPY --from=builder /usr/lib/libpcap.so.* /usr/lib/

# Copy the binary
COPY --from=builder /app/ppanther /ppanther
COPY --from=builder /app/web /web

# Set entrypoint
ENTRYPOINT ["/ppanther"]

# Default command flags
CMD ["--interface", "eth0", "--web-port", "8080"]

# Expose web port
EXPOSE 8080

# Label the image
LABEL org.opencontainers.image.source=https://github.com/Samirrahman71/PacketPanther
LABEL org.opencontainers.image.description="All-in-one network utility for packet capture, tracing, port scanning, and SNMP polling"
LABEL org.opencontainers.image.licenses=MIT
