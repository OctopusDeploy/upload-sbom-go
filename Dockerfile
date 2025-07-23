FROM golang:1.24-alpine AS builder
WORKDIR /build

# Copy Go source code
COPY . .

# Download dependencies
RUN go mod tidy

# Build statically linked binary
RUN CGO_ENABLED=0 go build -o sbom-uploader

# ---- Final Minimal Image ----
FROM alpine:3.19

LABEL maintainer="colby.prior@octopus.com"
WORKDIR /usr/bin

# Copy binary from builder
COPY --from=builder /build/sbom-uploader .

# Make it executable
RUN chmod +x sbom-uploader

# Default command
ENTRYPOINT ["sbom-uploader"]
