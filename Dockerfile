# Build
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
WORKDIR /build

# Dependency installation
COPY go.mod go.sum ./
RUN go mod download

# Build the app from source
COPY . .
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o upload-sbom-go .

# Runime image
FROM gcr.io/distroless/static:latest

# Copy only the binary from the build stage to the final image
COPY --from=build /build/upload-sbom-go /

# Set the entry point for the container
ENTRYPOINT ["/upload-sbom-go"]