# syntax=docker/dockerfile:1

# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Download dependencies first for layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build a statically linked binary; strip debug info to minimise size.
# CGO_ENABLED=0 avoids glibc dependency, keeping the final image at ~10 MB.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o scanner ./cmd/server

# ── Runtime stage ─────────────────────────────────────────────────────────────
# scratch + CA certificates keeps the image minimal and well under Render's
# 512 MB RAM limit for the free tier.
FROM scratch

# CA certs are required for HTTPS calls to external threat intel APIs.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /app/scanner /scanner

EXPOSE 8080

ENTRYPOINT ["/scanner"]
