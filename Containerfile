# syntax=docker/dockerfile:1
# Build a small, static NetAnchor image suitable for Podman or Docker.

# ---- build stage --------------------------------------------------------
# Run the compiler natively on the build host (BUILDPLATFORM) and cross-compile
# to the requested target, so multi-arch builds (amd64 / arm64 / armv7) are fast
# and don't need QEMU for the Go build itself.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
WORKDIR /src

ARG VERSION=dev
# These are provided automatically by Docker buildx / Podman-Buildah.
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# Module files first for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Fully static, stripped binary. CGO is off so it runs on a minimal base.
# GOARM is derived from the variant (e.g. "v7" -> 7) and ignored for non-arm.
RUN CGO_ENABLED=0 \
      GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
      go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /netanchor .

# ---- runtime stage ------------------------------------------------------
FROM alpine:3.20

ARG VERSION=dev
LABEL org.opencontainers.image.title="NetAnchor" \
      org.opencontainers.image.description="A simple, web-based certificate authority written in pure Go." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

# Non-root user; create the data dir owned by it so a fresh named volume
# inherits the right ownership via Podman/Docker volume copy-up.
RUN adduser -D -u 65532 netanchor \
 && mkdir -p /data \
 && chown netanchor:netanchor /data

COPY --from=build /netanchor /usr/local/bin/netanchor

USER netanchor
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8443

# Bind to all interfaces inside the container so the published port is reachable.
# TLS and authentication are ON by default; see the README for NETANCHOR_TLS,
# NETANCHOR_TLS_HOSTS, NETANCHOR_CA_PASSPHRASE and NETANCHOR_DISABLE_AUTH.
ENV NETANCHOR_ADDR=0.0.0.0:8443 \
    NETANCHOR_DATA=/data

# The binary self-probes /healthz (no extra tools needed; tolerates the
# self-signed TLS cert).
HEALTHCHECK --interval=30s --timeout=3s --start-period=3s \
  CMD ["netanchor", "-health"]

ENTRYPOINT ["netanchor"]
