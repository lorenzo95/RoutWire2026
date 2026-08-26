# meshd: decentralized WireGuard mesh daemon (kernel WG + OpenDHT roster).
# Build:   docker build -t routewire/meshd .
# Run:     docker run -d --name meshd --restart unless-stopped \
#            --network=host --cap-add=NET_ADMIN \
#            -v /etc/meshd.yaml:/etc/meshd.yaml:ro \
#            ghcr.io/lorenzo95/routewire2026 [-config /etc/meshd.yaml]
# The kernel wireguard module lives on the HOST; the container only
# programs it, hence NET_ADMIN + host networking.
#
# Multi-arch: buildx sets TARGETOS/TARGETARCH per platform; the Go
# compilation itself is pure Go, so no QEMU emulation of the toolchain.
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/meshd ./cmd/meshd

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/meshd /usr/local/bin/meshd
ENTRYPOINT ["/usr/local/bin/meshd"]
