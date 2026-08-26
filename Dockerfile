# meshd: decentralized WireGuard mesh daemon (kernel WG + OpenDHT roster).
# Build:   docker build -t routewire/meshd .
# Run:     docker run -d --name meshd --restart unless-stopped \
#            --network=host --cap-add=NET_ADMIN \
#            --sysctl net.ipv4.ip_forward=1 \
#            -v /etc/meshd.yaml:/etc/meshd.yaml:ro \
#            ghcr.io/lorenzo95/routewire2026 -config /etc/meshd.yaml
#
# The kernel wireguard module lives on the HOST; the container only programs
# it, hence NET_ADMIN + host networking. With host networking, iptables calls
# inside the container program the HOST's firewall tables. ip_forward is set
# via --sysctl (docker allowlists it); /proc/sys itself is read-only here.
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/meshd ./cmd/meshd

FROM alpine:3.20
RUN apk add --no-cache iptables ca-certificates
COPY --from=build /out/meshd /usr/local/bin/meshd
ENTRYPOINT ["/usr/local/bin/meshd"]
