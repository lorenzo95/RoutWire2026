# meshd: decentralized WireGuard mesh daemon (kernel WG + OpenDHT roster).
# Build:   docker build -t routewire/meshd .
# Run:     docker run -d --name meshd --restart unless-stopped \
#            --network=host --cap-add=NET_ADMIN \
#            -e MESH_PSK=<shared-secret> \
#            routewire/meshd [-name node1 ...]
# The kernel wireguard module lives on the HOST; the container only
# programs it, hence NET_ADMIN + host networking.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /meshd ./cmd/meshd

FROM gcr.io/distroless/static-debian12
COPY --from=build /meshd /usr/local/bin/meshd
ENTRYPOINT ["/usr/local/bin/meshd"]
