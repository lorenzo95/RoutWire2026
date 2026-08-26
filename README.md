# RoutWire2026

A decentralized, serverless [WireGuard](https://www.wireguard.com/) mesh daemon for Linux.

`meshd` turns a group of machines into one encrypted overlay network with **no
coordinator, no control plane, and no stored secrets**. Every node derives its
WireGuard key, signing identity, overlay IP, and the shared roster location
from nothing but the mesh PSK and its own name — then finds and connects to
every other node by itself, over LAN, across NAT, IPv4 or IPv6.

> **Status:** experimental. `meshd` creates real kernel interfaces, routes and
> firewall rules. Run it on machines you own.

## Install

One-liner (Linux amd64/arm64/arm, verifies sha256, installs to `/usr/local/bin`):

```sh
curl -fsSL https://raw.githubusercontent.com/lorenzo95/RoutWire2026/main/install.sh | sudo sh
```

Or grab a tarball directly from [Releases](https://github.com/lorenzo95/RoutWire2026/releases).

Container (host kernel provides WireGuard; container programs it):

```sh
sudo sysctl -w net.ipv4.ip_forward=1        # once per host (needed for spoke NAT)

docker run -d --name meshd --restart unless-stopped \
  --network=host --cap-add=NET_ADMIN \
  -v /etc/meshd.yaml:/etc/meshd.yaml:ro \
  ghcr.io/lorenzo95/routewire2026 [-config /etc/meshd.yaml]
```

Images are multi-arch (amd64/arm64): `ghcr.io/lorenzo95/routewire2026:<tag>` / `:latest`.
With host networking the container's iptables calls program the **host** tables;
`--sysctl` is not permitted under host networking, so set forwarding on the
host as above (meshd degrades gracefully and warns if iptables/forwarding are
unavailable). On networks that intercept TLS add `-dht-insecure` (payloads
remain end-to-end sealed+signed).

## How it works

- **Everything is derived from PSK + name.** A node's WireGuard private key,
  ed25519 signing identity, and overlay IP (`10.99.<hash>` within the mesh
  CIDR) are pure functions of the PSK and the node name (HKDF). Joining the
  mesh requires only the PSK and a free name — there is nothing to exchange.
- **The roster lives in OpenDHT.** Each node periodically publishes a signed,
  **sealed** record: who it is, its overlay IP, listen port, candidate
  addresses (interface IPs + STUN-reflexive mappings) and which subnets it
  serves. Values in the DHT are ciphertext to everyone — including the DHT
  storage operators.
- **Endpoints race, not negotiate.** Each peer tries every candidate pair
  (LAN first when both sides look local, then reflexive) until a WireGuard
  handshake lands; the winner is remembered until it goes stale. This is
  ICE-style connectivity without a signaling server.
- **Spokes for agent-less devices.** Phones, tablets, laptops — anything that
  can load a wg-quick config but can't run `meshd` — get an exported config.
  The hub peers them and source-NATs them into the mesh locally. Spoke names
  never touch the DHT; they live only in `/etc/meshd.spokes` on their hub.

## Quick start (two nodes)

On each machine (Debian/Ubuntu-ish, root):

```sh
# node A — generates the PSK and writes /etc/meshd.yaml
sudo meshd init -name alpha -out /etc/meshd.yaml     # prints the PSK once

# node B — same PSK, different name
sudo MESH_PSK='<psk-from-alpha>' meshd init -name beta -out /etc/meshd.yaml

# install + start as a boot-persistent service on both
sudo meshd -config /etc/meshd.yaml service -install   # auto-detects systemd/sysvinit
```

Within ~45 seconds the nodes find each other. Verify:

```sh
meshd peek                 # live roster from the DHT (names, IPs, candidates)
ping <peer-overlay-ip>     # encrypted by now
```

Serve a local subnet to the whole mesh, and give a phone access:

```sh
sudo systemctl edit --full meshd      # add: ExecStart=... -announce 192.168.50.0/24
sudo systemctl restart meshd          # forwarding is enabled automatically

# enrollment config for an agent-less device (bakes all known routes):
sudo meshd export -remote phone-alice -out phone-alice.conf
sudo meshd remove -remote phone-alice # ...and revoke it later
```

## CLI

| Command | Purpose |
|---|---|
| `meshd` | friendly quick-start help |
| `meshd init [-name N] [-announce CIDR,...] [-out F]` | write a starter config (generates PSK if unset); root defaults to `/etc/meshd.yaml` |
| `meshd [-config F]` | run the node |
| `meshd export -remote NAME [-routes none] [-out F]` | wg-quick config for an agent-less device |
| `meshd remove -remote NAME` | revoke a spoke (hub drops peer + NAT next tick) |
| `meshd peek` | fetch + verify the live DHT roster |
| `meshd service -install/-uninstall [-system auto\|systemd\|sysvinit]` | manage the system service |
| `meshd stop` | delete the interface and exit |

Config precedence: built-in defaults < `-config` file < env (`MESH_PSK`,
`MESH_NAME`) < explicit flags.

## Security model

- The **PSK is the root of trust**: possession lets you derive any node's keys
  and read the roster. Distribute it carefully; rotate = re-init the mesh.
- Roster records are **signed** (ed25519, derived per-name identity) and
  **sealed** (XSalsa20-Poly1305, PSK-derived key). The DHT stores opaque
  blobs; names, IPs and topology are invisible to storage operators.
- Spoke records never exist in the DHT at all — spokes are hub-local state.
- Nodes enable `ip_forward` and open the WireGuard UDP port themselves only as
  needed, and restore prior firewall state on clean shutdown.
- Known trade-off: NAT'd spokes can originate flows but cannot be initiated to
  from the mesh (they're masqueraded, like phones behind a router).

## Building

```sh
go build ./cmd/meshd            # Go 1.25+, CGO not required
docker build -t routewire .     # static binary in a distroless image
```

See [AGENTS.md](AGENTS.md) for architecture notes if you want to hack on it,
and [docs/legacy](docs/legacy) for the original 2024 shell-script experiment
this project grew out of.

## AI-assisted development

This codebase was built openly with heavy AI assistance: an agentic coding
tool ([opencode](https://opencode.ai)) wrote nearly all of the implementation,
driven by a human setting requirements, running acceptance tests on real VMs,
and steering design decisions turn by turn. The full session history — bugs
found in production testing, design arguments, rewrites — shaped what you see
here. Humans set the destination; the agent typed most of the road.

## License

MIT — see [LICENSE](LICENSE).
