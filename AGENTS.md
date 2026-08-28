# AGENTS.md

Notes for AI coding agents (and humans) working on this repository.

## What this is

`routewire` is a single Go module implementing `meshd`: a decentralized
WireGuard mesh daemon. Membership = PSK + node name; coordination = OpenDHT;
no servers anywhere. The legacy shell-script ancestor lives in `docs/legacy/`.

## Layout

```
cmd/meshd/          CLI: subcommands, config resolution, service management
cmd/keydump/        debug tool: prints derived WG keys for names (dev only)
internal/mesh/      the product: derivation, roster, daemon loop, device control,
                    router/firewall integration, spokes, export, STUN
internal/engine/    storage substrate: Store interface, OpenDHT proxy client,
                    ReliableStore (put-confirm-get), secretbox crypto, identity/
                    signatures, and the legacy chat Room (unused by meshd)
internal/config/    MeshConfig loading (YAML/JSON) + layered resolution
```

## Commands

```sh
go build ./...          # compile everything
go vet ./...            # must be clean
go test ./...           # full unit suite (~10s); no network or root needed
go build -o meshd ./cmd/meshd   # the binary
```

Integration testing needs two Linux boxes with WireGuard kernel support —
see "Lab conventions" below. Unit tests cover the rest via fakes
(`FakeDevice`, `recRouter`-style recorder, `MockStore`).

## Architecture invariants — do not break these casually

1. **PSK+name derive everything** (`internal/mesh/crypto.go`, HKDF domain
   `routewire/v1`). Never persist key material; a spoke file contains *names
   only* by design.
2. **Everything in the DHT is sealed then confirmed**: records are JSON →
   ed25519-signed (`Record.Sign`) → secretbox-sealed (`sealRecord`,
   key = `Deriver.RosterBoxKey()`). Reads unseal in `Roster.Fetch`; values
   that don't open are skipped. Chat envelopes are likewise fully sealed via
   `Envelope.Marshal(roomKey)` with a deterministic nonce.
3. **`Device.Apply` must merge, never replace.** It converges to the desired
   peer set without touching unrelated peers — wholesale `ReplacePeers`
   destroys live sessions on any transient roster gap (this was a real
   production bug).
4. **Roster reads go through `FetchStable`** (merge across N GETs). Single
   proxy GETs return arbitrary subsets of the value set.
5. **Seq is epoch-seeded monotonic** (`nextSeq` seeds from unix time once per
   process). Per-process counters lose to stale DHT values after restarts.
6. **Spokes are hub-local.** `meshd.spokes` (names only) is re-read every tick;
   the hub derives each spoke's peer + masquerade from the name. Spoke records
   are never published to the DHT; non-hub nodes never see them.
7. **Kernel state is owned by `Router`** (`router.go`): ip_forward, INPUT rule
   for the UDP listen port (both address families — WireGuard's transport is
   dual-stack even though the overlay is v4), per-spoke MASQUERADE. Everything
   it adds is removed on `Close()`; forwarding restores its prior value.
   **Firewall self-heal (inserting accepts into foreign input/forward chains)
   is OPT-IN via `firewall_selfheal` (default off = warn-only)** — the
   un-gated version blanket-patched foreign forward chains at position 0 and
   broke hosts badly enough to need snapshot restores; never widen it without
   an operator asking. Stop-path cleanup (`CleanupFirewall`) is always-on:
   it only removes rules meshd tagged (userdata/iptables comment
   `routewire-meshd`). Announced subnets get reconciling masquerade rules
   (`AnnounceNAT`). Migration note: the remaining iptables jobs are the
   spoke MASQUERADE and legacy-iptables-host coverage; everything else
   already speaks netlink via google/nftables — see router.go before
   removing the iptables dependency.
8. **Subcommand parsing**: `expandSubcommand` finds a subcommand token anywhere
   in argv (so `meshd -config f.yaml peek` works) but skips flag *values* —
   add new value-taking flags to `valueFlags`.

## Testing patterns

- Daemon tests use `newTestDaemon` + `FakeDevice` (handshakes appear only via
  `Traffic()` through applied endpoints) and record-fakes for `Router`.
- Roster/e2e tests run against `engine.NewMockStore`; sealing means tests must
  publish via `sealRecord`/`Roster.Publish`, not raw JSON.
- `device_linux_test.go` tests are root/WG-gated; they skip where unavailable.
- When fixing a field bug, add the regression test in the same commit.

## Lab / deploy conventions (the two-VM acceptance environment)

- Binary: `/usr/local/bin/meshd`; config `/etc/meshd.yaml` (0600); spokes
  `/etc/meshd.spokes`; service `meshd.service` (systemd) — nodes run under
  `Restart=always`, so restart via `systemctl restart meshd`, not pkill.
- Deploy order matters: stage `~/meshd.new` → verify sha256 → stop service →
  `install` → start. Overwriting a running binary fails with ETXTBSY.
- Real-bug history worth knowing: peers got private-as-public keys; seq reset
  on restart killed announcements after every redeploy; ReplacePeers churn
  severed live sessions; single-shot DHT GETs hid fresh announcements; export
  omitted `-announce` routes. Each has a regression test or invariant above.
