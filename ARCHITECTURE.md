# Architecture Overview: `cf-edge`

`cf-edge` is structured as a modular Pure Go application (`CGO_ENABLED=0`) targeting OpenWrt routers (`linux/arm64` and `linux/amd64`).

## Design Principles
- **Config vs. Runtime State separation**: `/etc/cf-edge/config.yaml` is read-only; dynamic runtime state is persisted atomically in RAM (`/tmp/cf-edge-state.json`) with file locking; persistent lock state is stored on flash (`/etc/cf-edge/shield.lock`).
- **Minimal OS footprint**: communicates with OpenWrt `ubus`, Linux Netlink, `/proc`/`/sys`, raw ICMP sockets, and `nftables` (`fw4`) directly without spawning heavy shell scripts.
- **Testable I/O boundaries**: external system, DNS, and HTTP calls are abstracted behind Go interfaces for offline unit testing.

## Project Layout
```text
cmd/cf-edge/          CLI entrypoint, daemon supervisor, subcommands & self-update
internal/
  config/             YAML configuration loading, defaults & validation
  state/              Atomic runtime state persistence (tmpfs + flock) & shield lock
  ubus/               OpenWrt ubus client & reconnecting interface event listener
  netutil/            IP classification, Linux Netlink & interface-bound ICMP ping
  ipwatch/            Parallel IPv4/IPv6 WAN discovery & event-driven watcher
  cloudflare/         Cloudflare DNS v4 client & serialized record sync engine
  reconcile/          Direct UDP/TCP DNS resolver & periodic drift reconciler
  pppoeguard/         Optional WAN/PPPoE health monitor & recovery state machine
  ddos/               Optional traffic monitor, nftables shield & worker integration
  notify/             Telegram Bot notification client
openwrt/              procd init script & POSIX sh installer
configs/              Starter YAML configuration template
.github/workflows/    CI unit tests, vet & multi-arch static release builds
```

## Build & Test
```sh
# Run unit tests
go test -race ./...

# Build static binary for OpenWrt (arm64 example)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o cf-edge ./cmd/cf-edge
```
