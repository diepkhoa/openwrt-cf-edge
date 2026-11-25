# `cf-edge`

Lightweight, event-driven Cloudflare DDNS, PPPoE watchdog, and Edge Shield daemon for OpenWrt (`linux/arm64`, `linux/amd64`).

## Highlights
- **Pure Go static binary (`CGO_ENABLED=0`)**: no external runtime dependencies (`curl`, `jq`, `awk`, `nslookup` not required), tuned for low-memory routers (`GOMEMLIMIT=32MiB`).
- **Event-driven IP sync**: listens to OpenWrt `ubus` interface events for fast IPv4/IPv6 Cloudflare DNS updates with state caching in `/tmp`.
- **Periodic DNS reconciliation**: verifies public DNS consistency for unproxied records.
- **Optional PPPoE Guard & Edge Shield**: automated WAN recovery and `nftables` ingress protection controls.
- **Single-binary CLI & OTA**: built-in `self-update` with SHA256 verification and `procd` service support.

## CLI Commands
```text
cf-edge daemon [-c /etc/cf-edge/config.yaml]
cf-edge update [-c /etc/cf-edge/config.yaml] [--force]
cf-edge status [-c /etc/cf-edge/config.yaml]
cf-edge shield [-c /etc/cf-edge/config.yaml] <enter [--no-redial] | exit | status>
cf-edge self-update [--check] [--restart] [--version vX.Y.Z] [--repo owner/repo]
cf-edge version
```

## Quick Install (OpenWrt)
```sh
sh -c "$(uclient-fetch -qO- https://github.com/diepkhoa/openwrt-cf-edge/releases/latest/download/install.sh)"
```
Edit `/etc/cf-edge/config.yaml` (see [`configs/config.example.yaml`](configs/config.example.yaml)), then start the service:
```sh
/etc/init.d/cf-edge start
```
