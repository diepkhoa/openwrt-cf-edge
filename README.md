# cf-edge

Lightweight, event-driven Cloudflare DDNS, PPPoE watchdog, and Edge Shield daemon for OpenWrt (`linux/arm64`, `linux/amd64`), compiled as a single static Pure Go binary (`CGO_ENABLED=0`).

## Quick Install (OpenWrt)

On routers without `curl` (uses `uclient-fetch` against `raw.githubusercontent.com` to avoid GitHub Releases >4 KB redirect headers, then auto-installs `curl` to download the verified release binary):

```sh
uclient-fetch -4 -O /tmp/install.sh https://raw.githubusercontent.com/diepkhoa/openwrt-cf-edge/main/openwrt/install.sh && sh /tmp/install.sh
```

Or if `curl` is already installed:

```sh
curl -fsSL https://raw.githubusercontent.com/diepkhoa/openwrt-cf-edge/main/openwrt/install.sh | sh
```

Edit `/etc/cf-edge/config.yaml` (see [`configs/config.example.yaml`](configs/config.example.yaml)), then start the service:

```sh
chmod 600 /etc/cf-edge/config.yaml
/etc/init.d/cf-edge start
```

## CLI Usage

```text
cf-edge daemon
cf-edge update [--force]
cf-edge status [--json]
cf-edge validate [--json]
cf-edge restart
cf-edge shield <enter [--no-redial] | exit | status>
cf-edge firewall <render | apply [--refresh] | remove | status [--json]>
cf-edge self-update [--check] [--version vX.Y.Z] [--no-restart]
cf-edge version [--json]
```

*(Pass `-c <path>` to override `/etc/cf-edge/config.yaml`; `cf-edge self-update` automatically restarts `/etc/init.d/cf-edge` on OpenWrt unless `--no-restart` is set.)*

See [ARCHITECTURE.md](ARCHITECTURE.md) for package structure and build instructions.
