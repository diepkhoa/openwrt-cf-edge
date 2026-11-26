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
cf-edge daemon [-c /etc/cf-edge/config.yaml]
cf-edge update [-c /etc/cf-edge/config.yaml] [--force]
cf-edge status [-c /etc/cf-edge/config.yaml]
cf-edge shield [-c /etc/cf-edge/config.yaml] <enter [--no-redial] | exit | status>
cf-edge self-update [--check] [--restart] [--version vX.Y.Z] [--repo owner/repo]
cf-edge version
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for package structure and build instructions.
