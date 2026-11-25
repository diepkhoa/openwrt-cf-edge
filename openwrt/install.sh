#!/bin/sh
set -eu

REPO="${CF_EDGE_REPO:-diepkhoa/openwrt-cf-edge}"
VERSION="${CF_EDGE_VERSION:-latest}"
BIN_PATH="/usr/bin/cf-edge"
INIT_PATH="/etc/init.d/cf-edge"
CONF_DIR="/etc/cf-edge"
CONF_PATH="${CONF_DIR}/config.yaml"

log() {
	printf '[cf-edge-install] %s\n' "$1"
}

detect_arch() {
	case "$(uname -m)" in
		aarch64|arm64) echo "arm64" ;;
		x86_64|amd64)  echo "amd64" ;;
		*)
			log "Unsupported architecture: $(uname -m)"
			exit 1
			;;
	esac
}

ensure_tls_certs() {
	if [ -f /etc/ssl/certs/ca-certificates.crt ] || [ -f /etc/ssl/cert.pem ]; then
		return 0
	fi
	if command -v apk >/dev/null 2>&1; then
		log "Installing ca-bundle via apk..."
		apk update >/dev/null 2>&1 || true
		apk add ca-bundle >/dev/null 2>&1 || true
	elif command -v opkg >/dev/null 2>&1; then
		log "Installing ca-bundle via opkg..."
		opkg update >/dev/null 2>&1 || true
		opkg install ca-bundle >/dev/null 2>&1 || true
	fi
}

fetch_file() {
	url="$1"
	dest="$2"
	if command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O "$dest" "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$dest" "$url"
	else
		log "Error: neither uclient-fetch nor wget is available"
		exit 1
	fi
}

ARCH="$(detect_arch)"
ensure_tls_certs

if [ "$VERSION" = "latest" ]; then
	BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
	BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BIN_NAME="cf-edge-linux-${ARCH}"
log "Downloading ${BIN_NAME} from ${BASE_URL}..."
fetch_file "${BASE_URL}/${BIN_NAME}" "${TMP_DIR}/${BIN_NAME}"
fetch_file "${BASE_URL}/checksums.txt" "${TMP_DIR}/checksums.txt"

log "Verifying SHA256 checksum..."
(
	cd "$TMP_DIR"
	grep " ${BIN_NAME}\$" checksums.txt > target.sha256
	sha256sum -c target.sha256
)

chmod 0755 "${TMP_DIR}/${BIN_NAME}"
mv "${TMP_DIR}/${BIN_NAME}" "${BIN_PATH}"
log "Installed binary to ${BIN_PATH}"

if fetch_file "${BASE_URL}/cf-edge.init" "${TMP_DIR}/cf-edge.init" 2>/dev/null; then
	chmod 0755 "${TMP_DIR}/cf-edge.init"
	mv "${TMP_DIR}/cf-edge.init" "${INIT_PATH}"
	log "Installed procd init script to ${INIT_PATH}"
fi

mkdir -p "${CONF_DIR}"
if [ ! -f "${CONF_PATH}" ]; then
	if fetch_file "${BASE_URL}/config.example.yaml" "${TMP_DIR}/config.example.yaml" 2>/dev/null; then
		chmod 0600 "${TMP_DIR}/config.example.yaml"
		mv "${TMP_DIR}/config.example.yaml" "${CONF_PATH}"
		log "Created starter config at ${CONF_PATH} (please edit before starting)"
	fi
else
	log "Existing config preserved at ${CONF_PATH}"
fi

if [ -x "${INIT_PATH}" ]; then
	"${INIT_PATH}" enable || true
fi

log "Installation complete. Edit ${CONF_PATH} and run: ${INIT_PATH} start"
