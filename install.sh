#!/bin/sh
# RoutWire2026 / meshd installer.
#
#   curl -fsSL https://raw.githubusercontent.com/lorenzo95/RoutWire2026/main/install.sh | sudo sh
#
# Env overrides: BINDIR=/usr/local/bin, VERSION=v0.1.0 (pin a release).
set -e

REPO="lorenzo95/RoutWire2026"
BINDIR="${BINDIR:-/usr/local/bin}"

case "$(uname -s)/$(uname -m)" in
Linux/x86_64 | Linux/amd64) ARCH=amd64 ;;
Linux/aarch64 | Linux/arm64) ARCH=arm64 ;;
Linux/armv7* | Linux/armv6*) ARCH=arm ;;
*)
    echo "unsupported platform: $(uname -s)/$(uname -m)" >&2
    exit 1
    ;;
esac

if [ -z "$VERSION" ]; then
    VERSION=$(
        curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
            sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'
    )
fi
[ -n "$VERSION" ] || {
    echo "could not determine latest release" >&2
    exit 1
}
VER="${VERSION#v}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "installing meshd $VERSION ($ARCH) ..."
curl -fsSL -o "$TMP/meshd.tar.gz" \
    "https://github.com/$REPO/releases/download/$VERSION/meshd_${VER}_linux_${ARCH}.tar.gz"
curl -fsSL -o "$TMP/checksums.txt" \
    "https://github.com/$REPO/releases/download/$VERSION/checksums.txt"

# verify checksum when the tooling exists
if command -v sha256sum >/dev/null 2>&1; then
    WANT=$(grep "meshd_${VER}_linux_${ARCH}.tar.gz" "$TMP/checksums.txt" | awk '{print $1}')
    GOT=$(sha256sum "$TMP/meshd.tar.gz" | awk '{print $1}')
    [ "$WANT" = "$GOT" ] || {
        echo "checksum mismatch!" >&2
        exit 1
    }
fi

tar -xzf "$TMP/meshd.tar.gz" -C "$TMP"
install -m755 "$TMP/meshd" "$BINDIR/meshd"
echo "installed $(meshd -h >/dev/null 2>&1 && echo ok): $BINDIR/meshd"
echo
echo "next steps:"
echo "  sudo meshd init                    # create /etc/meshd.yaml + generate PSK"
echo "  sudo meshd service -install        # run as a boot-persistent service"
echo "  meshd peek                         # inspect the live mesh roster"
