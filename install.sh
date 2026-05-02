#!/bin/sh
# zig-version-kit stage0 installer (POSIX)
#
# Downloads a prebuilt `zvk` binary, runs `zvk self-install` (places it on PATH)
# then `zvk install` (installs the latest Zig nightly to ~/.zoptia/zig/).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/zoptia/zig-version-kit/main/install.sh | sh
#
# Env:
#   ZVK_VERSION   release tag to pin to (default: "latest")

set -eu

REPO="zoptia/zig-version-kit"
VERSION="${ZVK_VERSION:-latest}"

case "$(uname -s)" in
    Linux)  os=linux-musl ;;
    Darwin) os=macos ;;
    *) echo "[zvk] unsupported OS: $(uname -s) (use install.ps1 on Windows)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo "[zvk] unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="zvk-${arch}-${os}"
if [ "$VERSION" = "latest" ]; then
    url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
    url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
zvk="$tmp/zvk"

echo "[zvk] downloading $url"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$zvk"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$zvk" "$url"
else
    echo "[zvk] need curl or wget" >&2; exit 1
fi
chmod +x "$zvk"

"$zvk" self-install
"$zvk" install
