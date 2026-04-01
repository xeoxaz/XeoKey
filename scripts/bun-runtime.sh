#!/usr/bin/env bash
set -euo pipefail

BUN_CHANNEL="${XEOKEY_BUN_CHANNEL:-canary}"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/xeokey"
INSTALL_DIR="$CACHE_ROOT/bun-$BUN_CHANNEL"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    ASSET_NAME="bun-linux-x64.zip"
    EXTRACTED_DIR="bun-linux-x64"
    ;;
  *)
    echo "Unsupported platform for bundled Bun runtime: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

BUN_BIN="$INSTALL_DIR/$EXTRACTED_DIR/bun"

if [[ ! -x "$BUN_BIN" ]]; then
  mkdir -p "$INSTALL_DIR"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  curl -fsSL -o "$TMP_DIR/$ASSET_NAME" "https://github.com/oven-sh/bun/releases/download/$BUN_CHANNEL/$ASSET_NAME"
  unzip -q "$TMP_DIR/$ASSET_NAME" -d "$INSTALL_DIR"
fi

export XEOKEY_BUN_BIN="$BUN_BIN"
exec "$BUN_BIN" "$@"