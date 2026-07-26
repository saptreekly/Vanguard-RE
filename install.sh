#!/usr/bin/env bash
# Rebuild the release binary and install it onto PATH (~/.local/bin by default).
# Also builds the optional Speakeasy Docker image used for Fort Knox dynamic analysis.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${VANGUARD_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
DEST="$BIN_DIR/vanguard"
SPEAKEASY_IMAGE="${VANGUARD_SPEAKEASY_IMAGE:-vanguard-speakeasy:latest}"

cd "$ROOT"

echo "==> cargo build --release"
cargo build --release

SRC="$ROOT/target/release/vanguard"
if [[ ! -x "$SRC" ]]; then
  echo "error: expected binary at $SRC" >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
# Write to a temp name then rename so PATH never sees a half-written binary.
tmp="$DEST.tmp.$$"
cp "$SRC" "$tmp"
chmod 755 "$tmp"
mv -f "$tmp" "$DEST"

echo "==> installed $DEST"
echo "    $(ls -la "$DEST")"

if ! command -v vanguard >/dev/null 2>&1; then
  echo
  echo "warning: 'vanguard' is not on PATH yet."
  echo "add this to your shell rc if needed:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
elif [[ "$(command -v vanguard)" != "$DEST" ]]; then
  echo
  echo "warning: PATH resolves to $(command -v vanguard), not $DEST"
else
  echo "==> PATH OK: $(command -v vanguard)"
fi

# Optional Fort Knox Speakeasy image (skip with VANGUARD_SKIP_DOCKER=1).
if [[ "${VANGUARD_SKIP_DOCKER:-0}" == "1" ]]; then
  echo "==> docker: skipped (VANGUARD_SKIP_DOCKER=1)"
elif ! command -v docker >/dev/null 2>&1; then
  echo "==> docker: not installed — dynamic analysis will stay skipped"
  echo "    install Docker, then: docker build -t $SPEAKEASY_IMAGE ./docker/speakeasy"
elif ! docker info >/dev/null 2>&1; then
  echo "==> docker: daemon not running — dynamic analysis will stay skipped"
  echo "    start Docker, then: docker build -t $SPEAKEASY_IMAGE ./docker/speakeasy"
else
  echo "==> docker build -t $SPEAKEASY_IMAGE ./docker/speakeasy"
  docker build -t "$SPEAKEASY_IMAGE" "$ROOT/docker/speakeasy"
  echo "==> docker image ready: $SPEAKEASY_IMAGE"
  if img_id="$(docker image inspect --format '{{.Id}}' "$SPEAKEASY_IMAGE" 2>/dev/null)"; then
    echo "==> image id: $img_id"
    # Strip tag / digest from the ref to suggest a content pin.
    pin_base="${SPEAKEASY_IMAGE%%@*}"
    pin_base="${pin_base%%:*}"
    echo "    digest pin: VANGUARD_SPEAKEASY_IMAGE=${pin_base}@${img_id}"
    echo "    (tag is fine too — the CLI banner shows this id when isolation is ready)"
  fi
fi
