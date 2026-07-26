#!/usr/bin/env bash
# Rebuild the release binary and install it onto PATH (~/.local/bin by default).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${VANGUARD_PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
DEST="$BIN_DIR/vanguard"

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
