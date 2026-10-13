#!/bin/bash
# Regenerates Resources/AppIcon.icns from Resources/AppIcon.png (a square PNG, 1024px or larger).
set -euo pipefail

cd "$(dirname "$0")/.."

SRC="Resources/AppIcon.png"
SET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$SET"

for SIZE in 16 32 128 256 512; do
    sips -z "$SIZE" "$SIZE" "$SRC" --out "$SET/icon_${SIZE}x${SIZE}.png" >/dev/null
    sips -z "$((SIZE * 2))" "$((SIZE * 2))" "$SRC" --out "$SET/icon_${SIZE}x${SIZE}@2x.png" >/dev/null
done

iconutil -c icns "$SET" -o Resources/AppIcon.icns
echo "Created Resources/AppIcon.icns"
