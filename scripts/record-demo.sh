#!/usr/bin/env bash
# Rebuilds docs/demo.mp4 from the harmless demo target.
#
# Everything runs on 127.0.0.1: docs/make-demo-target.py builds a fake open
# directory on documentation addresses, docs/record-demo.py serves it, starts a
# console against a throwaway runs folder, records and encodes. Nothing here
# sends a request to a real host.
#
# Needs uv, a Playwright Chromium (uv run --with playwright playwright install
# chromium) and an ffmpeg with libx264. Point FFMPEG at one that is not on PATH.

set -euo pipefail

cat <<'BANNER'
 ____  _      ____  _  __ _
|  _ \(_)_ __/ ___|(_)/ _| |_
| | | | | '__\___ \| | |_| __|
| |_| | | |   ___) | |  _| |_
|____/|_|_|  |____/|_|_|  \__|
  demo recorder
BANNER

cd "$(dirname "$0")/.."

FFMPEG="${FFMPEG:-$(command -v ffmpeg || true)}"
if [ -z "$FFMPEG" ]; then
  echo "ffmpeg not found: install one with libx264, or set FFMPEG=/path/to/ffmpeg"
  exit 1
fi

exec uv run --with playwright python docs/record-demo.py --ffmpeg "$FFMPEG" "$@"
