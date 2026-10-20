#!/usr/bin/env bash
# Re-sync the bundled web UI (webui/) from the Muse artifact's latest
# production build. Run this after the artifact is edited through the
# Muse artifact tools, so native/Docker deployments keep showing the
# exact same interface as the artifact tab (1:1).
#
# Source: the artifact project's client/dist (built by the artifact
# builder — never build it by hand).
set -euo pipefail

SRC="${1:-$HOME/workspace/ts-spaces/pentest-toolkit/client/dist}"
DST="$(cd "$(dirname "$0")" && pwd)/webui"

if [ ! -f "$SRC/index.html" ]; then
  echo "source bundle not found at: $SRC" >&2
  exit 1
fi

rm -rf "$DST"
mkdir -p "$DST"
cp -r "$SRC"/. "$DST"/
echo "webui synced from $SRC"
grep -o 'V1\.[0-9]*\.[0-9]*' "$DST"/assets/*.js | head -1 || true
