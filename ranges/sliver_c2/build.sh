#!/usr/bin/env bash
# Build the real Sliver C2 server image for duelswarm red_infra.
# Downloads the pinned Sliver release binaries (BishopFox/sliver) into this build context
# (they are .gitignored — ~300MB server, which bundles the offline implant-build toolchain),
# then builds the image. Needs host internet egress for the download only; the image runs
# fully offline afterward (assets are unpacked into the image at build time).
set -euo pipefail
cd "$(dirname "$0")"
SLIVER_VERSION="${SLIVER_VERSION:-v1.7.8}"
ARCH="${ARCH:-amd64}"
base="https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}"
[ -f sliver-server ] || curl -sSL -o sliver-server "${base}/sliver-server_linux-${ARCH}"
[ -f sliver-client ] || curl -sSL -o sliver-client "${base}/sliver-client_linux-${ARCH}"
chmod +x sliver-server sliver-client
docker build -t "duelswarm-sliver-c2:${SLIVER_VERSION}" .
echo "built duelswarm-sliver-c2:${SLIVER_VERSION}"
