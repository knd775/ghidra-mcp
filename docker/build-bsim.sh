#!/bin/sh
# Optional local helper. Compose / Portainer pull
# ghcr.io/<owner>/ghidra-mcp-bsim:<tag> (same GHCR_OWNER /
# GHIDRA_MCP_VERSION as the other images). Use this script only when
# you want to rebuild the image on the host instead of pulling.
# Corpus creation is bsim_create_db / bsim_ingest, not this.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
owner=${GHCR_OWNER:-knd775}
tag=${GHIDRA_MCP_VERSION:-dev}
image="ghcr.io/${owner}/ghidra-mcp-bsim:${tag}"
docker build -f "$root/docker/Dockerfile.bsim" -t "$image" "$root"
