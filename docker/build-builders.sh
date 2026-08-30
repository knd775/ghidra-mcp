#!/bin/sh
# Optional local helper: same one-image build Compose / Portainer already
# run. The operator path is `docker compose up --build`. Corpus updates go
# through build_manifest / build_reference, not this script.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
docker build -f "$root/docker/Dockerfile.builder" -t ghidra-builder "$root"
