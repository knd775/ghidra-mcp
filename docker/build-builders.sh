#!/bin/sh
# Build the three ghidra-builder:<gccN> images. Tags are the compiler; there
# is no :latest. Run from the repo root or from docker/.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
file="$root/docker/Dockerfile.builder"

build_one() {
    tag=$1
    base=$2
    docker build -f "$file" \
        --build-arg "BASE_IMAGE=$base" \
        --build-arg "TOOLCHAIN_TAG=$tag" \
        -t "ghidra-builder:$tag" \
        "$root"
}

build_one gcc10 ubuntu:22.04
build_one gcc12 debian:bookworm
build_one gcc13 ubuntu:24.04
