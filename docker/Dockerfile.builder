# Reference-library builder. One image per toolchain version; the tag IS the
# compiler. Do not tag this :latest — corpus quality depends on spanning GCC
# releases, and a floating tag would hide which one produced an object.
#
#   docker build -f docker/Dockerfile.builder \
#     --build-arg BASE_IMAGE=ubuntu:22.04 --build-arg TOOLCHAIN_TAG=gcc10 \
#     -t ghidra-builder:gcc10 .
#   docker build -f docker/Dockerfile.builder \
#     --build-arg BASE_IMAGE=debian:bookworm --build-arg TOOLCHAIN_TAG=gcc12 \
#     -t ghidra-builder:gcc12 .
#   docker build -f docker/Dockerfile.builder \
#     --build-arg BASE_IMAGE=ubuntu:24.04 --build-arg TOOLCHAIN_TAG=gcc13 \
#     -t ghidra-builder:gcc13 .
#
# Distro → gcc-arm-none-eabi (the reason this is parameterised at all):
#   ubuntu:22.04   gcc 10.x
#   debian:bookworm gcc 12.x
#   ubuntu:24.04   gcc 13.x
#
# pico-sdk firmware is commonly GCC 10–12. Matching littlefs built with GCC
# 13.2 produced the right names at 0.27–0.35 similarity; the firmware's
# lfs_dir_fetchmatch was ~300 bytes larger than any GCC-13 object. The
# corpus has to span the compilers, not just the library versions.
#
# libnewlib-arm-none-eabi is a Recommends of gcc-arm-none-eabi, not a
# Depends. --no-install-recommends would drop <string.h> and every other
# libc header; a -c compile of littlefs then dies with "string.h: No such
# file or directory". Install it explicitly.

ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ARG TOOLCHAIN_TAG=gcc13
ENV TOOLCHAIN_TAG=${TOOLCHAIN_TAG}
ENV BUILDER_PORT=8092
ENV BUILDER_CC=arm-none-eabi-gcc
ENV TZ=UTC
ENV LC_ALL=C
ENV LANG=C
ENV GHIDRA_MCP_FILE_ROOT=/data

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        make \
        python3 \
        gcc-arm-none-eabi \
        binutils-arm-none-eabi \
        libnewlib-arm-none-eabi \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

COPY docker/builder/ghidra_build_reference.py /usr/local/bin/ghidra-build-reference
RUN chmod 0755 /usr/local/bin/ghidra-build-reference \
    && sed -i 's/\r$//' /usr/local/bin/ghidra-build-reference

# Same uid as ghidra-mcp. Anything written to the shared /data mount must be
# readable by the headless server; uid mismatch on that volume has already
# failed imports.
RUN (getent passwd 1000 && userdel -r "$(getent passwd 1000 | cut -d: -f1)" || true) \
    && (getent group 1000 && groupdel "$(getent group 1000 | cut -d: -f1)" || true) \
    && groupadd --gid 1000 builder \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/builder builder \
    && mkdir -p /src /data/uploads \
    && chown -R builder:builder /src /data /home/builder

USER builder
WORKDIR /src
EXPOSE 8092
VOLUME ["/src", "/data"]

# /health is unauthenticated so this check does not put GHIDRA_MCP_AUTH_TOKEN
# on the process command line. POST /build still requires the token.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8092/health')"

ENTRYPOINT ["python3", "/usr/local/bin/ghidra-build-reference"]
CMD ["serve"]
