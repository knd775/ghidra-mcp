# syntax=docker/dockerfile:1
# One resident builder image holding every shipped toolchain identity.
# The tag is the service, not the compiler: ghidra-builder. Identity
# (gcc10-arm, gcc12-arm, gcc13-arm) selects a prefix under
# /opt/ghidra-builder/toolchains/<identity>/.
#
# Toolchains are pinned ARM GNU releases (docker/builder/toolchains.lock),
# downloaded from developer.arm.com in fetch stages. Distro packages of
# the ARM cross compiler track the archive and are not a corpus pin.
# Official prefixes are relocatable — no pack wrappers, no
# /etc/alternatives. Multilib newlib is left intact.
#
#   docker build -f docker/Dockerfile.builder -t ghidra-builder .
#
# Portainer / `docker compose up --build` is the operator path. There is
# no docker exec, no docker.sock, and no per-toolchain container.
#
# pico-sdk firmware is commonly GCC 10–12. Matching littlefs built with
# GCC 13.2 produced the right names at 0.27–0.35 similarity; the
# firmware's lfs_dir_fetchmatch was ~300 bytes larger than any GCC-13
# object. The corpus has to span the compilers, not just the library
# versions.
#
# Host gcc/g++, cmake, and ninja are for framework stubs: pico-sdk's
# pioasm is a nested host build. Do not set CC/CXX in ENV.

FROM debian:bookworm-slim AS fetch-deps
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        xz-utils \
        bzip2 \
    && rm -rf /var/lib/apt/lists/*
COPY docker/builder/toolchains.lock /tmp/toolchains.lock
COPY docker/builder/fetch_toolchains.sh /tmp/fetch_toolchains.sh
RUN sed -i 's/\r$//' /tmp/fetch_toolchains.sh /tmp/toolchains.lock \
    && chmod 0755 /tmp/fetch_toolchains.sh

FROM fetch-deps AS gcc10
RUN --mount=type=cache,target=/var/cache/arm-toolchains \
    /tmp/fetch_toolchains.sh /tmp/toolchains.lock /out gcc10-arm

FROM fetch-deps AS gcc12
RUN --mount=type=cache,target=/var/cache/arm-toolchains \
    /tmp/fetch_toolchains.sh /tmp/toolchains.lock /out gcc12-arm

FROM fetch-deps AS gcc13
RUN --mount=type=cache,target=/var/cache/arm-toolchains \
    /tmp/fetch_toolchains.sh /tmp/toolchains.lock /out gcc13-arm

FROM debian:bookworm-slim
ENV BUILDER_PORT=8092
ENV TZ=UTC
ENV LC_ALL=C
ENV LANG=C
ENV GHIDRA_MCP_FILE_ROOT=/data
ENV GHIDRA_MCP_STUBS=/opt/ghidra-builder/stubs
ENV GHIDRA_MCP_TOOLCHAINS=/opt/ghidra-builder/toolchains

# Pins are the lock file; labels are what `docker inspect` shows.
LABEL org.ghidra-mcp.toolchain.gcc10-arm="10.3-2021.10" \
      org.ghidra-mcp.toolchain.gcc12-arm="12.2.Rel1" \
      org.ghidra-mcp.toolchain.gcc13-arm="13.2.Rel1"

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        make \
        cmake \
        ninja-build \
        python3 \
        gcc \
        g++ \
        findutils \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

COPY --from=gcc10 --chown=1000:1000 /out /opt/ghidra-builder/toolchains/gcc10-arm
COPY --from=gcc12 --chown=1000:1000 /out /opt/ghidra-builder/toolchains/gcc12-arm
COPY --from=gcc13 --chown=1000:1000 /out /opt/ghidra-builder/toolchains/gcc13-arm

# Same uid as ghidra-mcp. Numeric --chown on COPY means prefixes are
# already uid 1000; do not chown -R the toolchain tree (that layer
# doubled the image).
RUN (getent passwd 1000 && userdel -r "$(getent passwd 1000 | cut -d: -f1)" || true) \
    && (getent group 1000 && groupdel "$(getent group 1000 | cut -d: -f1)" || true) \
    && groupadd --gid 1000 builder \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/builder builder \
    && mkdir -p /src /data/uploads \
    && chown -R builder:builder /src /data /home/builder

COPY --chown=1000:1000 docker/builder/ /usr/local/lib/ghidra-builder/
COPY --chown=1000:1000 docker/stubs/ /opt/ghidra-builder/stubs/
RUN chmod 0755 /usr/local/lib/ghidra-builder/ghidra_build_reference.py \
        /usr/local/lib/ghidra-builder/fetch_toolchains.sh \
    && find /usr/local/lib/ghidra-builder -name '*.py' -exec sed -i 's/\r$//' {} \; \
    && find /opt/ghidra-builder/stubs -type f -exec sed -i 's/\r$//' {} \;

USER builder
WORKDIR /src
EXPOSE 8092
VOLUME ["/src", "/data"]

# Internal network only. No host ports, no auth token on the process line.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8092/health')"

ENTRYPOINT ["python3", "/usr/local/lib/ghidra-builder/ghidra_build_reference.py"]
CMD ["serve"]
