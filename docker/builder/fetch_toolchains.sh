#!/bin/sh
# Download one pinned ARM GNU toolchain, verify sha256, extract into dest.
# The archive is deleted in this process (or kept only in a BuildKit cache
# mount), so it never becomes a layer in the final image.
#
# Usage: fetch_toolchains.sh <lock> <dest> <identity>
set -eu
LOCK=${1:?lock}
DEST=${2:?dest}
WANT=${3:?identity}

identity=""
version=""
sha256=""
url=""
while read -r a b c d extra; do
    case "$a" in
        ''|\#*) continue ;;
    esac
    if [ "$a" = "$WANT" ]; then
        identity=$a
        version=$b
        sha256=$c
        url=$d
        break
    fi
done < "$LOCK"

if [ -z "$url" ]; then
    echo "fetch_toolchains: unknown identity $WANT" >&2
    exit 1
fi

mkdir -p "$DEST"

if [ -d /var/cache/arm-toolchains ] && [ -w /var/cache/arm-toolchains ]; then
    cache_dir=/var/cache/arm-toolchains
    keep_archive=1
else
    cache_dir=$(mktemp -d)
    keep_archive=0
fi
archive=$cache_dir/$sha256
if [ ! -f "$archive" ]; then
    curl -fL --retry 5 --retry-delay 2 -o "$archive.part" "$url"
    echo "$sha256  $archive.part" | sha256sum -c -
    mv "$archive.part" "$archive"
fi
echo "$sha256  $archive" | sha256sum -c -

case "$url" in
    *.tar.xz) tar -xJf "$archive" --strip-components=1 -C "$DEST" ;;
    *.tar.bz2) tar -xjf "$archive" --strip-components=1 -C "$DEST" ;;
    *)
        echo "fetch_toolchains: unsupported archive $url" >&2
        exit 1
        ;;
esac

if [ "$keep_archive" -eq 0 ]; then
    rm -rf "$cache_dir"
fi

# Docs, not multilib. Leaving them in triples the share/ tree for no compile.
rm -rf "$DEST/share/doc" "$DEST/share/man" "$DEST/share/info"

printf '{"id":"%s","release":"%s"}\n' "$identity" "$version" > "$DEST/identity.json"
chmod -R a+rX "$DEST"

if [ ! -x "$DEST/bin/arm-none-eabi-gcc" ]; then
    echo "fetch_toolchains: missing $DEST/bin/arm-none-eabi-gcc" >&2
    exit 1
fi
if [ ! -f "$DEST/arm-none-eabi/include/string.h" ]; then
    echo "fetch_toolchains: missing string.h under $DEST" >&2
    exit 1
fi
echo "installed $identity $version -> $DEST"
