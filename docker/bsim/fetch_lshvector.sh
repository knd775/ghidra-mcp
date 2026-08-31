#!/bin/sh
# Sparse-clone Ghidra's lshvector sources at the pinned tag/commit, verify
# every git blob against docker/bsim/lshvector.lock, and flatten into dest
# (Makefile expects .c/.h next to it; Ghidra ships them under c/).
#
# Usage: fetch_lshvector.sh <lock> <dest>
set -eu
LOCK=${1:?lock}
DEST=${2:?dest}

commit=""
tag=""
ghidra=""
while read -r a b extra; do
    case "$a" in
        ''|\#*) continue ;;
        commit) commit=$b ;;
        tag) tag=$b ;;
        ghidra) ghidra=$b ;;
    esac
done < "$LOCK"

if [ -z "$commit" ] || [ -z "$tag" ]; then
    echo "fetch_lshvector: lock is missing commit/tag" >&2
    exit 1
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

git clone --filter=blob:none --sparse --branch "$tag" --depth 1 \
    https://github.com/NationalSecurityAgency/ghidra.git "$workdir/ghidra"
cd "$workdir/ghidra"
git sparse-checkout set Ghidra/Features/BSim/src/lshvector

head=$(git rev-parse HEAD)
if [ "$head" != "$commit" ]; then
    echo "fetch_lshvector: HEAD $head does not match pinned commit $commit (tag $tag, ghidra $ghidra)" >&2
    exit 1
fi

src=Ghidra/Features/BSim/src/lshvector
if [ ! -f "$src/Makefile.lshvector" ]; then
    echo "fetch_lshvector: Makefile.lshvector missing after sparse checkout" >&2
    exit 1
fi

failed=0
while read -r path blob extra; do
    case "$path" in
        ''|\#*|commit|tag|ghidra) continue ;;
    esac
    file="$src/$path"
    if [ ! -f "$file" ]; then
        echo "fetch_lshvector: missing $path" >&2
        failed=1
        continue
    fi
    got=$(git hash-object "$file")
    if [ "$got" != "$blob" ]; then
        echo "fetch_lshvector: $path blob $got != pinned $blob" >&2
        failed=1
    fi
done < "$LOCK"
if [ "$failed" -ne 0 ]; then
    exit 1
fi

mkdir -p "$DEST"
cp "$src/Makefile.lshvector" "$src/lshvector.control" "$src/lshvector--1.0.sql" "$DEST/"
cp "$src/c/"*.c "$src/c/"*.h "$DEST/"
echo "fetch_lshvector: pinned ghidra $ghidra ($tag $commit) -> $DEST"
