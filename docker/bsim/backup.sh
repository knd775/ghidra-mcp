#!/bin/bash
# Daily pg_dump of both BSim databases, plus a tar of ghidra-repos when
# that volume is mounted read-only at /repos. Rotate dumps older than
# BACKUP_KEEP_DAYS. SSL is required: this talks to ghidra-bsim over TCP.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
PGHOST="${PGHOST:-ghidra-bsim}"
PGUSER="${PGUSER:-bsim}"
PGSSLMODE="${PGSSLMODE:-require}"
export PGHOST PGUSER PGSSLMODE PGPASSWORD

mkdir -p "$BACKUP_DIR"

dump_one() {
    db=$1
    exists=$(psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$db'")
    if [ "$exists" != "1" ]; then
        echo "skip $db (not created yet; bsim_create_db first)"
        return 0
    fi
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    out="$BACKUP_DIR/${db}-${stamp}.dump"
    echo "pg_dump $db -> $out"
    pg_dump -Fc --no-owner --dbname="$db" --file="$out"
}

dump_repos() {
    if [ ! -d /repos ]; then
        return 0
    fi
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    out="$BACKUP_DIR/ghidra-repos-${stamp}.tar"
    echo "tar /repos -> $out"
    tar -C / -cf "$out" repos
}

rotate() {
    find "$BACKUP_DIR" -type f \( -name '*.dump' -o -name 'ghidra-repos-*.tar' \) \
        -mtime "+$KEEP_DAYS" -print -delete || true
}

while true; do
    dump_one embedded
    dump_one userland
    dump_repos
    rotate
    echo "next dump in ${INTERVAL}s"
    sleep "$INTERVAL"
done
