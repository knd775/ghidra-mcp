#!/bin/bash
# Acceptance 0 + 8 against a running ghidra-mcp-bsim container:
# CREATE EXTENSION lshvector on a fresh database, then prove a non-SSL
# TCP connection is rejected.
#
# Usage: smoke-lshvector.sh <container> [postgres-password]
set -euo pipefail

CONTAINER=${1:?container name or id}
PASSWORD=${2:-test}

exec_psql() {
    docker exec -e PGPASSWORD="$PASSWORD" "$CONTAINER" \
        psql -v ON_ERROR_STOP=1 -U bsim "$@"
}

echo "CREATE EXTENSION lshvector on a fresh database"
exec_psql -d postgres -c "DROP DATABASE IF EXISTS lshvector_probe;"
exec_psql -d postgres -c "CREATE DATABASE lshvector_probe;"
exec_psql -d lshvector_probe -c "CREATE EXTENSION lshvector;"
exec_psql -d lshvector_probe -c "SELECT extname, extversion FROM pg_extension WHERE extname = 'lshvector';"
exec_psql -d lshvector_probe -c "SELECT 'lshvector'::regtype;"

echo "non-SSL TCP must fail (sslmode=disable)"
set +e
docker exec -e PGPASSWORD="$PASSWORD" -e PGSSLMODE=disable "$CONTAINER" \
    psql -U bsim -h 127.0.0.1 -d lshvector_probe -c "SELECT 1;" >/tmp/bsim-nossl.out 2>&1
nossl=$?
set -e
if [ "$nossl" -eq 0 ]; then
    echo "FAIL: sslmode=disable connected; hostnossl is not reject" >&2
    cat /tmp/bsim-nossl.out >&2
    exit 1
fi
echo "non-SSL rejected (exit $nossl)"

echo "SSL TCP must succeed (sslmode=require)"
docker exec -e PGPASSWORD="$PASSWORD" -e PGSSLMODE=require "$CONTAINER" \
    psql -U bsim -h 127.0.0.1 -d lshvector_probe -c "SELECT 1;"

exec_psql -d postgres -c "DROP DATABASE lshvector_probe;"
echo "smoke-lshvector: ok"
