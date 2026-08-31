#!/bin/bash
# Generate a self-signed server cert if missing, lock down the key, then
# start Postgres with ssl=on. Ghidra refuses a non-SSL BSim connection
# (sslmode=require). A self-signed cert is enough: Ghidra's default trust
# manager authenticates peers only when ghidra.cacerts is set.
set -euo pipefail

CERT_DIR="${BSIM_SSL_CERT_DIR:-/var/lib/postgresql/certs}"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.key" ] || [ ! -f "$CERT_DIR/server.crt" ]; then
    openssl req -new -x509 -days 3650 -nodes \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -subj "/CN=ghidra-bsim"
fi

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"
chown postgres:postgres "$CERT_DIR/server.key" "$CERT_DIR/server.crt"

# Always pass ssl flags. Ignore extra CMD args so `command: postgres`
# from a compose override cannot drop ssl=on.
exec /usr/local/bin/docker-entrypoint.sh postgres \
    -c ssl=on \
    -c ssl_cert_file="$CERT_DIR/server.crt" \
    -c ssl_key_file="$CERT_DIR/server.key" \
    -c ssl_min_protocol_version=TLSv1.2 \
    -c hba_file=/etc/postgresql/pg_hba.conf
