#!/bin/sh
# jarsWAF entrypoint.
#
# Runs as root ONLY to fix ownership on mounted volumes (SQLite db, certs, logs), then drops
# privileges to the unprivileged `jarswaf` user for the actual server process. This keeps
# the runtime hardening (non-root process) while allowing host/named volumes that start
# root-owned. Requires the image to define a `jarswaf` system user.

set -eu

# Fix ownership on every writable runtime dir the server may touch.
chown -R jarswaf:jarswaf /app/logs /app/certs /var/log/jarswaf 2>/dev/null || true

# Drop to the jarswaf user and exec the real command (CMD from the image).
# `su --` forwards the remaining arguments verbatim as argv.
exec su -s /bin/sh jarswaf -- "$@"
