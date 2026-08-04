#!/bin/sh
# jarsWAF entrypoint.
#
# Runs as root ONLY to fix ownership on mounted volumes (SQLite db, certs, logs), then drops
# privileges to the unprivileged `jarswaf` user for the actual server process. This keeps
# the runtime hardening (non-root process) while allowing host/named volumes that start
# root-owned. Requires the image to define a `jarswaf` system user.

set -eu

# Ensure writable runtime dirs exist, then fix ownership (run as root). This is essential
# for named volumes that Docker bootstraps empty/root-owned from a dir not present in the
# image — without it the unprivileged server cannot create its SQLite db.
mkdir -p /app/logs /app/certs /var/log/jarswaf
chown -R jarswaf:jarswaf /app/logs /app/certs /var/log/jarswaf

# Drop to the jarswaf user and exec the real command (CMD from the image).
#
# NOTE: use `setpriv`, NOT `su`. `su` runs the target command via a shell, so an ELF binary
# gets parsed as a shell script ("/app/jarswaf: 1: ELF...: not found"). setpriv execs the
# command directly with no intermediate shell. Requires util-linux (present in bookworm-slim).
exec setpriv --reuid jarswaf --regid jarswaf --init-groups --inh-caps=-all -- "$@"
